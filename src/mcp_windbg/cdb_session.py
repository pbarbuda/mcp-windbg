import subprocess
import threading
import re
import os
import sys
import platform
import logging
import uuid
from typing import List, Optional
from collections import deque
from datetime import datetime

# Set up module logger
logger = logging.getLogger(__name__)

# Maximum number of lines to keep in the recent output buffer
MAX_RECENT_OUTPUT_LINES = 1000

# Regular expression to detect CDB prompts
PROMPT_REGEX = re.compile(r"^\d+:\d+>\s*$")

# Command marker to reliably detect command completion
# We use a unique ID per command to avoid stale marker issues
# Format: CMDMARKER_<session_id>_<counter> (e.g., CMDMARKER_a1b2c3d4_0001)
COMMAND_MARKER_PREFIX = "CMDMARKER_"
COMMAND_MARKER_PATTERN = re.compile(r"CMDMARKER_([a-f0-9]+_[a-f0-9]+)")

# Default paths where cdb.exe might be located
DEFAULT_CDB_PATHS = [
    # Traditional Windows SDK locations
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x86)\cdb.exe",

    # Microsoft Store WinDbg Preview locations (architecture-specific)
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX86.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbARM64.exe")
]

class CDBError(Exception):
    """Custom exception for CDB-related errors"""
    pass

class CDBSession:
    def __init__(
        self,
        dump_path: Optional[str] = None,
        remote_connection: Optional[str] = None,
        cdb_path: Optional[str] = None,
        symbols_path: Optional[str] = None,
        initial_commands: Optional[List[str]] = None,
        timeout: int = 10,
        verbose: bool = False,
        additional_args: Optional[List[str]] = None
    ):
        """
        Initialize a new CDB debugging session.

        Args:
            dump_path: Path to the crash dump file (mutually exclusive with remote_connection)
            remote_connection: Remote debugging connection string (e.g., "tcp:Port=5005,Server=192.168.0.100")
            cdb_path: Custom path to cdb.exe. If None, will try to find it automatically
            symbols_path: Custom symbols path. If None, uses default Windows symbols
            initial_commands: List of commands to run when CDB starts
            timeout: Timeout in seconds for waiting for CDB responses
            verbose: Whether to print additional debug information
            additional_args: Additional arguments to pass to cdb.exe

        Raises:
            CDBError: If cdb.exe cannot be found or started
            FileNotFoundError: If the dump file cannot be found
            ValueError: If invalid parameters are provided
        """
        # Validate that exactly one of dump_path or remote_connection is provided
        if not dump_path and not remote_connection:
            raise ValueError("Either dump_path or remote_connection must be provided")
        if dump_path and remote_connection:
            raise ValueError("dump_path and remote_connection are mutually exclusive")

        if dump_path and not os.path.isfile(dump_path):
            raise FileNotFoundError(f"Dump file not found: {dump_path}")

        self.dump_path = dump_path
        self.remote_connection = remote_connection
        self.timeout = timeout
        self.verbose = verbose

        # Find cdb executable
        self.cdb_path = self._find_cdb_executable(cdb_path)
        if not self.cdb_path:
            raise CDBError("Could not find cdb.exe. Please provide a valid path.")

        # Prepare command args
        cmd_args = [self.cdb_path]

        # Add connection type specific arguments
        if self.dump_path:
            cmd_args.extend(["-z", self.dump_path])
        elif self.remote_connection:
            # -clines 0 prevents CDB from retrieving the entire session history
            # from the remote, which can take minutes for long-running sessions.
            # The agent can use get_recent_output to retrieve output as needed.
            cmd_args.extend(["-remote", self.remote_connection, "-clines", "0"])

        # Add symbols path if provided
        if symbols_path:
            cmd_args.extend(["-y", symbols_path])

        # Add any additional arguments
        if additional_args:
            cmd_args.extend(additional_args)

        try:
            logger.info(f"Starting CDB process with args: {cmd_args}")
            self.process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            logger.info(f"CDB process started with PID: {self.process.pid}")
        except Exception as e:
            logger.error(f"Failed to start CDB process: {str(e)}")
            raise CDBError(f"Failed to start CDB process: {str(e)}")

        self.output_lines = []
        self.recent_output = deque(maxlen=MAX_RECENT_OUTPUT_LINES)
        self.lock = threading.Lock()
        self.ready_event = threading.Event()
        self.expected_marker_id: Optional[str] = None  # The marker ID we're waiting for

        # Use a unique session ID to avoid marker collisions with other sessions
        # or stale markers from previous connections to the same remote
        self.session_id = uuid.uuid4().hex[:8]
        self.command_counter = 0  # Counter for unique marker IDs within this session

        self.reader_thread = threading.Thread(target=self._read_output)
        self.reader_thread.daemon = True
        self.reader_thread.start()

        # Wait for CDB to initialize by sending an echo marker
        # For remote connections, use a longer timeout since there can be
        # extensive symbol path validation output
        init_timeout = self.timeout
        if self.remote_connection:
            # Remote connections can take much longer due to symbol validation
            init_timeout = max(self.timeout, 60)
            logger.info(f"Remote connection detected, using {init_timeout}s init timeout")

        try:
            self._wait_for_prompt(timeout=init_timeout)
        except CDBError:
            self.shutdown()
            raise CDBError("CDB initialization timed out")

        # For remote connections, clear any accumulated output from the connection
        # process (symbol validation, path errors, etc.) so it doesn't pollute
        # the first command's output
        if self.remote_connection:
            with self.lock:
                self.recent_output.clear()
                self.output_lines = []
            logger.info("Cleared initial remote connection output")

        # Run initial commands if provided
        if initial_commands:
            for cmd in initial_commands:
                self.send_command(cmd)

    def _find_cdb_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the cdb.exe executable"""
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        for path in DEFAULT_CDB_PATHS:
            if os.path.isfile(path):
                return path

        return None

    def _generate_marker_id(self) -> str:
        """
        Generate a unique marker ID for a command.

        Uses a combination of session UUID and counter to ensure markers
        are globally unique and won't collide with markers from other
        sessions or stale markers in the remote debugger's output buffer.
        """
        self.command_counter += 1
        return f"{self.session_id}_{self.command_counter:04x}"

    def _read_output(self):
        """Thread function to continuously read CDB output"""
        if not self.process or not self.process.stdout:
            return

        buffer = []
        try:
            for line in self.process.stdout:
                line = line.rstrip()
                if self.verbose:
                    print(f"CDB > {line}", file=sys.stderr)

                with self.lock:
                    buffer.append(line)
                    # Always append to recent_output (except marker lines)
                    if not COMMAND_MARKER_PATTERN.search(line):
                        self.recent_output.append(line)
                    # Check if the marker is in this line
                    marker_match = COMMAND_MARKER_PATTERN.search(line)
                    if marker_match:
                        marker_id = marker_match.group(1)
                        # Only trigger if this is the marker we're waiting for
                        if self.expected_marker_id and marker_id == self.expected_marker_id:
                            logger.debug(f"Received expected marker: {marker_id}")
                            # Remove the marker line itself
                            if buffer and COMMAND_MARKER_PATTERN.search(buffer[-1]):
                                buffer.pop()
                            self.output_lines = buffer
                            buffer = []
                            self.expected_marker_id = None
                            self.ready_event.set()
                        else:
                            logger.debug(f"Ignoring stale marker: {marker_id} (expected: {self.expected_marker_id})")
                            # Remove marker line from buffer but don't signal
                            if buffer and COMMAND_MARKER_PATTERN.search(buffer[-1]):
                                buffer.pop()
        except (IOError, ValueError) as e:
            if self.verbose:
                print(f"CDB output reader error: {e}", file=sys.stderr)

    def _wait_for_prompt(self, timeout=None):
        """Wait for CDB to be ready for commands by sending a marker"""
        try:
            marker_id = self._generate_marker_id()
            marker_cmd = f".echo {COMMAND_MARKER_PREFIX}{marker_id}"
            logger.debug(f"_wait_for_prompt: sending marker {marker_id}")

            self.ready_event.clear()
            with self.lock:
                self.expected_marker_id = marker_id
                self.output_lines = []

            self.process.stdin.write(f"{marker_cmd}\n")
            self.process.stdin.flush()

            if not self.ready_event.wait(timeout=timeout or self.timeout):
                raise CDBError(f"Timed out waiting for CDB prompt")
            logger.debug(f"_wait_for_prompt: marker {marker_id} received")
        except IOError as e:
            raise CDBError(f"Failed to communicate with CDB: {str(e)}")

    def send_command(self, command: str, timeout: Optional[int] = None) -> List[str]:
        """
        Send a command to CDB and return the output

        Args:
            command: The command to send
            timeout: Custom timeout for this command (overrides instance timeout)

        Returns:
            List of output lines from CDB

        Raises:
            CDBError: If the command times out or CDB is not responsive
        """
        if not self.process:
            logger.error("send_command called but CDB process is not running")
            raise CDBError("CDB process is not running")

        # Check if process is still alive
        poll_result = self.process.poll()
        if poll_result is not None:
            logger.error(f"CDB process has terminated with exit code: {poll_result}")
            raise CDBError(f"CDB process has terminated (exit code: {poll_result})")

        cmd_timeout = timeout or self.timeout
        timestamp = datetime.now().isoformat()
        marker_id = self._generate_marker_id()
        marker_cmd = f".echo {COMMAND_MARKER_PREFIX}{marker_id}"

        logger.debug(f"[{timestamp}] send_command: '{command}' (timeout={cmd_timeout}s, marker={marker_id})")

        self.ready_event.clear()
        with self.lock:
            self.expected_marker_id = marker_id
            self.output_lines = []

        try:
            # Send the command followed by our unique marker to detect completion
            logger.debug(f"[{timestamp}] Writing command to stdin...")
            self.process.stdin.write(f"{command}\n{marker_cmd}\n")
            self.process.stdin.flush()
            logger.debug(f"[{timestamp}] Command written and flushed (marker={marker_id})")
        except IOError as e:
            logger.error(f"[{timestamp}] Failed to send command: {str(e)}")
            raise CDBError(f"Failed to send command: {str(e)}")

        logger.debug(f"[{timestamp}] Waiting for ready_event (timeout={cmd_timeout}s, marker={marker_id})...")
        if not self.ready_event.wait(timeout=cmd_timeout):
            logger.error(f"[{timestamp}] Command timed out after {cmd_timeout} seconds: {command} (marker={marker_id})")
            raise CDBError(f"Command timed out after {cmd_timeout} seconds: {command}")

        with self.lock:
            result = self.output_lines.copy()
            self.output_lines = []

        logger.debug(f"[{timestamp}] Command completed, got {len(result)} lines of output (marker={marker_id})")
        return result

    def send_command_async(self, command: str) -> None:
        """
        Send a command to CDB without waiting for completion.

        This is useful for commands like 'g' (go/continue) that don't return
        until the debugger breaks again. The output can be retrieved later
        using get_recent_output().

        Args:
            command: The command to send

        Raises:
            CDBError: If CDB is not running or communication fails
        """
        if not self.process:
            logger.error("send_command_async called but CDB process is not running")
            raise CDBError("CDB process is not running")

        # Check if process is still alive
        poll_result = self.process.poll()
        if poll_result is not None:
            logger.error(f"CDB process has terminated with exit code: {poll_result}")
            raise CDBError(f"CDB process has terminated (exit code: {poll_result})")

        timestamp = datetime.now().isoformat()
        logger.debug(f"[{timestamp}] send_command_async: '{command}'")

        # Clear any pending marker expectation since we're not waiting
        with self.lock:
            self.expected_marker_id = None

        try:
            # Send just the command, no marker - we don't expect it to complete
            logger.debug(f"[{timestamp}] Writing async command to stdin...")
            self.process.stdin.write(f"{command}\n")
            self.process.stdin.flush()
            logger.debug(f"[{timestamp}] Async command written and flushed")
        except IOError as e:
            logger.error(f"[{timestamp}] Failed to send async command: {str(e)}")
            raise CDBError(f"Failed to send command: {str(e)}")

    def get_recent_output(self, clear: bool = True) -> List[str]:
        """
        Get the recent output from the debugger.

        This returns all output that has been captured since the session started
        or since the last call to get_recent_output (if clear=True). This is useful
        for capturing output that occurs asynchronously, such as debug prints
        when the target is running.

        Args:
            clear: Whether to clear the buffer after reading (default True)

        Returns:
            List of output lines from the debugger
        """
        with self.lock:
            result = list(self.recent_output)
            if clear:
                self.recent_output.clear()
        return result

    def break_execution(self) -> bool:
        """
        Break into the debugger by sending Ctrl+C.

        This is primarily useful for remote debugging sessions where the target
        may be running. For crash dumps, the debugger is always in a stopped state.

        Returns:
            True if the break signal was sent successfully

        Raises:
            CDBError: If the process is not running or communication fails
        """
        if not self.process or self.process.poll() is not None:
            raise CDBError("CDB process is not running")

        if not self.remote_connection:
            raise CDBError("Break is only supported for remote debugging sessions")

        try:
            # Send Ctrl+C (0x03) to break into the debugger
            self.process.stdin.write("\x03")
            self.process.stdin.flush()
            return True
        except IOError as e:
            raise CDBError(f"Failed to send break signal: {str(e)}")

    def shutdown(self):
        """Clean up and terminate the CDB process"""
        try:
            if self.process and self.process.poll() is None:
                try:
                    if self.remote_connection:
                        # For remote connections, send CTRL+B to detach
                        self.process.stdin.write("\x02")  # CTRL+B
                        self.process.stdin.flush()
                    else:
                        # For dump files, send 'q' to quit
                        self.process.stdin.write("q\n")
                        self.process.stdin.flush()
                    self.process.wait(timeout=1)
                except Exception:
                    pass

                if self.process.poll() is None:
                    self.process.terminate()
                    self.process.wait(timeout=3)
        except Exception as e:
            if self.verbose:
                print(f"Error during shutdown: {e}", file=sys.stderr)
        finally:
            self.process = None

    def get_session_id(self) -> str:
        """Get a unique identifier for this CDB session."""
        if self.dump_path:
            return os.path.abspath(self.dump_path)
        elif self.remote_connection:
            return f"remote:{self.remote_connection}"
        else:
            raise CDBError("Session has no valid identifier")

    def __enter__(self):
        """Support for context manager protocol"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up when exiting context manager"""
        self.shutdown()
