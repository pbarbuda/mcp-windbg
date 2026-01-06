"""
Mock CDB server for testing.

This simulates CDB behavior for testing purposes without needing a real debugger.
It can simulate both "stopped" (responsive) and "running" (unresponsive to commands) states.
"""

import sys
import threading
import time
import re

COMMAND_MARKER_PATTERN = re.compile(r"\.echo (CMDMARKER_[a-f0-9]+_[a-f0-9]+)")


class MockCDBServer:
    """A mock CDB server that simulates debugger behavior."""

    def __init__(self, running: bool = False, output_delay: float = 0.1):
        """
        Initialize the mock server.

        Args:
            running: If True, simulates a running target that doesn't respond to commands
                     until break_execution() is called. If False, responds immediately.
            output_delay: Delay before producing output (simulates real CDB latency)
        """
        self.running = running
        self.output_delay = output_delay
        self.broken = not running  # If not running, we're already "broken" into debugger
        self.pending_commands = []
        self.lock = threading.Lock()

    def process_input(self, line: str) -> list[str]:
        """
        Process a command and return output lines.

        Args:
            line: The command input

        Returns:
            List of output lines (empty if target is running)
        """
        line = line.strip()
        if not line:
            return []

        with self.lock:
            # Check for marker echo command
            marker_match = COMMAND_MARKER_PATTERN.match(line)

            if self.running and not self.broken:
                # Target is running - queue command but don't respond
                self.pending_commands.append(line)
                return []

            # Target is stopped - process command
            time.sleep(self.output_delay)

            if marker_match:
                # Echo the marker
                marker = marker_match.group(1)
                return [f"0:000> {line}", marker, "0:000>"]

            # Handle various commands
            return self._handle_command(line)

    def _handle_command(self, cmd: str) -> list[str]:
        """Generate mock output for various commands."""
        output = [f"0:000> {cmd}"]

        if cmd == "version":
            output.extend([
                "Microsoft (R) Windows Debugger Version 10.0.99999.0 AMD64",
                "Copyright (c) Microsoft Corporation. All rights reserved.",
                "",
            ])
        elif cmd == "r":
            output.extend([
                "rax=0000000000000000 rbx=0000000000000000 rcx=0000000000000000",
                "rdx=0000000000000000 rsi=0000000000000000 rdi=0000000000000000",
                "rip=00007ff800000000 rsp=000000000014f000 rbp=0000000000000000",
                "",
            ])
        elif cmd == "k" or cmd == "kb":
            output.extend([
                " # Child-SP          RetAddr           Call Site",
                "00 00000000`0014f000 00007ff8`00000001 ntdll!NtWaitForMultipleObjects+0x14",
                "01 00000000`0014f100 00007ff8`00000002 KERNEL32!WaitForMultipleObjects+0x20",
                "",
            ])
        elif cmd == "lm":
            output.extend([
                "start             end                 module name",
                "00007ff8`00000000 00007ff8`001f0000   ntdll      (pdb symbols)",
                "00007ff8`00200000 00007ff8`002c0000   KERNEL32   (pdb symbols)",
                "",
            ])
        elif cmd == "~":
            output.extend([
                ".  0  Id: 1234.5678 Suspend: 1 Teb: 00000000`00300000 Unfrozen",
                "   1  Id: 1234.5679 Suspend: 1 Teb: 00000000`00301000 Unfrozen",
                "",
            ])
        elif cmd == "g":
            # Go command - target starts running
            self.running = True
            self.broken = False
            output.append("Target is running...")
            return output  # Return immediately, don't wait
        elif cmd == ".sympath":
            output.extend([
                "Symbol search path is: srv*",
                "",
            ])
        elif cmd.startswith("!"):
            output.extend([
                f"Extension command: {cmd}",
                "Mock extension output",
                "",
            ])
        else:
            output.extend([
                f"Unknown command: {cmd}",
                "",
            ])

        output.append("0:000>")
        return output

    def break_execution(self) -> list[str]:
        """
        Simulate Ctrl+C break into debugger.

        Returns:
            Output lines from the break
        """
        with self.lock:
            if not self.broken:
                self.broken = True
                self.running = False

                # Process any pending commands
                output = [
                    "Break instruction exception - code 80000003 (first chance)",
                    "ntdll!DbgBreakPoint:",
                    "00007ff8`789e0000 cc              int     3",
                    "0:000>",
                ]

                # Now process pending commands
                for cmd in self.pending_commands:
                    output.extend(self.process_input(cmd))
                self.pending_commands = []

                return output
            return []

    def get_initial_output(self) -> list[str]:
        """Get the initial output when CDB starts."""
        return [
            "",
            "Microsoft (R) Windows Debugger Version 10.0.99999.0 AMD64",
            "Copyright (c) Microsoft Corporation. All rights reserved.",
            "",
            "Connected to mock debugging session",
            "0:000>",
        ]


def run_mock_cdb_stdio(running: bool = False):
    """
    Run mock CDB server using stdio.

    This is meant to be run as a subprocess to simulate real CDB.

    Args:
        running: If True, start with target running (won't respond until break)
    """
    server = MockCDBServer(running=running)

    # Print initial output
    for line in server.get_initial_output():
        print(line, flush=True)

    # Process commands from stdin
    try:
        for line in sys.stdin:
            output = server.process_input(line)
            for out_line in output:
                print(out_line, flush=True)
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Mock CDB server for testing")
    parser.add_argument("--running", action="store_true",
                        help="Start with target running (won't respond until break)")
    args = parser.parse_args()

    run_mock_cdb_stdio(running=args.running)
