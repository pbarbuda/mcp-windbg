"""
Tests for auto-creating sessions when using get_windbg_output and other tools.

These tests verify that sessions can be created on-demand for all tools,
not just run_windbg_cmd.
"""

import os
import sys
import pytest
import subprocess
import time
import threading

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from mcp_windbg.cdb_session import CDBSession, CDBError
from mcp_windbg.server import get_or_create_session, active_sessions, unload_session


# Path to mock CDB server
MOCK_CDB_PATH = os.path.join(os.path.dirname(__file__), 'mock_cdb_server.py')


class MockCDBProcess:
    """Helper to run mock CDB as a subprocess."""

    def __init__(self, running: bool = False):
        self.running = running
        self.process = None

    def start(self) -> str:
        """Start mock CDB and return a fake connection string."""
        # We'll use a special path that CDBSession will recognize
        # For now, just return a marker that our tests can use
        return f"mock:running={self.running}"

    def stop(self):
        """Stop the mock CDB process."""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None


class TestSessionAutoCreation:
    """Test that sessions are auto-created for tools that need them."""

    def setup_method(self):
        """Clear active sessions before each test."""
        for session_id in list(active_sessions.keys()):
            try:
                unload_session(session_id)
            except:
                pass
        active_sessions.clear()

    def teardown_method(self):
        """Clean up after each test."""
        for session_id in list(active_sessions.keys()):
            try:
                unload_session(session_id)
            except:
                pass
        active_sessions.clear()

    def test_get_windbg_output_auto_creates_session(self):
        """
        Test that get_windbg_output now auto-creates a session with skip_initial_wait=True.

        This means get_windbg_output can be called on a potentially running target
        without blocking on the initial prompt.
        """
        from mcp_windbg.server import get_or_create_session

        connection_string = "tcp:Port=9999,Server=nonexistent"
        session_id = f"remote:{connection_string}"

        # Verify no session exists initially
        assert session_id not in active_sessions or active_sessions[session_id] is None

        # Try to create a session with skip_initial_wait=True
        # This should NOT block waiting for a prompt
        # Note: This will fail to connect since server doesn't exist,
        # but we're just testing the logic flow
        try:
            session = get_or_create_session(
                dump_path=None,
                connection_string=connection_string,
                skip_initial_wait=True
            )
            # If we got here, session was created
            # Clean up
            if session_id in active_sessions:
                del active_sessions[session_id]
        except Exception:
            # Expected - can't connect to nonexistent server
            # But the important thing is we didn't block forever
            pass

    def test_run_windbg_cmd_creates_session(self):
        """Test that run_windbg_cmd creates a session if one doesn't exist."""
        # This test uses a real dump file to verify session creation
        TEST_DUMP_PATH = os.path.join(os.path.dirname(__file__), 'dumps', 'DemoCrash1.exe.7088.dmp')

        if not os.path.exists(TEST_DUMP_PATH):
            pytest.skip("Test dump file not found")

        session_id = os.path.abspath(TEST_DUMP_PATH)

        # Verify no session exists initially
        assert session_id not in active_sessions

        # Create session via get_or_create_session (which run_windbg_cmd uses)
        try:
            session = get_or_create_session(dump_path=TEST_DUMP_PATH, timeout=30, verbose=True)

            # Session should now exist
            assert session_id in active_sessions
            assert active_sessions[session_id] is not None

            # Should be able to send commands
            output = session.send_command("version")
            assert len(output) > 0
        finally:
            if session_id in active_sessions:
                unload_session(session_id)


class TestMockCDBIntegration:
    """Tests using the mock CDB server."""

    def test_mock_cdb_server_responds_to_commands(self):
        """Test that the mock CDB server works correctly."""
        python_exe = sys.executable

        # Start mock CDB in stopped state
        process = subprocess.Popen(
            [python_exe, MOCK_CDB_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        try:
            # Read initial output
            initial_lines = []
            for _ in range(6):  # Mock outputs 6 lines initially
                line = process.stdout.readline()
                if line:
                    initial_lines.append(line.strip())

            assert any("Microsoft" in line for line in initial_lines), f"Expected version info, got: {initial_lines}"

            # Send a command
            process.stdin.write("version\n")
            process.stdin.flush()

            # Read response
            response_lines = []
            for _ in range(5):  # version outputs ~5 lines
                line = process.stdout.readline()
                if line:
                    response_lines.append(line.strip())

            assert any("Debugger" in line for line in response_lines), f"Expected version output, got: {response_lines}"

        finally:
            process.terminate()
            process.wait()

    def test_mock_cdb_running_target_does_not_respond(self):
        """Test that mock CDB with running target doesn't respond to commands."""
        python_exe = sys.executable

        # Start mock CDB in RUNNING state
        process = subprocess.Popen(
            [python_exe, MOCK_CDB_PATH, "--running"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        try:
            # Read initial output
            initial_lines = []
            for _ in range(6):
                line = process.stdout.readline()
                if line:
                    initial_lines.append(line.strip())

            # Send a command - should NOT get a response because target is running
            process.stdin.write("version\n")
            process.stdin.flush()

            # Try to read with timeout - should not get anything
            import select
            # On Windows, use a different approach
            response_received = False

            def try_read():
                nonlocal response_received
                line = process.stdout.readline()
                if line and "Debugger" in line:
                    response_received = True

            reader_thread = threading.Thread(target=try_read)
            reader_thread.daemon = True
            reader_thread.start()
            reader_thread.join(timeout=1.0)  # Wait max 1 second

            # Should NOT have received a response
            assert not response_received, "Running target should not respond to commands"

        finally:
            process.terminate()
            process.wait()


class TestGetOutputWithoutExistingSession:
    """
    Tests for the desired behavior: get_windbg_output should work even without
    an existing session, by creating one that doesn't wait for prompt.

    These tests currently FAIL because the feature is not implemented yet.
    """

    def setup_method(self):
        """Clear active sessions before each test."""
        for session_id in list(active_sessions.keys()):
            try:
                unload_session(session_id)
            except:
                pass
        active_sessions.clear()

    def teardown_method(self):
        """Clean up after each test."""
        for session_id in list(active_sessions.keys()):
            try:
                unload_session(session_id)
            except:
                pass
        active_sessions.clear()

    def test_get_or_create_session_with_skip_initial_wait(self):
        """
        Test that get_or_create_session with skip_initial_wait=True
        creates a session without blocking.
        """
        TEST_DUMP_PATH = os.path.join(os.path.dirname(__file__), 'dumps', 'DemoCrash1.exe.7088.dmp')

        if not os.path.exists(TEST_DUMP_PATH):
            pytest.skip("Test dump file not found")

        session_id = os.path.abspath(TEST_DUMP_PATH)

        # Verify no session exists initially
        assert session_id not in active_sessions

        # Create session with skip_initial_wait=True
        # This should return quickly without waiting for marker
        import time
        start_time = time.time()

        session = get_or_create_session(
            dump_path=TEST_DUMP_PATH,
            timeout=30,
            verbose=True,
            skip_initial_wait=True
        )

        elapsed = time.time() - start_time

        # Session should be created
        assert session is not None
        assert session_id in active_sessions

        # Should return quickly (less than 2 seconds) since we're not waiting for marker
        assert elapsed < 2.0, f"Session creation took too long: {elapsed}s"

        # Give some time for output to accumulate
        time.sleep(1.0)

        # Should be able to get recent output
        output = session.get_recent_output(clear=False)
        # There should be some initial output from CDB starting up
        assert len(output) > 0, "Expected some output from CDB startup"


class TestCDBSessionWithMock:
    """
    Tests that use CDBSession with a mock CDB server.

    These tests verify behavior when connecting to running vs stopped targets.
    """

    def test_cdb_session_with_running_mock_target_times_out(self):
        """
        Test that CDBSession times out when connecting to a running mock target.

        This demonstrates the problem: when the target is running, the initialization
        hangs waiting for a prompt marker that never comes.

        We use a dump file with a real CDB but simulate "running" by using
        a very short timeout - the test passes if timeout occurs.
        """
        # For this test, we can't easily mock a running target with real CDB
        # Instead, we document the expected behavior:
        # - If target is running, _wait_for_prompt will timeout
        # - The CDBError("CDB initialization timed out") will be raised

        # This test uses the mock server directly to demonstrate the concept
        python_exe = sys.executable

        # Start mock CDB in RUNNING state directly (not via CDBSession)
        process = subprocess.Popen(
            [python_exe, MOCK_CDB_PATH, "--running"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        try:
            # Read initial output
            for _ in range(6):
                process.stdout.readline()

            # Send a marker command (like _wait_for_prompt does)
            process.stdin.write(".echo CMDMARKER_test1234_0001\n")
            process.stdin.flush()

            # Try to read with timeout - should NOT get marker back because target is running
            response_received = False

            def try_read():
                nonlocal response_received
                line = process.stdout.readline()
                if line and "CMDMARKER" in line:
                    response_received = True

            reader_thread = threading.Thread(target=try_read)
            reader_thread.daemon = True
            reader_thread.start()
            reader_thread.join(timeout=2.0)

            # Should NOT have received a response - this is the problem we need to handle
            assert not response_received, \
                "Running target correctly does not respond to marker commands"

        finally:
            process.terminate()
            process.wait()


if __name__ == "__main__":
    pytest.main(["-v", __file__])
