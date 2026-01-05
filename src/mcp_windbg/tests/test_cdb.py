import os
import pytest
import time

from mcp_windbg.cdb_session import CDBSession, CDBError, DEFAULT_CDB_PATHS

# Path to the test dump file
TEST_DUMP_PATH = os.path.join(os.path.dirname(__file__), 'dumps', 'DemoCrash1.exe.7088.dmp')

def setup_cdb_session():
    """Helper function to create a CDB session"""
    if not os.path.exists(TEST_DUMP_PATH):
        pytest.skip("Test dump file not found")

    if not any(os.path.exists(path) for path in DEFAULT_CDB_PATHS):
        pytest.skip("CDB executable not found")

    return CDBSession(
        dump_path=TEST_DUMP_PATH,
        timeout=20,
        verbose=True
    )

def test_basic_cdb_command():
    """Test basic CDB command execution"""
    session = setup_cdb_session()
    try:
        output = session.send_command("version")
        assert len(output) > 0
        assert any("Microsoft (R) Windows Debugger" in line for line in output)
    finally:
        session.shutdown()

def test_command_sequence():
    """Test multiple commands in sequence"""
    session = setup_cdb_session()
    try:
        # Basic command sequence
        commands = ["version", ".sympath", "!analyze -v", "lm", "~"]
        results = []

        for cmd in commands:
            output = session.send_command(cmd)
            results.append((cmd, output))
            assert len(output) > 0

        # Check expected output patterns
        assert any("Microsoft (R) Windows Debugger" in line for line in results[0][1])
        assert any("Symbol search path is:" in line for line in results[1][1])
        assert any("start" in line.lower() for line in results[3][1])
    finally:
        session.shutdown()

def test_module_inspection():
    """Test module inspection capabilities"""
    session = setup_cdb_session()
    try:
        # Get module list
        modules_output = session.send_command("lm")

        # Find a common Windows module
        target_modules = ['ntdll', 'kernel32']
        module_name = None

        for target in target_modules:
            for line in modules_output:
                if target in line.lower():
                    parts = line.split()
                    for part in parts:
                        if target in part.lower():
                            module_name = part
                            break
                    if module_name:
                        break
            if module_name:
                break

        assert module_name is not None

        # Get module details
        module_info = session.send_command(f"lmv m {module_name}")
        assert len(module_info) > 0
        assert any(module_name.lower() in line.lower() for line in module_info)

        # Get stack info
        stack_info = session.send_command("k 5")
        assert len(stack_info) > 0
    finally:
        session.shutdown()

def test_thread_context():
    """Test thread context operations"""
    session = setup_cdb_session()
    try:
        # Get thread list
        thread_list = session.send_command("~")

        # Select first thread
        thread_id = "0"
        for line in thread_list:
            if line.strip().startswith("#"):
                parts = line.split()
                if len(parts) > 1:
                    thread_id = parts[1].strip(":")
                    break

        # Switch to thread and check registers
        session.send_command(f"~{thread_id}s")
        registers = session.send_command("r")
        assert len(registers) > 0
        assert any("eax" in line.lower() or "rax" in line.lower() for line in registers)

        # Check stack trace
        stack = session.send_command("k")
        assert len(stack) > 0
    finally:
        session.shutdown()


def test_get_recent_output():
    """Test get_recent_output captures command output"""
    session = setup_cdb_session()
    try:
        # Clear any initial output
        session.get_recent_output(clear=True)

        # Run some commands
        session.send_command("version")
        session.send_command("r")

        # Get recent output - should contain output from both commands
        output = session.get_recent_output(clear=True)
        assert len(output) > 0
        # Should contain version info
        assert any("Microsoft" in line or "Debugger" in line for line in output)

        # After clearing, should be empty
        output_after_clear = session.get_recent_output(clear=True)
        assert len(output_after_clear) == 0
    finally:
        session.shutdown()


def test_get_recent_output_no_clear():
    """Test get_recent_output with clear=False preserves buffer"""
    session = setup_cdb_session()
    try:
        # Clear any initial output
        session.get_recent_output(clear=True)

        # Run a command
        session.send_command("version")

        # Get output without clearing
        output1 = session.get_recent_output(clear=False)
        assert len(output1) > 0

        # Get output again - should still have the same content
        output2 = session.get_recent_output(clear=False)
        assert len(output2) > 0
        assert len(output2) >= len(output1)

        # Now clear and verify empty
        session.get_recent_output(clear=True)
        output3 = session.get_recent_output(clear=True)
        assert len(output3) == 0
    finally:
        session.shutdown()


def test_break_execution_not_allowed_for_dumps():
    """Test that break_execution raises error for dump files"""
    session = setup_cdb_session()
    try:
        # break_execution should raise CDBError for dump files
        with pytest.raises(CDBError, match="only supported for remote debugging"):
            session.break_execution()
    finally:
        session.shutdown()


def test_send_command_async():
    """Test send_command_async sends commands without waiting"""
    session = setup_cdb_session()
    try:
        # Clear any initial output
        session.get_recent_output(clear=True)

        # Send an async command (any command works for this test)
        session.send_command_async("version")

        # Should return immediately (unlike send_command which waits for marker)
        # Wait a brief moment for output to arrive
        time.sleep(0.5)

        # Get recent output should have captured the command output
        output = session.get_recent_output(clear=True)
        assert len(output) > 0
        assert any("Microsoft" in line or "Debugger" in line for line in output)

    finally:
        session.shutdown()


def test_send_command_async_multiple():
    """Test multiple async commands accumulate output in buffer"""
    session = setup_cdb_session()
    try:
        # Clear any initial output
        session.get_recent_output(clear=True)

        # Send multiple async commands
        session.send_command_async("version")
        time.sleep(0.3)
        session.send_command_async(".sympath")
        time.sleep(0.3)

        # Get all accumulated output
        output = session.get_recent_output(clear=True)
        assert len(output) > 0

        # Should contain output from both commands
        has_version = any("Microsoft" in line or "Debugger" in line for line in output)
        has_sympath = any("Symbol search path" in line for line in output)

        # At least one should be present (timing-dependent)
        assert has_version or has_sympath

    finally:
        session.shutdown()


def test_send_command_async_then_get_output():
    """Test async command followed by get_recent_output retrieves accumulated output"""
    session = setup_cdb_session()
    try:
        # Clear buffer
        session.get_recent_output(clear=True)

        # Send async command
        session.send_command_async("lm")

        # Wait for output to accumulate
        time.sleep(1)

        # Get output without clearing first
        output1 = session.get_recent_output(clear=False)
        assert len(output1) > 0

        # Get output again without clearing - should be same or more
        output2 = session.get_recent_output(clear=False)
        assert len(output2) >= len(output1)

        # Clear and verify empty
        session.get_recent_output(clear=True)
        output3 = session.get_recent_output(clear=True)
        assert len(output3) == 0

    finally:
        session.shutdown()


if __name__ == "__main__":
    pytest.main(["-v", __file__])
