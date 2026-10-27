import asyncio
import subprocess
import sys
import types

import pytest

from metasploit_mcp import platforms
from metasploit_mcp.processes import ProcessManager
from metasploit_mcp.rpc import RPCError
from metasploit_mcp.windows_terminal import WindowsTerminal


def test_windows_process_group_options(monkeypatch):
    monkeypatch.setattr(platforms, "WINDOWS", True)
    monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 512, raising=False)
    assert platforms.process_options() == {"creationflags": 512}


def test_windows_metasploit_wrapper_uses_bundled_ruby_with_literal_arguments(tmp_path, monkeypatch):
    monkeypatch.setattr(platforms, "WINDOWS", True)
    root = tmp_path / "Metasploit With Spaces"
    wrapper = root / "bin" / "msfconsole.bat"
    ruby = root / "embedded" / "bin" / "ruby.exe"
    script = root / "embedded" / "framework" / "msfconsole"
    for path in (wrapper, ruby, script):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    arguments = ["-x", "help & echo literal %VALUE% !value!"]
    command, env = platforms.prepare_command(
        [str(wrapper), *arguments], {"PATH": "existing-path", "GEM_HOME": "wrong-ruby", "EXAMPLE": "value"},
    )
    assert command == [str(ruby), str(script), *arguments]
    assert "GEM_HOME" not in env and env["EXAMPLE"] == "value"
    assert env["PATH"].startswith(str(ruby.parent))


def test_unrecognized_batch_requires_explicit_interpreter(tmp_path, monkeypatch):
    monkeypatch.setattr(platforms, "WINDOWS", True)
    with pytest.raises(RPCError, match="explicit shell"):
        platforms.prepare_command([str(tmp_path / "custom.cmd"), "& anything"], {})


def test_conpty_adapter_quotes_arguments_and_handles_unicode_resize_and_exit(monkeypatch):
    calls = {}
    class FakePTY:
        pid = 123
        alive = True
        def __init__(self, columns, rows, backend):
            calls["size"] = (columns, rows, backend)
        def spawn(self, command, **kwargs):
            calls["spawn"] = command, kwargs
            return True
        def isalive(self):
            return self.alive
        def get_exitstatus(self):
            return 7
        def read(self, blocking):
            assert blocking is False
            return "unicode: café"
        def write(self, text):
            calls["write"] = text
        def set_size(self, columns, rows):
            calls["resize"] = columns, rows
    monkeypatch.setitem(sys.modules, "winpty", types.SimpleNamespace(
        PTY=FakePTY, Backend=types.SimpleNamespace(ConPTY=0),
    ))
    terminal = WindowsTerminal(
        [r"C:\Program Files\ruby.exe", "script with spaces.rb", 'quote"and&literal'],
        cwd=r"C:\directory", env={"EXAMPLE": "value"}, rows=24, columns=80,
    )
    assert calls["size"] == (80, 24, 0)
    assert '"script with spaces.rb"' in calls["spawn"][1]["cmdline"]
    assert calls["spawn"][1]["env"] == "EXAMPLE=value\0"
    assert terminal.returncode is None
    assert terminal.read() == "unicode: café".encode()
    terminal.write("こんにちは\r\n".encode())
    assert calls["write"] == "こんにちは\r\n"
    with pytest.raises(RPCError, match="UTF-8"):
        terminal.write(b"\xff")
    terminal.resize(40, 100)
    assert calls["resize"] == (100, 40)
    terminal._pty.alive = False
    assert terminal.returncode == 7
    terminal.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Real Windows ConPTY integration")
async def test_native_conpty_input_control_resize_and_cleanup():
    manager = ProcessManager()
    try:
        program = (
            "import signal,sys; "
            "signal.signal(signal.SIGINT,lambda *_:print('INTERRUPTED',flush=True)); "
            "print('CONPTY READY',flush=True); "
            "exec(\"while True:\\n line=sys.stdin.readline()\\n print('RECEIVED:'+line.strip(),flush=True)\")"
        )
        started = await manager.start([sys.executable, "-u", "-c", program], terminal=True)
        process_id = started["process_id"]
        async def wait(text):
            async def poll():
                while text not in manager.read(process_id)["text"]:
                    await asyncio.sleep(0.02)
            await asyncio.wait_for(poll(), 15)
        await wait("CONPTY READY")
        manager.resize(process_id, 40, 100)
        await manager.write(process_id, "hello windows\r\n")
        await wait("RECEIVED:hello windows")
        manager.send_signal(process_id, "SIGINT")
        await wait("INTERRUPTED")
        assert manager.list()[0]["terminal"] is True
        await manager.close(process_id)
    finally:
        await manager.shutdown()
