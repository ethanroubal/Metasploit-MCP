import asyncio
import base64
import os
import signal
import sys

import httpx
import msgpack
import psutil
import pytest
from mcp import Client

from metasploit_mcp.catalog import method_catalog, scan_framework
from metasploit_mcp.config import Config
from metasploit_mcp.files import LocalFiles
from metasploit_mcp.processes import ProcessManager
from metasploit_mcp.rpc import RPCClient, RPCError
from metasploit_mcp.server import create_server

CATALOG = method_catalog(limit=1000)


@pytest.mark.parametrize("entry", CATALOG["methods"], ids=lambda entry: entry["method"])
async def test_every_catalog_method_can_be_forwarded(entry):
    """Verify transport coverage; intentionally does not execute upstream actions."""
    calls = []
    def handler(request):
        calls.append(msgpack.unpackb(request.content, raw=False))
        return httpx.Response(200, content=msgpack.packb({"forwarded": True}))
    client = RPCClient(Config(token="test-token"), httpx.MockTransport(handler))
    try:
        await client.call(entry["method"], ["sentinel"], authenticated=entry["authenticated"])
        assert calls == [[entry["method"], *(["test-token"] if entry["authenticated"] else []), "sentinel"]]
    finally:
        await client.close()


async def test_noauth_without_credentials_and_direct_login():
    calls = []
    def handler(request):
        parts = msgpack.unpackb(request.content, raw=False)
        calls.append(parts)
        result = {"result": "success", "token": "new-token"} if parts[0] == "auth.login" else {"ok": True}
        return httpx.Response(200, content=msgpack.packb(result))
    client = RPCClient(Config(), httpx.MockTransport(handler))
    try:
        await client.call("health.check")
        await client.call("custom.noauth", [1], authenticated=False)
        await client.call("auth.login", ["someone", "password"])
        await client.call("core.version")
        assert calls == [["health.check"], ["custom.noauth", 1],
                         ["auth.login", "someone", "password"], ["core.version", "new-token"]]
    finally:
        await client.close()


async def test_long_rpc_does_not_block_interrupt_and_custom_timeout():
    started, interrupted = asyncio.Event(), asyncio.Event()
    async def handler(request):
        parts = msgpack.unpackb(request.content, raw=False)
        if parts[0] == "session.interactive_write":
            assert request.extensions["timeout"]["read"] == 123.0
            started.set()
            await interrupted.wait()
        elif parts[0] == "session.stop":
            interrupted.set()
        return httpx.Response(200, content=msgpack.packb({"result": "success"}))
    client = RPCClient(Config(token="token"), httpx.MockTransport(handler))
    try:
        pending = asyncio.create_task(client.call("session.interactive_write", [1, "test"], timeout=123))
        await asyncio.wait_for(started.wait(), 1)
        await asyncio.wait_for(client.call("session.stop", [1]), 1)
        await asyncio.wait_for(pending, 1)
    finally:
        await client.close()


async def test_real_metasploit_http_error_body_preserved():
    client = RPCClient(Config(token="secret"), httpx.MockTransport(lambda _: httpx.Response(
        500, content=msgpack.packb({"error": True, "error_code": 500,
                                  "error_string": "Unknown session secret"}))))
    try:
        with pytest.raises(RPCError, match="Unknown session \\[redacted\\]"):
            await client.call("session.interactive_read", [1])
    finally:
        await client.close()


async def test_mixed_legacy_raw_string_and_modern_binary_preserve_types():
    # fixmap: two fields, raw str containing invalid UTF-8, and bin with valid UTF-8.
    packed = b"\x82\xa3raw\xa1\xff\xa3bin\xc4\x03abc"
    client = RPCClient(Config(token="token"), httpx.MockTransport(
        lambda _: httpx.Response(200, content=packed)))
    try:
        assert await client.call("custom.method") == {
            "raw": {"$binary": "/w=="}, "bin": {"$binary": "YWJj"},
        }
    finally:
        await client.close()


def test_catalog_covers_registered_handlers_and_noauth():
    methods = {entry["method"]: entry for entry in CATALOG["methods"]}
    assert {name.split(".")[0] for name in methods} == {
        "health", "core", "auth", "console", "module", "session", "plugin", "job", "db",
    }
    assert not methods["health.check"]["authenticated"]
    assert not methods["auth.login"]["authenticated"]
    assert methods["session.interactive_read"]["authenticated"]
    assert CATALOG["commit"] and CATALOG["reference_only"]


def test_installed_source_catalog_including_multiline_arguments(tmp_path):
    base = tmp_path / "lib/msf/core/rpc/v10"
    base.mkdir(parents=True)
    (base / "service.rb").write_text('add_handler("example", Msf::RPC::RPC_Example.new(self))')
    (base / "rpc_example.rb").write_text('class RPC_Example\n  def rpc_public_noauth(a,\n b={})\n  end\nend\n')
    catalog = scan_framework(tmp_path)
    assert catalog["methods"][0]["method"] == "example.public"
    assert catalog["methods"][0]["arguments"] == "(a, b={})"
    assert not catalog["methods"][0]["authenticated"]


@pytest.fixture
async def processes():
    manager = ProcessManager()
    try:
        yield manager
    finally:
        await manager.shutdown()


async def wait_for_output(manager, process_id, text, *, offset=0):
    async def read():
        while True:
            result = manager.read(process_id, offset=offset, max_bytes=1048576)
            if text in result["text"]:
                return result
            if result["eof"]:
                pytest.fail(f"Process exited before {text!r}: {result}")
            await asyncio.sleep(0.01)
    return await asyncio.wait_for(read(), 5)


async def test_pipe_binary_input_output_and_eof(processes):
    program = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.write('err')"
    started = await processes.start([sys.executable, "-c", program])
    pid = started["process_id"]
    payload = bytes(range(256)) * 1000
    await processes.write(pid, {"$binary": base64.b64encode(payload).decode()}, close_stdin=True)
    await asyncio.wait_for(processes.get(pid).process.wait(), 5)
    offset, combined = 0, bytearray()
    while True:
        result = processes.read(pid, offset=offset, max_bytes=4096)
        combined.extend(base64.b64decode(result["data"]["$binary"]))
        offset = result["next_offset"]
        if result["eof"]:
            break
    assert combined == payload
    assert processes.read(pid, "stderr")["text"] == "err"
    # Reads can be repeated without consuming data.
    assert processes.read(pid, offset=0, max_bytes=10)["data"] == {"$binary": base64.b64encode(payload[:10]).decode()}
    directory = processes.get(pid).directory
    await processes.close(pid)
    assert not directory.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX PTY")
async def test_real_controlling_pty_input_resize_and_ctrl_c(processes):
    program = '''import os, signal, sys
with open('/dev/tty') as terminal:
    print('READY', os.isatty(0), os.tcgetpgrp(0) == os.getpgrp(), flush=True)
signal.signal(signal.SIGINT, lambda *_: print('INTERRUPTED', flush=True))
while True:
    line = sys.stdin.readline()
    if not line:
        break
    if line.strip() == 'size':
        print('SIZE', os.get_terminal_size().columns, os.get_terminal_size().lines, flush=True)
    else:
        print('LINE', line.strip(), flush=True)
'''
    started = await processes.start([sys.executable, "-u", "-c", program], terminal=True)
    pid = started["process_id"]
    await wait_for_output(processes, pid, "READY True True")
    processes.resize(pid, 40, 90)
    await processes.write(pid, "size\n")
    await wait_for_output(processes, pid, "SIZE 90 40")
    await processes.write(pid, "\x03")
    await wait_for_output(processes, pid, "INTERRUPTED")
    await processes.write(pid, "still-alive\n")
    await wait_for_output(processes, pid, "LINE still-alive")
    with pytest.raises(RPCError, match="merges stderr"):
        processes.read(pid, "stderr")


async def test_process_environment_cwd_arguments_and_group_cleanup(processes, tmp_path):
    program = "import os,sys; print(os.getcwd(),os.environ['EXAMPLE'],repr(sys.argv[1]),flush=True); sys.stdin.read()"
    started = await processes.start([sys.executable, "-u", "-c", program, "$(literal); words"],
                                    cwd=str(tmp_path), env={"EXAMPLE": "value"})
    pid = started["process_id"]
    output = await wait_for_output(processes, pid, "$(literal); words")
    assert str(tmp_path) in output["text"] and "value" in output["text"]
    assert processes.list()[0]["pid"] == started["pid"]
    await processes.close(pid)
    assert not psutil.pid_exists(started["pid"])


async def test_process_signals_and_failed_spawn(processes):
    with pytest.raises(FileNotFoundError):
        await processes.start(["/nonexistent/metasploit-test-executable"])
    with pytest.raises(RPCError, match="argv"):
        await processes.start([])
    started = await processes.start([sys.executable, "-c", "import time; time.sleep(20)"])
    pid = started["process_id"]
    processes.send_signal(pid, "SIGTERM")
    await asyncio.wait_for(processes.get(pid).process.wait(), 3)
    if os.name == "nt":
        assert processes.get(pid).process.returncode != 0
    else:
        assert processes.get(pid).process.returncode == -signal.SIGTERM


def test_chunked_local_files_without_corruption(tmp_path):
    target = tmp_path / "nested" / "script.rc"
    LocalFiles.write(str(target), "old trailing contents")
    LocalFiles.write(str(target), {"$binary": "AP8="}, truncate=True)
    LocalFiles.write(str(target), "text", offset=2)
    first = LocalFiles.read(str(target), max_bytes=2)
    assert first["data"] == {"$binary": "AP8="}
    assert not first["eof"]
    second = LocalFiles.read(str(target), offset=first["next_offset"])
    assert second["text"] == "text" and second["eof"]
    assert LocalFiles.list(str(target.parent))["entries"][0]["name"] == "script.rc"
    with pytest.raises(RPCError):
        LocalFiles.write(str(target), {"$binary": "!invalid"})
    with pytest.raises(RPCError):
        LocalFiles.read(str(target), offset=-1)


async def test_new_tools_through_mcp_with_no_rpc_credentials(tmp_path):
    server = create_server(Config())
    async with Client(server, raise_exceptions=True) as client:
        result = await client.call_tool("msf_rpc_methods", {"query": "health."})
        assert result.structured_content["data"]["methods"][0]["method"] == "health.check"
        artifact = str(tmp_path / "example.rc")
        wrote = await client.call_tool("msf_file_write", {"path": artifact, "data": "version\n"})
        assert not wrote.is_error
        read = await client.call_tool("msf_file_read", {"path": artifact})
        assert read.structured_content["data"]["text"] == "version\n"
        started = await client.call_tool("msf_process_start", {
            "argv": [sys.executable, "-u", "-c", "print('NATIVE READY'); input()"],
        })
        pid = started.structured_content["data"]["process_id"]
        async def wait():
            while True:
                output = await client.call_tool("msf_process_read", {"process_id": pid})
                if "NATIVE READY" in output.structured_content["data"]["text"]:
                    break
                await asyncio.sleep(0.01)
        await asyncio.wait_for(wait(), 5)
        await client.call_tool("msf_process_write", {"process_id": pid, "data": "done\n"})
        closed = await client.call_tool("msf_process_close", {"process_id": pid})
        assert not closed.is_error
        bad = await client.call_tool("msf_process_read", {"process_id": "missing"})
        assert bad.is_error


@pytest.mark.parametrize("termination", ["disconnect", "sigterm"])
async def test_stdio_shutdown_cleans_native_children(termination):
    from mcp import StdioServerParameters

    if termination == "sigterm" and os.name == "nt":
        pytest.skip("Windows TerminateProcess cannot run Python signal/finally handlers")
    params = StdioServerParameters(command=sys.executable, args=["-m", "metasploit_mcp"])
    async with Client(params, read_timeout_seconds=10) as client:
        started = await client.call_tool("msf_process_start", {
            "argv": [sys.executable, "-u", "-c", "import os,sys; print(os.getppid()); sys.stdin.read()"],
        })
        process_id = started.structured_content["data"]["process_id"]
        native_pid = started.structured_content["data"]["pid"]
        async def find_parent():
            while True:
                output = await client.call_tool("msf_process_read", {"process_id": process_id})
                text = output.structured_content["data"]["text"].strip()
                if text:
                    return int(text)
                await asyncio.sleep(0.01)
        bridge_pid = await asyncio.wait_for(find_parent(), 5)
        if termination == "sigterm":
            os.kill(bridge_pid, signal.SIGTERM)
            # No request is pending while the connection closes.
            await asyncio.sleep(0.1)
    async def exited():
        while True:
            if not psutil.pid_exists(native_pid):
                return
            await asyncio.sleep(0.01)
    await asyncio.wait_for(exited(), 5)
