import asyncio
import json
import os
import signal
import subprocess
import sys
import threading

import httpx
import msgpack
import psutil
import pytest
from mcp import Client

from metasploit_mcp.cli import stop_process
from metasploit_mcp.config import Config
from metasploit_mcp.ownership import OWNER_ENV, ProcessOwner
from metasploit_mcp.processes import ProcessManager
from metasploit_mcp.rpc import RPCClient, RPCError, decode_input, json_output
from metasploit_mcp.server import create_server


@pytest.mark.parametrize("value", [
    {"$binary": "YWJj"},
    {"$binary": "not even base64"},
    {"$map": [["this", "is literal data"]]},
    {"$map": None},
    {1: "numeric", "1": "text"},
    {1.5: "float", "1.5": "text", b"key": "bytes"},
    {"nested": [{"$binary": "literal"}, {"$map": "literal"}, b"abc", {2: b"\x00\xff"}]},
    {"$binary": "ordinary multi-key object", "other": b"value"},
    {"$map": "ordinary multi-key object", "other": None},
])
def test_encoding_is_lossless_and_json_compatible(value):
    encoded = json_output(value)
    # A complete JSON round trip must not change how the value is decoded.
    assert decode_input(json.loads(json.dumps(encoded))) == value


def test_literal_marker_escape_and_numeric_key_types():
    assert json_output({"$binary": "literal"}) == {"$map": [["$binary", "literal"]]}
    assert decode_input({"$map": [["$binary", "literal"]]}) == {"$binary": "literal"}
    assert json_output({1: "int", "1": "str"}) == {"$map": [[1, "int"], ["1", "str"]]}
    # Normal string-keyed data and raw byte encoding keep their existing shapes.
    assert json_output({"normal": [1, True, None]}) == {"normal": [1, True, None]}
    assert json_output(b"abc") == {"$binary": "YWJj"}


@pytest.mark.parametrize("encoded", [
    {"$map": None}, {"$map": "bad"}, {"$map": [[1]]}, {"$map": [{"key": 1}]},
    {"$map": [[[1, 2], "unhashable"]]}, {"$map": [[1, "a"], [1, "b"]]},
])
async def test_invalid_map_rejected_without_network_activity(encoded):
    calls = []
    client = RPCClient(Config(token="token"), httpx.MockTransport(lambda request: calls.append(request)))
    try:
        with pytest.raises(RPCError, match="\\$map"):
            await client.call("custom.echo", [encoded])
        assert not calls
    finally:
        await client.close()


async def test_maps_roundtrip_through_messagepack_and_mcp():
    value = {1: "int", "1": "str", "literal": {"$binary": "literal"}, b"key": b"bytes"}
    wire = []
    def handler(request):
        parts = msgpack.unpackb(request.content, raw=False, strict_map_key=False)
        wire.append(parts)
        return httpx.Response(200, content=msgpack.packb(parts[2], use_bin_type=True))
    config = Config(token="token")
    rpc = RPCClient(config, httpx.MockTransport(handler))
    async with Client(create_server(config, rpc), raise_exceptions=True) as client:
        result = await client.call_tool("msf_rpc", {
            "method": "custom.echo", "params": [json_output(value)],
        })
        assert not result.is_error
        assert wire == [["custom.echo", "token", value]]
        assert decode_input(result.structured_content["data"]) == value


def is_active(pid):
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


async def read_pid(manager, process_id):
    async def read():
        while True:
            text = manager.read(process_id)["text"].strip()
            if text:
                return int(text)
            await asyncio.sleep(0.01)
    return await asyncio.wait_for(read(), 5)


@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("parent_exits", [False, True])
async def test_detached_descendant_cleanup_even_after_parent_exit(terminal, parent_exits):
    manager = ProcessManager()
    child_pid = None
    try:
        program = (
            "import subprocess,sys; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'], "
            "start_new_session=True); print(p.pid,flush=True); "
            + ("pass" if parent_exits else "sys.stdin.read()")
        )
        started = await manager.start([sys.executable, "-u", "-c", program], terminal=terminal)
        child_pid = await read_pid(manager, started["process_id"])
        if parent_exits:
            await asyncio.wait_for(manager.get(started["process_id"]).process.wait(), 5)
        assert is_active(child_pid)
        await manager.close(started["process_id"])
        assert not is_active(child_pid)
    finally:
        if child_pid and is_active(child_pid):
            os.kill(child_pid, signal.SIGKILL)
        await manager.shutdown()


async def test_unrelated_process_is_not_stopped():
    unrelated = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "import time; time.sleep(30)",
    )
    manager = ProcessManager()
    try:
        started = await manager.start([sys.executable, "-c", "import time; time.sleep(30)"])
        await manager.close(started["process_id"])
        assert unrelated.returncode is None
    finally:
        unrelated.kill()
        await unrelated.wait()
        await manager.shutdown()


async def test_concurrent_and_cancelled_close_still_cleans_up(monkeypatch):
    manager = ProcessManager()
    entered, release = threading.Event(), threading.Event()
    try:
        started = await manager.start([sys.executable, "-c", "import time; time.sleep(30)"])
        item = manager.get(started["process_id"])
        real_terminate = item.owner.terminate
        def slow_terminate():
            entered.set()
            assert release.wait(5)
            real_terminate()
        monkeypatch.setattr(item.owner, "terminate", slow_terminate)
        first = asyncio.create_task(manager.close(started["process_id"]))
        assert await asyncio.to_thread(entered.wait, 5)
        second = asyncio.create_task(manager.close(started["process_id"]))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
        await asyncio.wait_for(second, 5)
        assert not is_active(started["pid"])
        assert not manager.list()
    finally:
        release.set()
        await manager.shutdown()


def test_managed_rpc_cleanup_recovers_orphaned_descendant(tmp_path):
    owner = ProcessOwner()
    pid_file = tmp_path / "child.pid"
    program = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid))"
    )
    process = subprocess.Popen([sys.executable, "-c", program], env=owner.environment())
    process._metasploit_mcp_owner = owner
    owner.attach(process.pid)
    child_pid = None
    try:
        process.wait(timeout=5)
        child_pid = int(pid_file.read_text())
        stop_process(process)
        assert not is_active(child_pid)
    finally:
        if child_pid and is_active(child_pid):
            os.kill(child_pid, signal.SIGKILL)
        if process.poll() is None:
            process.kill()
            process.wait()


def test_pid_reuse_check_avoids_signaling_unrelated_group(monkeypatch):
    owner = ProcessOwner()
    class ReusedIdentity:
        pid = 12345
        def is_running(self):
            return False
    owner._root = ReusedIdentity()
    calls = []
    monkeypatch.setattr(os, "killpg", lambda *args: calls.append(args))
    owner.signal_group(signal.SIGTERM)
    assert not calls


def test_inherited_owner_marker_cannot_be_overridden():
    owner = ProcessOwner()
    assert owner.environment({OWNER_ENV: "different"})[OWNER_ENV] == owner.token


@pytest.mark.parametrize("terminal", [False, True])
async def test_cancelled_spawn_cleans_child_created_before_handle_return(monkeypatch, terminal):
    manager = ProcessManager()
    created, release = asyncio.Event(), asyncio.Event()
    child = None
    real_spawn = asyncio.create_subprocess_exec
    async def delayed_spawn(*args, **kwargs):
        nonlocal child
        child = await real_spawn(*args, **kwargs)
        created.set()
        await release.wait()
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(manager.start(
        [sys.executable, "-c", "import time; time.sleep(30)"], terminal=terminal,
    ))
    try:
        await asyncio.wait_for(created.wait(), 5)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert not is_active(child.pid)
        assert not manager.list()
    finally:
        release.set()
        if child and is_active(child.pid):
            child.kill()
            await child.wait()
        await manager.shutdown()
