import asyncio
import os
import sys

import httpx
import msgpack
import pytest
from mcp import Client, StdioServerParameters

from metasploit_mcp.config import Config
from metasploit_mcp.rpc import RPCClient, RPCError
from metasploit_mcp.server import create_server


class FakeMetasploit:
    def __init__(self):
        self.calls = []
        self.consoles = {}
        self.expired = False

    def handle(self, request):
        assert request.headers["content-type"] == "binary/message-pack"
        parts = msgpack.unpackb(request.content, raw=False)
        self.calls.append(parts)
        method, *args = parts
        if method == "auth.login":
            assert args == ["msf", "test-password"]
            return self.response({"result": "success", "token": "test-token"})
        assert args.pop(0) == "test-token"
        if self.expired:
            self.expired = False
            return self.response({"error": True, "error_code": 401, "error_message": "Invalid token"})
        if method == "core.version":
            result = {"version": "test-framework", "api": "1.0"}
        elif method == "console.create":
            self.consoles["0"] = ""
            result = {"id": "0", "busy": False, "prompt": "msf > "}
        elif method == "console.write":
            self.consoles[args[0]] += "received:" + args[1]
            result = {"wrote": len(args[1])}
        elif method == "console.read":
            result = {"data": self.consoles[args[0]], "busy": False, "prompt": "msf > "}
            self.consoles[args[0]] = ""
        elif method == "console.destroy":
            del self.consoles[args[0]]
            result = {"result": "success"}
        elif method == "module.execute":
            result = {"job_id": 7, "uuid": "test-uuid"}
        elif method == "module.search":
            result = [{"fullname": "auxiliary/example"}]
        elif method == "module.info":
            result = {"name": "Example module"}
        elif method in {"session.list", "job.list"}:
            result = {7: {"type": "test"}}
        elif method == "custom.echo":
            result = args
        else:
            result = {"error": True, "error_code": 404, "error_message": "Unknown method"}
        return self.response(result)

    @staticmethod
    def response(value):
        return httpx.Response(200, content=msgpack.packb(value, use_bin_type=True))


@pytest.fixture
async def rpc():
    service = FakeMetasploit()
    config = Config(password="test-password")
    client = RPCClient(config, httpx.MockTransport(service.handle))
    yield client, service, config
    await client.close()


async def test_authentication_and_arbitrary_rpc_arguments(rpc):
    client, service, _ = rpc
    assert await client.call("core.version") == {"version": "test-framework", "api": "1.0"}
    args = ["text", 2, True, None, {"nested": [1, 2]}]
    assert await client.call("custom.echo", args) == args
    assert service.calls == [
        ["auth.login", "msf", "test-password"], ["core.version", "test-token"],
        ["custom.echo", "test-token", *args],
    ]


async def test_binary_nested_roundtrip_and_numeric_keys(rpc):
    client, _, _ = rpc
    args = [{"binary": {"$binary": "AP9BQkM="}}]
    assert await client.call("custom.echo", args) == args
    assert await client.call("job.list") == {"$map": [[7, {"type": "test"}]]}


async def test_legacy_ruby_binary_strings():
    payload = msgpack.packb({"data": b"\xff\x00", "prompt": "msf > "}, use_bin_type=False)
    client = RPCClient(Config(token="test-token"), httpx.MockTransport(
        lambda _: httpx.Response(200, content=payload)))
    try:
        assert await client.call("console.read", ["0"]) == {
            "data": {"$binary": "/wA="}, "prompt": "msf > ",
        }
    finally:
        await client.close()


async def test_authentication_expiry_does_not_replay_action(rpc):
    client, service, _ = rpc
    await client.call("core.version")
    service.expired = True
    with pytest.raises(RPCError, match="401"):
        await client.call("module.execute", ["auxiliary", "example", {}])
    assert sum(c[0] == "module.execute" for c in service.calls) == 1
    await client.call("core.version")
    assert sum(c[0] == "auth.login" for c in service.calls) == 2


async def test_concurrent_requests_share_one_login(rpc):
    client, service, _ = rpc
    await asyncio.gather(*(client.call("core.version") for _ in range(8)))
    assert sum(c[0] == "auth.login" for c in service.calls) == 1


@pytest.mark.parametrize("value", ["!invalid", None, 42])
async def test_invalid_binary_rejected_before_network(rpc, value):
    client, service, _ = rpc
    with pytest.raises(RPCError, match="Invalid.*base64"):
        await client.call("custom.echo", [{"$binary": value}])
    assert not service.calls


async def test_missing_credentials_and_bad_method_are_actionable():
    client = RPCClient(Config())
    try:
        with pytest.raises(RPCError, match="MSF_RPC_PASS"):
            await client.call("core.version")
        with pytest.raises(RPCError, match="method name"):
            await client.call("invalid method")
    finally:
        await client.close()


async def test_timeout_is_not_replayed():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("private data must not leak", request=request)

    client = RPCClient(Config(token="private-token"), httpx.MockTransport(handler))
    try:
        with pytest.raises(RPCError, match="may still be running") as exc:
            await client.call("module.execute", ["auxiliary", "example", {}])
        assert "private" not in str(exc.value)
        assert len(calls) == 1
    finally:
        await client.close()


@pytest.mark.parametrize("response, message", [
    (httpx.Response(302, headers={"Location": "http://example.org"}), "HTTP status 302"),
    (httpx.Response(401), "HTTP status 401"),
    (httpx.Response(200, content=b"not messagepack"), "invalid MessagePack"),
    (httpx.Response(200, content=msgpack.packb({"result": "failure"})), "returned failure"),
    (httpx.Response(200, content=msgpack.packb({
        "error": True, "error_code": 500, "error_message": "bad private-token",
    })), r"bad \[redacted\]"),
])
async def test_upstream_errors_and_secret_redaction(response, message):
    client = RPCClient(Config(token="private-token"), httpx.MockTransport(lambda _: response))
    try:
        with pytest.raises(RPCError, match=message):
            await client.call("core.version")
    finally:
        await client.close()


async def test_response_size_limit():
    client = RPCClient(Config(token="test-token", max_response_bytes=4), httpx.MockTransport(
        lambda _: FakeMetasploit.response({"data": "long response"})))
    try:
        with pytest.raises(RPCError, match="byte limit"):
            await client.call("core.version")
    finally:
        await client.close()


@pytest.mark.parametrize("url", [
    "http://example.com/api/", "http://0.0.0.0/api/", "file:///tmp/rpc",
    "http://user:secret@localhost/api/", "http://localhost/api/?token=secret",
])
def test_endpoint_validation(url):
    with pytest.raises(ValueError):
        Config(url=url)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_timeout_validation(timeout):
    with pytest.raises(ValueError):
        Config(timeout=timeout)


async def test_mcp_tool_discovery_console_state_execution_and_errors(rpc):
    rpc_client, service, config = rpc
    server = create_server(config, rpc_client)
    async with Client(server, raise_exceptions=True) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert {"msf_rpc", "msf_process_start", "msf_file_write", "msf_rpc_methods"} <= tools.keys()
        assert tools["msf_rpc"].annotations.destructive_hint is True
        assert tools["msf_console_read"].annotations.read_only_hint is False
        status = await client.call_tool("msf_status", {})
        assert not status.is_error
        assert status.structured_content["data"]["version"] == "test-framework"
        created = await client.call_tool("msf_console_create", {})
        console_id = created.structured_content["data"]["id"]
        wrote = await client.call_tool("msf_console_write", {"console_id": console_id, "command": "version"})
        assert wrote.structured_content["data"]["wrote"] == 8
        read = await client.call_tool("msf_console_read", {"console_id": console_id})
        assert read.structured_content["data"]["data"] == "received:version\n"
        empty = await client.call_tool("msf_console_read", {"console_id": console_id})
        assert empty.structured_content["data"]["data"] == ""
        await client.call_tool("msf_console_destroy", {"console_id": console_id})
        assert not service.consoles
        executed = await client.call_tool("msf_module_execute", {
            "module_type": "auxiliary", "module_name": "example", "options": {"VERBOSE": True},
        })
        assert executed.structured_content["data"]["job_id"] == 7
        bad = await client.call_tool("msf_rpc", {"method": "unknown.method"})
        assert bad.is_error
        assert "Unknown method" in bad.content[0].text
        invalid = await client.call_tool("msf_console_write", {"console_id": "0", "command": ""})
        assert invalid.is_error


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_real_stdio_subprocess_handshake(mode):
    env = {**os.environ, "MSF_RPC_PASS": "", "MSF_RPC_TOKEN": ""}
    params = StdioServerParameters(command=sys.executable, args=["-m", "metasploit_mcp"], env=env)
    async with Client(params, mode=mode, read_timeout_seconds=10) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert "msf_rpc" in names
        failure = await client.call_tool("msf_status", {})
        assert failure.is_error
        assert "MSF_RPC_PASS" in failure.content[0].text


async def test_managed_child_does_not_stop_existing_listener():
    import socket

    from metasploit_mcp.cli import launch_rpc

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        with pytest.raises(ValueError, match="already in use"):
            launch_rpc(Config(url=f"http://127.0.0.1:{port}/api/"), "not-a-real-executable", 1)


def test_launcher_failure_and_managed_child_cleanup(tmp_path):
    import socket

    from metasploit_mcp.cli import launch_rpc

    script = tmp_path / "fake_msfrpcd.py"
    script.write_text("raise SystemExit(1)\n")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(ValueError, match="exited during startup"):
        launch_rpc(Config(url=f"http://127.0.0.1:{port}/api/"), sys.executable, 2, [str(script)])


def test_config_repr_does_not_expose_secrets():
    value = repr(Config(password="secret-password", token="secret-token"))
    assert "secret-password" not in value
    assert "secret-token" not in value


@pytest.fixture
def fake_daemon(tmp_path):
    import socket

    script = tmp_path / "fake_daemon.py"
    script.write_text(r'''import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer
import msgpack

args = sys.argv
port = int(args[args.index("-p") + 1])
consoles = {}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        print("simulated RPC request accepted", file=sys.stderr, flush=True)
        body = self.rfile.read(int(self.headers["Content-Length"]))
        method, *params = msgpack.unpackb(body, raw=False)
        if method == "auth.login":
            assert params == [os.environ["MSF_RPC_USER"], os.environ["MSF_RPC_PASS"]]
            result = {"result": "success", "token": "daemon-token"}
        else:
            assert params.pop(0) == "daemon-token"
            if method == "core.version":
                result = {"version": "simulated-daemon"}
            elif method == "console.create":
                consoles["0"] = ""
                result = {"id": "0"}
            elif method == "console.write":
                consoles[params[0]] = "simulated output:" + params[1]
                result = {"wrote": len(params[1])}
            elif method == "console.read":
                result = {"data": consoles[params[0]], "busy": False, "prompt": "msf > "}
                consoles[params[0]] = ""
            else:
                result = {"result": "success"}
        packed = msgpack.packb(result, use_bin_type=True)
        self.send_response(200)
        self.send_header("Content-Length", str(len(packed)))
        self.end_headers()
        self.wfile.write(packed)

print("simulated daemon startup log", flush=True)
class LocalRPCServer(HTTPServer):
    def server_bind(self):
        # HTTPServer normally performs a reverse-DNS lookup here. The simulated
        # loopback service does not need DNS, which can stall on macOS runners.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

server = LocalRPCServer(("127.0.0.1", port), Handler)
print("simulated RPC listening", file=sys.stderr, flush=True)
server.serve_forever()
''')
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return script, port


def assert_port_closed(port):
    import socket

    with socket.socket() as sock:
        sock.settimeout(1)
        assert sock.connect_ex(("127.0.0.1", port)) != 0


def test_managed_check_over_real_http_and_cleanup(fake_daemon):
    import json
    import subprocess

    executable, port = fake_daemon
    result = subprocess.run(
        [sys.executable, "-m", "metasploit_mcp", "--launch-rpc", "--check",
         "--msfrpcd", sys.executable, "--msfrpcd-arg", str(executable), "--startup-timeout", "30"],
        env={**os.environ, "MSF_RPC_URL": f"http://127.0.0.1:{port}/api/"},
        capture_output=True, text=True, timeout=40, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["version"] == {"version": "simulated-daemon"}
    assert "simulated daemon startup log" in result.stderr
    assert_port_closed(port)


async def test_managed_stdio_console_roundtrip_and_shutdown(fake_daemon):
    executable, port = fake_daemon
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "metasploit_mcp", "--launch-rpc", "--msfrpcd", sys.executable, "--msfrpcd-arg", str(executable),
              "--startup-timeout", "30"],
        env={**os.environ, "MSF_RPC_URL": f"http://127.0.0.1:{port}/api/"},
    )
    async with Client(params, read_timeout_seconds=40) as client:
        assert "msf_console_write" in {t.name for t in (await client.list_tools()).tools}
        status = await client.call_tool("msf_status", {})
        assert status.structured_content["data"]["version"] == "simulated-daemon"
        created = await client.call_tool("msf_console_create", {})
        cid = created.structured_content["data"]["id"]
        await client.call_tool("msf_console_write", {"console_id": cid, "command": "version"})
        output = await client.call_tool("msf_console_read", {"console_id": cid})
        assert output.structured_content["data"]["data"] == "simulated output:version\n"
    assert_port_closed(port)
