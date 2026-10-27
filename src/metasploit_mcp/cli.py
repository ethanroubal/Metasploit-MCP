import argparse
import asyncio
import json
import secrets
import signal
import socket
import subprocess
import sys
import time
from dataclasses import replace
from urllib.parse import urlsplit

from .config import Config
from .ownership import ProcessOwner
from .platforms import prepare_command, process_options
from .rpc import RPCClient, RPCError


async def check(config: Config):
    client = RPCClient(config)
    try:
        return await client.call("core.version")
    finally:
        await client.close()


def stop_process(process):
    # Only identities/descendants owned by this invocation are stopped.
    owner = process._metasploit_mcp_owner
    owner.terminate()
    process.wait()


def launch_rpc(config: Config, executable: str, startup_timeout: float, arguments: list[str] | None = None):
    parsed = urlsplit(config.url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path != "/api/":
        raise ValueError("--launch-rpc requires http://127.0.0.1:PORT/api/")
    port = parsed.port or 80
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ValueError("RPC port is already in use; omit --launch-rpc to connect to it") from exc
    # Recent msfrpcd supports these environment variables, avoiding secrets in argv.
    managed = replace(config, username="mcp", password=secrets.token_urlsafe(32), token="")
    owner = ProcessOwner()
    env = owner.environment({"MSF_RPC_USER": managed.username, "MSF_RPC_PASS": managed.password})
    command, env = prepare_command(
        [executable, *(arguments or []), "-a", "127.0.0.1", "-p", str(port), "-u", "/api/", "-S", "-f"], env,
    )
    process = subprocess.Popen(
        command,
        env=env, stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr,
        **process_options(),
    )
    owner.attach(process.pid)
    process._metasploit_mcp_owner = owner
    try:
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(
                    "msfrpcd exited during startup. Check stderr; this mode requires a version "
                    "supporting MSF_RPC_USER and MSF_RPC_PASS. Older versions can be started manually."
                )
            try:
                asyncio.run(check(replace(managed, timeout=min(2, startup_timeout))))
                return managed, process
            except RPCError:
                time.sleep(0.25)
        raise ValueError("Timed out waiting for msfrpcd to authenticate")
    except BaseException:
        stop_process(process)
        raise


def main():
    parser = argparse.ArgumentParser(description="Local Metasploit MCP bridge (stdio)")
    parser.add_argument("--check", action="store_true", help="Check RPC auth/version and exit")
    parser.add_argument("--launch-rpc", action="store_true", help="Start and own a local msfrpcd child")
    parser.add_argument("--msfrpcd", default="msfrpcd", help="Path to msfrpcd for --launch-rpc")
    parser.add_argument("--msfrpcd-arg", action="append", default=[],
                        help="Argument before RPC flags, e.g. a script path when --msfrpcd is Ruby")
    parser.add_argument("--startup-timeout", type=float, default=60)
    args = parser.parse_args()
    process = None
    previous_sigterm = None
    try:
        config = Config.from_env()
        if args.startup_timeout <= 0 or not args.startup_timeout < float("inf"):
            raise ValueError("--startup-timeout must be positive and finite")
        # Route SIGTERM through server cleanup for both RPC and local process children.
        previous_sigterm = signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        if args.launch_rpc:
            config, process = launch_rpc(config, args.msfrpcd, args.startup_timeout, args.msfrpcd_arg)
        if args.check:
            print(json.dumps({"endpoint": config.url, "version": asyncio.run(check(config))}))
        else:
            from .server import create_server
            create_server(config).run(transport="stdio")
    except (ValueError, OSError, RPCError) as exc:
        print(f"metasploit-mcp: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        pass
    finally:
        if process is not None:
            stop_process(process)
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)
