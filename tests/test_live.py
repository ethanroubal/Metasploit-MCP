"""Explicit opt-in: only version, search, health, and console version commands."""
import os

import pytest
from mcp import Client

from metasploit_mcp.config import Config
from metasploit_mcp.server import create_server

pytestmark = pytest.mark.skipif(os.getenv("MSF_LIVE_TESTS") != "1", reason="live Metasploit not requested")


async def test_live_framework_mcp_roundtrip():
    import asyncio

    async with Client(create_server(Config.from_env()), raise_exceptions=True) as client:
        status = await client.call_tool("msf_status", {})
        assert not status.is_error
        assert status.structured_content["data"]["version"]
        health = await client.call_tool("msf_rpc", {"method": "health.check"})
        assert not health.is_error
        search = await client.call_tool("msf_module_search", {"query": "type:auxiliary"})
        assert not search.is_error
        created = await client.call_tool("msf_console_create", {})
        assert not created.is_error
        console_id = created.structured_content["data"]["id"]
        try:
            await client.call_tool("msf_console_read", {"console_id": console_id})
            wrote = await client.call_tool("msf_console_write", {"console_id": console_id, "command": "version"})
            assert not wrote.is_error
            async def collect():
                output = ""
                while True:
                    read = await client.call_tool("msf_console_read", {"console_id": console_id})
                    assert not read.is_error
                    output += read.structured_content["data"]["data"]
                    if "Framework" in output:
                        return output
                    await asyncio.sleep(0.1)
            assert await asyncio.wait_for(collect(), 15)
        finally:
            await client.call_tool("msf_console_destroy", {"console_id": console_id})
