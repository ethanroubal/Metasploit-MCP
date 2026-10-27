# Connect ChatGPT

Install the project using the [README](../README.md#1-install) first.

## Desktop app

ChatGPT desktop and Codex share local MCP configuration, according to the
[official OpenAI documentation](https://learn.chatgpt.com/docs/extend/mcp).

1. Merge [mcp-chatgpt.toml](../examples/mcp-chatgpt.toml) into
   `~/.codex/config.toml` (Windows: `%USERPROFILE%/.codex/config.toml`).
2. Replace the example project path with your clone's absolute path. On Windows,
   change `uv` to `uv.exe` and use forward slashes in the project path.
3. Restart the app. Type `/mcp` to check the connection, then ask it to call
   `msf_status`.

Alternatively, open **Settings → MCP servers → Add server**, choose **STDIO**,
and enter the sample's command and arguments. Add each argument as a separate
entry; the project path is one entry even when it contains spaces. `--directory`
must point to this cloned project, not the Metasploit installation or `msfconsole`.
See the [README's desktop steps](../README.md#2-add-the-mcp-server).
Save and select **Restart**.
The TOML example allows 120 seconds for startup because Metasploit can take longer
than the client's default timeout.

If a command is not found, use absolute paths for `uv` and `msfrpcd` as explained
in [troubleshooting](../README.md#troubleshooting).

Each automatic connection starts its own Metasploit instance on a free local port.
Chats therefore have separate sessions and jobs. An explicit `MSF_RPC_URL` pins
the port; omit it for concurrent automatic connections, or use an existing daemon
to [share state](reference.md#connect-to-an-existing-rpc-daemon).

## ChatGPT in a browser

The browser does not load the local TOML file. This bridge serves stdio, not an
HTTP MCP endpoint; its Metasploit RPC address is not an MCP server URL.

Use OpenAI's [Secure MCP Tunnel setup](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
to connect the existing stdio server:

1. Create a tunnel in Platform tunnel settings and obtain a runtime API key.
2. Run `tunnel-client` on the Metasploit computer. Configure its stdio command as
   `uv --directory /absolute/path/to/Metasploit-MCP run --frozen metasploit-mcp --launch-rpc`.
   Keep the tunnel client running.
3. In ChatGPT, open **Plugins → + → Add custom MCP server**, select **Tunnel**,
   choose your tunnel, and create and install the plugin.
4. Select the plugin with `@` and ask it to call `msf_status`.

Tunnel access and ChatGPT workspace permissions must allow this connection. See
the [official custom MCP server guide](https://developers.openai.com/api/docs/guides/custom-mcp-server)
for availability, authentication, and workspace restrictions.

These are configuration examples; a live ChatGPT connection has not been tested
in this repository.
