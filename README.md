# Metasploit-MCP

Connect AI agents to local Metasploit through MCP. Includes 23 tools for RPC,
modules, sessions, jobs, consoles, native terminals, and files.

Use only on systems you are authorized to test.

## Installation

### Requirements

- Python 3.11+, [uv](https://docs.astral.sh/uv/), and Git.
- [Metasploit Framework](https://docs.metasploit.com/) installed, with `msfrpcd` on your PATH.
- An AI client that supports local MCP servers.

Supports macOS, Linux, and Windows 10 (1809+) / Windows 11.

### 1. Install

```sh
git clone https://github.com/ethanroubal/Metasploit-MCP.git
cd Metasploit-MCP
uv sync --frozen
```

### 2. Add the MCP server

Add this entry to your AI client's MCP configuration:

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/Metasploit-MCP",
        "run", "--frozen", "metasploit-mcp", "--launch-rpc"
      ]
    }
  }
}
```

Replace the project path with your clone's absolute path. If you already have
MCP servers configured, add `metasploit` inside the existing `mcpServers` object.

**Windows:** use `uv.exe` and a path such as `C:/Users/you/Metasploit-MCP`.
See the [Windows configuration](examples/mcp-windows.json).

### 3. Connect

Restart your AI client and ask it to call `msf_status`. A successful response shows
the Metasploit version.

The client starts the MCP server and local RPC daemon automatically. The bridge
creates temporary credentials and stops its daemon on shutdown. Automatic startup
requires a recent Metasploit release; for an existing or older daemon, follow
[these instructions](docs/reference.md#connect-to-an-existing-rpc-daemon).

## Usage

Ask your AI client to use the Metasploit tools. For example:

- “Check the Metasploit version and list running jobs.”
- “Search for HTTP auxiliary modules and show their options.”
- “Create a console, run `version`, read the output, and close it.”
- “List the available sessions.”

You do not need to start the MCP server manually when using the configuration
above. Metasploit must be installed separately; database operations also need a
configured Metasploit database.

### Troubleshooting

- **Command not found:** use absolute paths for `uv` and `msfrpcd`. Append
  `"--msfrpcd", "/path/to/msfrpcd"` to the configuration's `args` if needed.
- **Port already in use:** connect to the running daemon using the
  [existing-daemon configuration](examples/mcp.json).

### More information

- [Advanced setup, tool reference, and development](docs/reference.md)
- [Feature coverage and limitations](docs/coverage.md)
- [MCP configuration examples](examples/)
