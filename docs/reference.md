# Advanced setup and tool reference

[Back to the README](../README.md). Run commands from the repository root.

## Windows setup

Install Python, Git, uv, and the official
[Windows Metasploit Framework package](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html#installing-metasploit-on-windows).
Follow the [README installation steps](../README.md#installation) from PowerShell.
The Windows-only ConPTY dependency is installed automatically.

When configuring the MCP client, use Windows paths. JSON requires escaped
backslashes, for example `"C:\\Users\\you\\Metasploit-MCP"`; forward slashes such as
`"C:/Users/you/Metasploit-MCP"` also work. `uv.exe` and Metasploit must be on the
GUI client's PATH, or use absolute paths.

A complete Windows configuration is in
[examples/mcp-windows.json](../examples/mcp-windows.json). It starts the bridge with
`--launch-rpc`. Rapid7's installed `msfrpcd.bat`, `msfconsole.bat`, and related
Ruby launchers are resolved to their bundled Ruby interpreter and script so
arguments retain their literal values without an implicit command shell.
Custom Ruby installations can instead use:

```powershell
uv run --frozen metasploit-mcp --launch-rpc --msfrpcd 'C:/Ruby/bin/ruby.exe' --msfrpcd-arg 'C:/metasploit-framework/msfrpcd' --check
```

To connect to an existing daemon, omit `--launch-rpc` and supply credentials in
the client configuration. In PowerShell, terminal environment variables use:

```powershell
$env:MSF_RPC_URL = 'http://127.0.0.1:55553/api/'
$env:MSF_RPC_USER = 'msf'
$env:MSF_RPC_PASS = 'your-local-rpc-password'
uv run --frozen metasploit-mcp --check
```

## Connect to an existing RPC daemon

If you already manage the RPC service yourself, omit `--launch-rpc`.
For a local HTTP setup, start Metasploit in a separate terminal:

```sh
msfrpcd -a 127.0.0.1 -p 55553 -U msf -P 'your-local-rpc-password' -S -f
```

Here `-S` disables TLS for the loopback connection and `-f` keeps the daemon in
the foreground. Use the same credentials in your MCP client:

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/Metasploit-MCP",
        "run",
        "--frozen",
        "metasploit-mcp"
      ],
      "env": {
        "MSF_RPC_URL": "http://127.0.0.1:55553/api/",
        "MSF_RPC_USER": "msf",
        "MSF_RPC_PASS": "your-local-rpc-password"
      }
    }
  }
}
```

Replace the project path and password. See [examples/mcp.json](../examples/mcp.json)
for another copy of this configuration.

To check this connection from a terminal:

```sh
export MSF_RPC_URL='http://127.0.0.1:55553/api/'
export MSF_RPC_USER='msf'
export MSF_RPC_PASS='your-local-rpc-password'
uv run --frozen metasploit-mcp --check
```

`.env` files are **not** automatically loaded. GUI clients normally need the
connection environment supplied explicitly in their MCP configuration. The bridge
leaves an externally managed RPC daemon running when it shuts down.

## Available tools

| Tool | Purpose |
| --- | --- |
| `msf_status` | Authenticate and get framework/API versions |
| `msf_rpc` | Any installed RPC method, with positional parameters, auth mode, and timeout |
| `msf_rpc_methods` | Search 123 reference RPC signatures or scan installed source |
| `msf_module_search` | Metasploit module search syntax |
| `msf_module_info` | Module metadata |
| `msf_module_execute` | Execute a module with datastore options |
| `msf_jobs` / `msf_sessions` | List running jobs / sessions |
| `msf_console_create` / `msf_console_list` | Create / find persistent consoles |
| `msf_console_write` / `msf_console_read` | Submit commands / consume output |
| `msf_console_destroy` | Release a console |
| `msf_process_start` / `msf_process_list` | Start native executables / find owned processes |
| `msf_process_read` / `msf_process_write` | Read output chunks / send stdin or terminal keys |
| `msf_process_signal` / `msf_process_resize` | Interrupt / stop / resume / resize a PTY |
| `msf_process_close` | Stop an owned process tree and delete captured output |
| `msf_file_read` / `msf_file_write` / `msf_file_list` | Local artifact access with chunking |

There are 23 MCP tools. The resource `metasploit://usage` provides client instructions
and a reference link. See [the coverage audit](coverage.md) for feature routes,
validation evidence, and the limits of the coverage claim.

## RPC calls

`msf_rpc` accepts `method` and `params`. The bridge inserts the authentication token;
do not include it in `params`. Results are returned as `{"data": <RPC result>}`.

For example, call `msf_rpc` with these arguments to search installed modules:

```json
{"method": "module.search", "params": ["type:auxiliary name:http"]}
```

Other calls include `core.version`, `db.workspaces`, `job.list`, and `session.list`,
all with an empty `params` array. These snippets are MCP tool arguments, not shell
commands.

This covers the `core`, `module`, `job`, `session`, `db`, `plugin`, `console`, and
`auth` handlers provided by your version. Read module options with `module.options`
before execution. For long-running modules, track returned job IDs / UUIDs with
`job.info`, `module.running_stats`, and `module.results`, where supported.
Session shell/Meterpreter methods are available through the same generic tool.
Method availability and argument signatures depend on the installed framework.
Password login is normally managed internally. `auth.login` and `health.check`
automatically omit the token. For another unauthenticated endpoint, pass
`authenticated=false`; set `authenticated=true` to force token insertion. An
explicit successful `auth.login` updates the token used for subsequent calls.
`timeout` overrides the HTTP timeout for an individual RPC call. Nothing is
replayed automatically. `msf_console_create` also accepts optional console options.

`msf_rpc_methods` returns method signatures and authentication requirements from
a reference catalog pinned to a specific upstream commit. Set `framework_root` to
your installed Framework directory to scan its source instead. This is source
information, not a live probe or an allowlist; custom plugin methods can always
be called directly. Refresh the bundled catalog with
`uv run --frozen python scripts/update_rpc_catalog.py --ref COMMIT_OR_REF`.

For binary arguments and results, an exact `{"$binary": "BASE64_DATA"}` object
represents bytes, recursively inside arrays and objects. Normal strings stay text.
Older Ruby responses sometimes encode bytes as strings; invalid UTF-8 string data
is returned as base64. Valid UTF-8 legacy string fields remain text.

Maps with non-string keys use `{"$map": [[key, value], ...]}` so numeric, text, and
binary keys retain their types and cannot overwrite one another. For example,
`{"$map": [[1, "integer key"], ["1", "string key"]]}` retains both entries.
This representation also escapes a **literal** object whose only key is `$binary`
or `$map`: `{"$map": [["$binary", "literal value"]]}` represents a map, not bytes.
The encoding applies recursively in arguments and results. Ordinary string-keyed
objects keep their existing JSON shape; malformed pair lists and duplicate map
keys are rejected before sending a request. Clients handling job/session maps
with numeric keys must accept this `$map` result representation.

The default RPC response limit is 64 MiB; configure
`MSF_RPC_MAX_RESPONSE_BYTES` when a larger response is required. Native process and
file tools use chunked reads so total output can exceed a single MCP response.

## Console workflow

1. Call `msf_console_create` and retain its `id` from `data`.
2. Call `msf_console_write` with that ID and a command such as `version` or `help`.
3. Call `msf_console_read` repeatedly to consume output. Writes append a newline
   unless `append_newline=false`. Each console keeps its module and option state.
4. Destroy the console when done. Stop any jobs/sessions separately if required.

Reads drain the output buffer. Do not share a console between independent agents.
A `busy=false` snapshot immediately after a write does not prove command completion.
Consoles created by tools remain in Metasploit until explicitly destroyed or the
underlying daemon stops; shutting down an externally connected bridge leaves them.

## What “any action” means

There is no bridge-level restriction on RPC methods or console commands. Coverage
is bounded by the installed Metasploit version, plugins, OS permissions, database,
and available sessions. Native PTY mode provides a controlling terminal, input, control characters,
signals, and resizing for interactive programs. It returns terminal bytes rather
than rendering a graphical terminal screen. Programs requiring a graphical desktop
still require that desktop environment. Framework console commands can run
local code, and session methods can operate on connected systems. Only connect
clients that you intend to grant that authority. Remote output should be treated
as untrusted data by the AI client.

## Native tools, interactive terminals, and files

Start an interactive native console:

```json
{"argv": ["msfconsole", "-q"], "terminal": true}
```

Use the returned `process_id` with `msf_process_read` and `msf_process_write`.
Process writes do **not** append newlines. Send `"help\n"` to execute a command,
`"\u0003"` for Ctrl-C, and `"\u0004"` for terminal EOF. `msf_process_signal` also
supports process controls, and `msf_process_resize` updates terminal dimensions.
On Windows, commands normally end in `"\r\n"`; Ctrl-Z plus Enter is the conventional
console EOF gesture, whereas Ctrl-D is a POSIX convention. A pipe can always send
EOF using `close_stdin=true`. Windows terminal input must be valid UTF-8; pipe
mode preserves arbitrary bytes. Windows resizing accepts dimensions up to 32767.

For standalone tools, use pipe mode to preserve binary stdout exactly:

```json
{"argv": ["msfvenom", "--help"], "terminal": false}
```

The executable and arguments are passed literally with no implicit shell interpolation.
On Windows, Rapid7's bundled Ruby batch launchers are resolved to Ruby and their
scripts. Other `.bat`/`.cmd` launchers require an explicit interpreter or an explicit
`cmd.exe /d /c` command string; shell quoting and expansion then follow that shell's
rules. For PowerShell scripts, use an explicit `powershell.exe -File` invocation.
Use an absolute executable path when it is not on the MCP client's PATH. `cwd` and
an `env` object can be supplied. The process tool can launch installed Framework
utilities, Ruby scripts, and external programs used by Metasploit; it has the
same OS authority as the bridge. Pipe stdout/stderr are separate. Pipe stdin can
accept text or `{"$binary": "..."}` and `close_stdin=true` sends EOF.

Reads accept `offset` and `max_bytes` (up to 1 MiB) and return lossless `data`,
display-only `text`, `next_offset`, `return_code`, and `eof`. Retain `next_offset`;
reads do not drain output. UTF-8 characters may span chunks, so decode concatenated
bytes when exact text matters. Output is spooled to temporary disk files until
`msf_process_close` or bridge shutdown; disk capacity bounds total captured output.
Retrieve output before closing. Cleanup tracks process identities and descendants,
including new sessions. A per-launch inherited `METASPLOIT_MCP_PROCESS_OWNER`
marker recovers descendants that have already been reparented after their parent
exits. Cleanup checks process identities before signaling and escalates from TERM
to KILL when needed. It continues if the close request is cancelled. The managed
RPC launcher uses the same ownership tracking. This is lifecycle tracking, not
OS containment: a process that both removes the marker and loses all known
ancestry cannot be identified through this mechanism.

Terminal output combines stdout/stderr and follows terminal transformations;
Windows ConPTY produces Unicode terminal output which is spooled as UTF-8. Use
pipes or output files for exact binary artifacts. On Windows, `SIGINT` writes
Ctrl-C in terminal mode; pipe mode attempts `CTRL_BREAK_EVENT`, which requires a
shared Windows console. `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` can be requested
explicitly. `SIGTERM`/`SIGKILL` terminate the owned tree; `SIGSTOP`/`SIGCONT` use
suspend/resume. Other POSIX signals are unavailable. Forcefully terminating the
bridge process on Windows bypasses Python cleanup; normal MCP disconnect performs
cleanup, as does normal shutdown on macOS/Linux.

### Share native console and RPC state

A newly launched `msfconsole` normally has its own framework instance. To use
native terminal interaction **and** RPC against one instance:

1. Start the bridge without `--launch-rpc`, with `MSF_RPC_USER` and `MSF_RPC_PASS`
   set for the RPC endpoint you plan to create.
2. Launch `msfconsole` through `msf_process_start` in terminal mode.
3. Inside that native console, load Metasploit's `msgrpc` plugin with the same
   user/password, `ServerHost=127.0.0.1`, the configured `ServerPort`, and the matching
   SSL setting and URI. For the default bridge endpoint, the console command is:

   ```text
   load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=your-local-rpc-password SSL=false URI=/api/
   ```

   Replace the placeholder password with the same value configured in the bridge.
4. Call `msf_status`. RPC and the native terminal now operate on that framework's
   sessions, modules, datastore, and jobs. Avoid simultaneous interaction with the
   same session from both interfaces.

If you connect to an already-running `msfrpcd`, a separately launched native
console will not inherit its in-memory sessions. Continue using the RPC console
and session APIs for that daemon, or start with the shared-instance workflow.

### Scripts, custom modules, imports, and generated artifacts

`msf_file_write` creates local files from text or base64 chunks. Use `truncate=true`
on the first chunk to replace an existing file, then continue at `next_offset`.
You can write resource scripts and run `resource /absolute/path/file.rc` through
the console, write custom Ruby modules and load their module path, or stage database
import files. `msf_file_read` retrieves generated files in chunks; `msf_file_list`
finds outputs with directory pagination. These paths are local to the MCP host,
which is also the local RPC host in the supported setup. Remote session filesystem
operations continue to use Metasploit's session commands/APIs.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `MSF_RPC_URL` | `http://127.0.0.1:55553/api/` | Local MessagePack endpoint |
| `MSF_RPC_USER` | `msf` | RPC username |
| `MSF_RPC_PASS` | empty | RPC password |
| `MSF_RPC_TOKEN` | empty | Existing token; takes precedence over password |
| `MSF_RPC_TIMEOUT` | `30` | Default per-request HTTP timeout in seconds |
| `MSF_RPC_MAX_RESPONSE_BYTES` | `67108864` | Maximum bytes in a single RPC response |
| `MSF_RPC_VERIFY_TLS` | `true` | Verify HTTPS certificates |
| `MSF_RPC_CA_FILE` | empty | Custom CA file for local HTTPS |

Only loopback endpoint names/addresses are accepted. HTTP clients ignore proxy
environment variables and do not follow redirects. For HTTPS with a private CA,
set `MSF_RPC_CA_FILE`. A self-signed local endpoint can explicitly use
`MSF_RPC_VERIFY_TLS=false`; verification is enabled by default. The bridge itself
exposes only stdio, with no network listener.

Only password login is serialized. RPC actions can run concurrently, allowing
another call to inspect state or stop a job while an earlier call is waiting.
Keep reads/writes to each individual console or session ordered. Failed or timed-out requests are never
automatically replayed: an action could already have executed. Check its state
before retrying. After an authentication rejection, password-based connections
log in on the next call. Token-only connections require a valid replacement token
and a bridge restart if their configured token expires. MCP cancellation does not
cancel an underlying Metasploit job.

## Development

```sh
uv sync --frozen --group dev
uv run --frozen pytest
uv run --frozen ruff check .
```

GitHub Actions runs the suite on Windows, Linux, and macOS with Python 3.11 and
3.14. Windows-specific integration tests exercise native ConPTY input, interrupts,
resizing, cleanup, and the shared pipe/file/RPC tests. Live Metasploit smoke tests
remain opt-in.

Tests cover all 123 cataloged RPC method routes, simulated MessagePack services,
MCP protocol connections, actual local processes, PTY controlling-terminal behavior,
Ctrl-C, resizing, binary stdin/stdout, file chunks, and child cleanup. They do not
execute exploitation modules or require a live Metasploit installation. Run
`metasploit-mcp --check` and a `version` console round trip to validate a real
installation. An end-to-end live Metasploit check requires Metasploit installed.
With a running, configured local RPC service, opt in to non-exploitative live smoke
tests using `MSF_LIVE_TESTS=1 uv run --frozen pytest tests/test_live.py -q`.

## References

- [MessagePack RPC guide](https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/how-to-use-metasploit-messagepack-rpc.html)
- [Metasploit RPC class reference](https://docs.metasploit.com/api/Msf/RPC.html)
- [msfrpcd source and flags](https://github.com/rapid7/metasploit-framework/blob/master/msfrpcd)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
