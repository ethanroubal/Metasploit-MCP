# Metasploit coverage audit

The bridge provides three routes: arbitrary MessagePack RPC, the daemon's RPC
console, and native executables with persistent stdin/stdout or a controlling PTY.
It does not apply a module, command, executable, or RPC-method allowlist.

The reference catalog was extracted from the nine registered RPC handlers in
[Rapid7 commit e217fb2d76e34d71ce710f207f9ca419439e2ea4](https://github.com/rapid7/metasploit-framework/tree/e217fb2d76e34d71ce710f207f9ca419439e2ea4/lib/msf/core/rpc/v10).
It contains 123 canonical methods: auth 6, console 8, core 11, db 42, health 1,
job 3, module 28, plugin 3, session 21. No-auth implementation suffixes are mapped
to the public method names. Catalogs describe source declarations; they are not
proof that a configured daemon exposes a method or that an action will succeed.
Use `msf_rpc_methods(framework_root=...)` to inspect a local version's source.
Dynamically registered plugin methods remain callable even if not cataloged.

| Metasploit functionality | MCP route |
| --- | --- |
| Search, metadata, standard/advanced options, compatible payloads | `msf_rpc` module methods; RPC console |
| Run/check modules, payload generation, encoding, results and job tracking | `msf_rpc` module/job methods; RPC console |
| Framework globals, module paths, cache/reload, saving state | `msf_rpc` core methods; RPC console |
| Shell, Meterpreter, interactive session types, read/write, completion, stopping | `msf_rpc` session methods; RPC console |
| Session backgrounding, console completion, console creation options | `msf_rpc` console methods; `msf_console_create(options=...)` |
| Databases, workspaces, hosts, services, vulnerabilities, notes, credentials, loot | `msf_rpc` db methods; RPC console |
| Plugin load/unload and custom RPC handlers | `msf_rpc` plugin/custom methods; native console |
| Resource scripts, custom Ruby modules and module paths | File tools + console `resource` / module path commands |
| Ruby IRB, debuggers, interactive prompts, terminal-dependent commands | Native `msfconsole` through PTY process tools |
| Standalone `msfvenom`, Framework tools, database utilities, Ruby scripts | Native process tools with arbitrary argv, cwd, and environment |
| Binary input/output and large generated files | Pipe processes, base64 data, chunked file reads/writes |
| Console interrupt/EOF, terminal resizing, stop/continue and other signals | PTY control bytes; process signal and resize tools |
| Health and authentication methods without an RPC token | Automatic noauth detection; explicit `authenticated=false` |
| Methods added by future versions or custom plugins | Generic `msf_rpc`; native console/process routes |

## Gaps corrected by this audit

- Added native process and PTY interfaces instead of limiting access to the web-style
  RPC console. The PTY is a real controlling terminal, supporting `/dev/tty` and
  foreground process input/control behavior.
- Added local files and chunked output to handle scripts, imports, custom modules,
  binary stdin, generated artifacts, and outputs larger than one response.
- Added noauth handling, explicit login support, per-call RPC timeouts, a configurable
  response-size limit, and a searchable signature catalog.
- Limited the RPC lock to login, so a pending request does not prevent a second
  request from stopping or inspecting an action.
- Preserved Metasploit's MessagePack error details on non-200 HTTP responses and
  preserved modern binary fields even when mixed with legacy non-UTF-8 strings.

## Defects corrected after review

- Process close and managed-RPC shutdown now track process identities and descendant
  ancestry, plus an inherited per-launch marker to recover detached/reparented
  descendants. Cleanup continues through cancelled close calls and concurrent
  close requests share one cleanup operation. Startup cancellation recovers the
  subprocess handle before cleanup. Unrelated processes are not cleanup targets.
- JSON transport now preserves non-string map key types with `$map` pair lists.
  Literal `$binary` and `$map` marker-shaped objects use the same representation
  to escape the reserved form. Nested values round-trip without key collisions;
  malformed pair lists and duplicate keys fail before network activity.

## Validation and boundaries

Tests forward every cataloged method through the MessagePack transport using a
simulated upstream service. This verifies transport coverage and authentication
placement, **not execution or semantics of all 123 upstream methods**. Other tests
exercise MCP discovery/calls over real stdio, simulated local HTTP, pipe processes,
controlling PTYs, terminal input, Ctrl-C, resizing, binary round trips, file chunks,
and cleanup. Regression tests cover detached children before/after parent exit,
pipe and PTY cleanup, unrelated processes, cancellation, typed map keys, and literal
marker objects through both MessagePack and MCP. No exploit execution is used in
automated tests.

Live smoke tests are opt-in (`MSF_LIVE_TESTS=1`) and require an installed, configured
local Metasploit daemon. They exercise version, health, module search, and a console
round trip. A full live module/session/database compatibility run has not been
performed in an environment without Metasploit. No test suite can guarantee that
every module works on every target or platform.

Native consoles and an existing RPC daemon have separate in-memory state unless
the RPC plugin is loaded inside that native console. See the README's shared-instance
workflow. A bridge can only do what its OS user, installed Framework, dependencies,
plugins, sessions, network connectivity, and target allow. PTYs are macOS/Linux;
there is no graphical desktop automation interface. Process output is bounded by
available disk capacity; each MCP read is chunked. These are environmental and
interface limits, not a claim of universal success for every Metasploit action.
