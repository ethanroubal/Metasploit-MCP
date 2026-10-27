"""Persistent local processes with lossless output spools and POSIX PTYs or Windows ConPTY."""
import asyncio
import errno
import os
import signal
import struct
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from .ownership import ProcessOwner
from .platforms import WINDOWS, prepare_command, process_options
from .rpc import RPCError, decode_input, json_output
from .windows_terminal import WindowsTerminal


@dataclass
class Process:
    process: asyncio.subprocess.Process | WindowsTerminal
    argv: list[str]
    directory: Path
    stdout: BinaryIO
    stderr: BinaryIO | None
    owner: ProcessOwner
    master: int | None = None
    pump: asyncio.Task | None = None
    pump_error: str | None = None
    stdin_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    close_task: asyncio.Task | None = None


async def fd_ready(fd: int, *, write: bool = False):
    loop = asyncio.get_running_loop()
    ready = loop.create_future()

    def wake():
        if not ready.done():
            ready.set_result(None)

    register = loop.add_writer if write else loop.add_reader
    remove = loop.remove_writer if write else loop.remove_reader
    register(fd, wake)
    try:
        await ready
    finally:
        remove(fd)


class ProcessManager:
    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="metasploit-mcp-")
        self._processes: dict[str, Process] = {}
        self._closed = False

    def get(self, process_id: str) -> Process:
        try:
            return self._processes[process_id]
        except KeyError:
            raise RPCError("Unknown process ID; use msf_process_list") from None

    async def _pump_windows(self, item: Process):
        try:
            while True:
                data = await asyncio.to_thread(item.process.read)
                if data:
                    item.stdout.write(data)
                    item.stdout.flush()
                elif item.process.returncode is not None:
                    break
                else:
                    await asyncio.sleep(0.01)
        except (OSError, RPCError) as exc:
            item.pump_error = str(exc)

    async def _pump(self, item: Process):
        try:
            while True:
                try:
                    data = os.read(item.master, 65536)
                except BlockingIOError:
                    await fd_ready(item.master)
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:  # PTY slave closed on Linux/macOS.
                        break
                    raise
                if not data:
                    break
                item.stdout.write(data)
                item.stdout.flush()
        except asyncio.CancelledError:
            raise
        except OSError as exc:
            item.pump_error = str(exc)

    @staticmethod
    def _resize(fd: int, rows: int, columns: int):
        import fcntl
        import termios

        if not 1 <= rows <= 65535 or not 1 <= columns <= 65535:
            raise RPCError("Terminal rows and columns must be between 1 and 65535")
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))

    async def start(
        self, argv: list[str], *, terminal: bool = False, cwd: str | None = None,
        env: dict[str, str] | None = None, rows: int = 24, columns: int = 120,
    ) -> dict[str, Any]:
        if self._closed:
            raise RPCError("Process manager is closed")
        if not argv or not argv[0]:
            raise RPCError("argv must contain an executable and its arguments")
        if not 1 <= rows <= 65535 or not 1 <= columns <= 65535:
            raise RPCError("Terminal rows and columns must be between 1 and 65535")
        if terminal and WINDOWS and (rows > 32767 or columns > 32767):
            raise RPCError("Windows terminal dimensions must be between 1 and 32767")
        process_id = uuid.uuid4().hex
        directory = Path(self._temporary.name) / process_id
        directory.mkdir()
        stdout = (directory / "stdout").open("w+b")
        stderr = None if terminal else (directory / "stderr").open("w+b")
        master = slave = None
        process = None
        spawn_task = None
        owner = ProcessOwner()
        try:
            command, environment = prepare_command(argv, owner.environment(env))
            if terminal and WINDOWS:
                async def spawn_terminal():
                    return await asyncio.to_thread(
                        WindowsTerminal, command, cwd=cwd, env=environment, rows=rows, columns=columns,
                    )
                spawn_task = asyncio.create_task(spawn_terminal())
                process = await asyncio.shield(spawn_task)
            elif terminal:
                import pty

                master, slave = pty.openpty()
                self._resize(slave, rows, columns)
                # The small runner makes the PTY controlling terminal before exec,
                # without unsafe preexec_fn use in the MCP server process.
                spawn_task = asyncio.create_task(asyncio.create_subprocess_exec(
                    sys.executable, "-m", "metasploit_mcp.pty_runner", *command,
                    stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                    cwd=cwd, env={"TERM": "xterm-256color", **environment},
                ))
                process = await asyncio.shield(spawn_task)
                os.close(slave)
                slave = None
                os.set_blocking(master, False)
            else:
                spawn_task = asyncio.create_task(asyncio.create_subprocess_exec(
                    *command, stdin=asyncio.subprocess.PIPE, stdout=stdout, stderr=stderr,
                    cwd=cwd, env=environment, **process_options(),
                ))
                process = await asyncio.shield(spawn_task)
            owner.attach(process.pid)
            item = Process(process, argv, directory, stdout, stderr, owner, master)
            self._processes[process_id] = item
            if terminal:
                item.pump = asyncio.create_task(
                    self._pump_windows(item) if WINDOWS else self._pump(item),
                )
            return {"process_id": process_id, "pid": process.pid, "argv": argv,
                    "terminal": terminal, "stderr_merged": terminal}
        except BaseException:
            # Cancellation can arrive after the OS spawned a child but before
            # asyncio returned its handle. Recover the shielded handle first.
            if process is None and spawn_task is not None:
                result, = await asyncio.gather(spawn_task, return_exceptions=True)
                if not isinstance(result, BaseException):
                    process = result
            if process is not None:
                owner.attach(process.pid)
                await asyncio.to_thread(owner.terminate)
                await process.wait()
                if isinstance(process, WindowsTerminal):
                    await asyncio.to_thread(process.close)
            stdout.close()
            if stderr is not None:
                stderr.close()
            for fd in (master, slave):
                if fd is not None:
                    os.close(fd)
            raise

    def read(self, process_id: str, stream: str = "stdout", offset: int = 0,
             max_bytes: int = 65536) -> dict[str, Any]:
        item = self.get(process_id)
        if stream not in {"stdout", "stderr"} or offset < 0 or not 1 <= max_bytes <= 1048576:
            raise RPCError("Use stdout/stderr, a nonnegative offset, and max_bytes in 1..1048576")
        if stream == "stderr" and item.stderr is None:
            raise RPCError("PTY output merges stderr into stdout")
        path = item.directory / stream
        with path.open("rb") as source:
            source.seek(offset)
            data = source.read(max_bytes)
        size = path.stat().st_size
        drained = item.pump is None or item.pump.done()
        return {"data": json_output(data), "text": data.decode("utf-8", errors="replace"),
                "offset": offset, "next_offset": offset + len(data), "size": size,
                "eof": item.process.returncode is not None and drained and offset + len(data) >= size,
                "return_code": item.process.returncode, "capture_error": item.pump_error}

    async def write(self, process_id: str, data: Any = "", close_stdin: bool = False):
        item = self.get(process_id)
        value = decode_input(data)
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            raise RPCError("Process input must be text or a $binary object")
        async with item.stdin_lock:
            if item.process.returncode is not None:
                raise RPCError("The process has already exited")
            if item.stderr is None:
                if close_stdin:
                    raise RPCError("For PTY EOF send \\u0004; closing a PTY also closes its output")
                if WINDOWS:
                    await asyncio.to_thread(item.process.write, value)
                    return {"wrote": len(value), "stdin_closed": False}
                remaining = memoryview(value)
                while remaining:
                    try:
                        wrote = os.write(item.master, remaining[:65536])
                        remaining = remaining[wrote:]
                    except BlockingIOError:
                        await fd_ready(item.master, write=True)
            else:
                if item.process.stdin.is_closing():
                    raise RPCError("Process stdin is closed")
                item.process.stdin.write(value)
                await item.process.stdin.drain()
                if close_stdin:
                    item.process.stdin.close()
                    await item.process.stdin.wait_closed()
        return {"wrote": len(value), "stdin_closed": close_stdin}

    def send_signal(self, process_id: str, name: str):
        item = self.get(process_id)
        if WINDOWS:
            if name == "SIGINT" and item.stderr is None:
                item.process.write(b"\x03")
            elif name in {"SIGTERM", "SIGKILL", "SIGSTOP", "SIGCONT"}:
                action = {"SIGTERM": "terminate", "SIGKILL": "kill", "SIGSTOP": "suspend", "SIGCONT": "resume"}[name]
                import psutil
                for process in item.owner.discover():
                    try:
                        getattr(process, action)()
                    except psutil.NoSuchProcess:
                        pass
            elif name in {"SIGINT", "CTRL_BREAK_EVENT", "CTRL_C_EVENT"}:
                event = signal.CTRL_C_EVENT if name == "CTRL_C_EVENT" else signal.CTRL_BREAK_EVENT
                item.owner.signal_group(event)
            else:
                raise RPCError("Windows supports SIGINT, SIGTERM, SIGKILL, SIGSTOP, SIGCONT, CTRL_C_EVENT, or CTRL_BREAK_EVENT")
            return {"signal": name, "process_id": process_id}
        try:
            signum = signal.Signals[name]
        except KeyError:
            raise RPCError("Unknown POSIX signal name (for example SIGINT or SIGTERM)") from None
        item.owner.signal_group(signum)
        return {"signal": name, "process_id": process_id}

    def resize(self, process_id: str, rows: int, columns: int):
        item = self.get(process_id)
        if item.stderr is not None:
            raise RPCError("Resize is only available for terminal processes")
        if WINDOWS:
            item.process.resize(rows, columns)
        else:
            self._resize(item.master, rows, columns)
        return {"rows": rows, "columns": columns}

    def list(self):
        return [{"process_id": key, "pid": item.process.pid, "argv": item.argv,
                 "terminal": item.stderr is None, "return_code": item.process.returncode}
                for key, item in self._processes.items()]

    async def close(self, process_id: str):
        item = self.get(process_id)
        if item.close_task is None:
            item.close_task = asyncio.create_task(self._close(process_id, item))
        # Cleanup continues if the MCP caller cancels its request. Concurrent
        # close/shutdown calls await the same operation rather than deleting twice.
        try:
            return await asyncio.shield(item.close_task)
        except Exception:
            item.close_task = None
            raise

    async def _close(self, process_id: str, item: Process):
        await asyncio.to_thread(item.owner.terminate)
        await item.process.wait()
        if item.pump is not None:
            try:
                await asyncio.wait_for(asyncio.shield(item.pump), timeout=1)
            except TimeoutError:
                item.pump.cancel()
                await asyncio.gather(item.pump, return_exceptions=True)
        if item.master is not None:
            os.close(item.master)
        if isinstance(item.process, WindowsTerminal):
            await asyncio.to_thread(item.process.close)
        if item.process.stdin is not None:
            item.process.stdin.close()
        item.stdout.close()
        if item.stderr is not None:
            item.stderr.close()
        for path in item.directory.iterdir():
            path.unlink()
        item.directory.rmdir()
        del self._processes[process_id]
        return {"return_code": item.process.returncode}

    async def shutdown(self):
        self._closed = True
        results = await asyncio.gather(
            *(self.close(key) for key in list(self._processes)), return_exceptions=True,
        )
        errors = [result for result in results if isinstance(result, BaseException)]
        if errors:
            raise RPCError("Process cleanup failed: " + "; ".join(map(str, errors)))
        self._temporary.cleanup()
