"""Native ConPTY adapter. Imported on all hosts, pywinpty loaded only on Windows."""
import asyncio

from .rpc import RPCError


class WindowsTerminal:
    stdin = None

    def __init__(self, argv: list[str], *, cwd: str | None, env: dict[str, str], rows: int, columns: int):
        import subprocess

        from winpty import PTY, Backend

        self._pty = PTY(columns, rows, backend=Backend.ConPTY)
        self._returncode = None
        try:
            environment = "\0".join(f"{key}={value}" for key, value in sorted(env.items())) + "\0"
            spawned = self._pty.spawn(
                argv[0], cmdline=" " + subprocess.list2cmdline(argv[1:]) if len(argv) > 1 else None,
                cwd=cwd, env=environment,
            )
            if not spawned or self._pty.pid is None:
                raise RPCError("ConPTY failed to start the requested executable")
            self.pid = self._pty.pid
        except Exception as exc:
            self.close()
            raise RPCError(f"ConPTY startup failed: {exc}") from exc

    @property
    def returncode(self):
        if self._returncode is None and self._pty is not None and not self._pty.isalive():
            self._returncode = self._pty.get_exitstatus()
        return self._returncode

    async def wait(self):
        while self.returncode is None:
            await asyncio.sleep(0.02)
        return self.returncode

    def read(self):
        try:
            return self._pty.read(blocking=False).encode("utf-8")
        except Exception as exc:
            if self.returncode is not None:
                return b""
            raise RPCError(f"ConPTY read failed: {exc}") from exc

    def write(self, value: bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RPCError("Windows terminal input must be UTF-8; use pipe mode for arbitrary bytes") from exc
        try:
            self._pty.write(text)
        except Exception as exc:
            raise RPCError(f"ConPTY write failed: {exc}") from exc

    def resize(self, rows: int, columns: int):
        if not 1 <= rows <= 32767 or not 1 <= columns <= 32767:
            raise RPCError("Windows terminal dimensions must be between 1 and 32767")
        try:
            self._pty.set_size(columns, rows)
        except Exception as exc:
            raise RPCError(f"ConPTY resize failed: {exc}") from exc

    def close(self):
        # Dropping the native PTY object releases its handles and pseudoconsole.
        # The ProcessOwner terminates descendants before this is called.
        self._pty = None
