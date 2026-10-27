"""Track local process identity across descendants, new sessions, and reparenting."""
import os
import time
import uuid

import psutil

from .platforms import WINDOWS
from .rpc import RPCError

OWNER_ENV = "METASPLOIT_MCP_PROCESS_OWNER"


class ProcessOwner:
    def __init__(self):
        self.token = uuid.uuid4().hex
        self._known: dict[int, psutil.Process] = {}
        self._root: psutil.Process | None = None

    def environment(self, overrides: dict[str, str] | None = None):
        return {**os.environ, **(overrides or {}), OWNER_ENV: self.token}

    def attach(self, pid: int):
        try:
            self._root = psutil.Process(pid)
            # Cache creation time so psutil's signal methods can reject PID reuse.
            self._root.create_time()
            self._known[pid] = self._root
        except psutil.NoSuchProcess:
            pass

    @staticmethod
    def active(process: psutil.Process):
        try:
            return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False

    def discover(self):
        # First recover descendants of known identities, including children that
        # start new sessions or replace their inherited environment.
        for process in list(self._known.values()):
            try:
                for child in process.children(recursive=True):
                    child.create_time()
                    self._known[child.pid] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # Once a parent exits, PPID ancestry is lost. An inherited per-launch
        # marker still identifies ordinary detached/reparented descendants.
        for process in psutil.process_iter():
            try:
                if process.environ().get(OWNER_ENV) == self.token:
                    process.create_time()
                    self._known[process.pid] = process
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return [process for process in self._known.values() if self.active(process)]

    def signal_group(self, signum: int):
        # Never reuse a bare remembered PID as a process-group target after the
        # leader exits: that PID may now identify an unrelated process group.
        if self._root is not None and self._root.is_running():
            try:
                if WINDOWS:
                    self._root.send_signal(signum)
                else:
                    os.killpg(self._root.pid, signum)
            except ProcessLookupError:
                pass

    def terminate(self, timeout: float = 2):
        """Stop owned processes, then kill survivors; do not reap asyncio's child."""
        frozen: dict[int, psutil.Process] = {}
        terminated: set[int] = set()
        try:
            # Freeze each discovered generation before stopping parents so
            # descendants cannot disappear from ancestry during this snapshot.
            for _ in range(8):
                new = [process for process in self.discover() if process.pid not in frozen]
                if not new:
                    break
                for process in new:
                    try:
                        process.suspend()
                    except psutil.NoSuchProcess:
                        continue
                    frozen[process.pid] = process
            for process in reversed(list(frozen.values())):
                try:
                    process.terminate()
                    terminated.add(process.pid)
                except psutil.NoSuchProcess:
                    pass
        finally:
            for process in frozen.values():
                # Windows termination kills suspended processes directly. A
                # resume after TerminateProcess can race with kernel teardown
                # and fail with AccessDenied even for an owned process.
                if WINDOWS and process.pid in terminated:
                    continue
                try:
                    process.resume()
                except psutil.NoSuchProcess:
                    pass
        deadline = time.monotonic() + timeout
        alive = list(frozen.values())
        while alive and time.monotonic() < deadline:
            alive = [process for process in alive if self.active(process)]
            if alive:
                time.sleep(0.02)
        # Also find children spawned by a termination handler, or reparented
        # children whose parent exited before the initial snapshot.
        alive = self.discover()
        for process in alive:
            try:
                process.kill()
            except psutil.NoSuchProcess:
                pass
        deadline = time.monotonic() + 2
        while alive and time.monotonic() < deadline:
            alive = [process for process in alive if self.active(process)]
            if alive:
                time.sleep(0.02)
        if alive:
            raise RPCError("Could not stop owned processes: " + ", ".join(str(p.pid) for p in alive))
