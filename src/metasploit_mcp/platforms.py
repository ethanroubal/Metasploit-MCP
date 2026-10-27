"""Platform-specific launch settings, keeping arguments out of implicit shells."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .rpc import RPCError

WINDOWS = sys.platform == "win32"


def process_options():
    if WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def prepare_command(argv: list[str], env: dict[str, str]):
    if not argv or not argv[0]:
        raise RPCError("argv must contain an executable and its arguments")
    if not WINDOWS:
        return argv, env
    env = {key.upper(): value for key, value in env.items()}
    command = shutil.which(argv[0], path=env.get("PATH")) or argv[0]
    path = Path(command)
    if path.suffix.lower() not in {".bat", ".cmd"}:
        return [command, *argv[1:]], env
    # Rapid7's Windows wrappers select bundled Ruby and reset Ruby/Gem settings.
    # Execute that Ruby/script pair directly to preserve literal argv semantics.
    embedded = path.resolve().parent.parent / "embedded"
    ruby = embedded / "bin" / "ruby.exe"
    script = embedded / "framework" / path.stem
    if not script.is_file():
        script = embedded / "bin" / path.stem
    if path.stem.lower().startswith("msf") and ruby.is_file() and script.is_file():
        for name in ("GEM_HOME", "GEM_PATH", "GEM_ROOT", "RUBY_ENGINE", "RUBY_ROOT"):
            env.pop(name, None)
        env["PATH"] = str(ruby.parent) + os.pathsep + env.get("PATH", "")
        return [str(ruby), str(script), *argv[1:]], env
    raise RPCError(
        "Batch launchers need explicit shell handling. Use the executable/interpreter "
        "and script path as argv, or explicitly invoke cmd.exe /d /c with a command string. "
        "Rapid7's bundled Metasploit Ruby launchers are resolved automatically."
    )
