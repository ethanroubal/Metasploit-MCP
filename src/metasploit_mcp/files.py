"""Chunked local artifact access for resource scripts, modules, imports, and exports."""
from pathlib import Path
from typing import Any

from .rpc import RPCError, decode_input, json_output


class LocalFiles:
    @staticmethod
    def read(path: str, offset: int = 0, max_bytes: int = 65536):
        if offset < 0 or not 1 <= max_bytes <= 1048576:
            raise RPCError("Use a nonnegative offset and max_bytes in 1..1048576")
        target = Path(path).expanduser().resolve()
        with target.open("rb") as source:
            source.seek(offset)
            data = source.read(max_bytes)
            size = source.seek(0, 2)
        return {"path": str(target), "data": json_output(data),
                "text": data.decode("utf-8", errors="replace"), "size": size,
                "next_offset": offset + len(data), "eof": offset + len(data) >= size}

    @staticmethod
    def write(path: str, data: Any, offset: int = 0, truncate: bool = False):
        if offset < 0:
            raise RPCError("File offset must be nonnegative")
        value = decode_input(data)
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            raise RPCError("File data must be text or a $binary object")
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        # a+b cannot be used: append mode ignores seek when writing.
        try:
            source = target.open("r+b")
        except FileNotFoundError:
            source = target.open("x+b")
        with source:
            if truncate:
                source.truncate(0)
            source.seek(offset)
            source.write(value)
        return {"path": str(target), "wrote": len(value), "next_offset": offset + len(value),
                "size": target.stat().st_size}

    @staticmethod
    def list(path: str, offset: int = 0, limit: int = 100):
        if offset < 0 or not 1 <= limit <= 1000:
            raise RPCError("Use a nonnegative offset and limit in 1..1000")
        target = Path(path).expanduser().resolve()
        entries = sorted(target.iterdir(), key=lambda entry: entry.name)
        return {"path": str(target), "total": len(entries),
                "entries": [{"name": entry.name, "directory": entry.is_dir(),
                             "size": entry.stat().st_size if entry.is_file() else None}
                            for entry in entries[offset:offset + limit]],
                "next_offset": min(offset + limit, len(entries))}
