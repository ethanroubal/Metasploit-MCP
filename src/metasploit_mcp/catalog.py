"""Source-based RPC method discovery; catalogs are references, never allowlists."""
import json
import re
from importlib.resources import files
from pathlib import Path


def scan_framework(root: str | Path):
    root = Path(root).expanduser().resolve()
    base = root / "lib/msf/core/rpc/v10"
    service = (base / "service.rb").read_text()
    handlers = dict(re.findall(r'add_handler\(\s*"([^"]+)"\s*,\s*([\w:]+)\.new', service))
    methods = []
    for source in sorted(base.glob("rpc_*.rb")):
        text = source.read_text()
        found = re.search(r"class\s+(RPC_\w+)", text)
        if not found:
            continue
        groups = [group for group, name in handlers.items() if name.split("::")[-1] == found[1]]
        for declaration in re.finditer(r"^[ \t]*def[ \t]+rpc_(\w+)([^\n]*)", text, re.MULTILINE):
            name, arguments = declaration[1], declaration[2].strip()
            # Join multiline argument declarations without evaluating Ruby.
            end = declaration.end()
            while arguments.count("(") > arguments.count(")") and end < len(text):
                next_end = text.find("\n", end + 1)
                if next_end < 0:
                    next_end = len(text)
                arguments += " " + text[end:next_end].strip()
                end = next_end
            noauth = name.endswith("_noauth")
            if noauth:
                name = name.removesuffix("_noauth")
            for group in groups:
                methods.append({"method": f"{group}.{name}", "arguments": arguments,
                                "authenticated": not noauth,
                                "source": str(source.relative_to(root)),
                                "line": text.count("\n", 0, declaration.start()) + 1})
    return {"origin": str(root), "reference_only": True,
            "methods": sorted(methods, key=lambda entry: entry["method"])}


def method_catalog(framework_root: str | None = None, query: str = "",
                   offset: int = 0, limit: int = 100):
    catalog = scan_framework(framework_root) if framework_root else json.loads(
        files("metasploit_mcp").joinpath("rpc_methods.json").read_text())
    matches = [entry for entry in catalog["methods"] if query.lower() in entry["method"].lower()]
    return {**{key: value for key, value in catalog.items() if key != "methods"},
            "total": len(matches), "methods": matches[offset:offset + limit],
            "next_offset": min(offset + limit, len(matches))}
