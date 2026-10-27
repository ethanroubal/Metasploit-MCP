"""Refresh the reference catalog from a pinned Rapid7 commit; never runs source code."""
import argparse
import concurrent.futures
import json
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from metasploit_mcp.catalog import scan_framework


def fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "metasploit-mcp-catalog"}), timeout=30) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="master")
    args = parser.parse_args()
    api = "https://api.github.com/repos/rapid7/metasploit-framework"
    commit = json.loads(fetch(f"{api}/commits/{args.ref}"))["sha"]
    entries = json.loads(fetch(f"{api}/contents/lib/msf/core/rpc/v10?ref={commit}"))
    urls = {entry["name"]: entry["download_url"] for entry in entries
            if entry["name"] == "service.rb" or entry["name"].startswith("rpc_")}
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp) / "lib/msf/core/rpc/v10"
        base.mkdir(parents=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for name, content in zip(urls, pool.map(fetch, urls.values()), strict=True):
                (base / name).write_bytes(content)
        catalog = scan_framework(temp)
    catalog["origin"] = "rapid7/metasploit-framework"
    catalog["commit"] = commit
    catalog["source_url"] = f"https://github.com/rapid7/metasploit-framework/tree/{commit}/lib/msf/core/rpc/v10"
    target = Path(__file__).resolve().parents[1] / "src/metasploit_mcp/rpc_methods.json"
    target.write_text(json.dumps(catalog, indent=2) + "\n")
    print(json.dumps({"commit": commit, "methods": len(catalog["methods"])}))


if __name__ == "__main__":
    main()
