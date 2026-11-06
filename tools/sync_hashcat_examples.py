#!/usr/bin/env python3
"""
sync_hashcat_examples.py - Build tests/hashcat_examples.json from hashcat's
real source tree (hashcat is MIT licensed).

Every src/modules/module_NNNNN.c contains a genuine example hash (ST_HASH)
and the official mode name (HASH_NAME). These are REAL hashes, so they test
HashScope far better than regex-generated strings.

Usage (best - uses the hashcat installed on YOUR machine, e.g. Kali):
    python3 tools/sync_hashcat_examples.py --installed
    python3 tools/sync_hashcat_examples.py ex.json      # from: hashcat --example-hashes --machine-readable > ex.json

Usage (from source, no hashcat install needed):
    git clone --depth 1 https://github.com/hashcat/hashcat.git /tmp/hashcat
    python3 tools/sync_hashcat_examples.py /tmp/hashcat
"""
import glob
import json
import os
import re
import sys


def c_unescape(s):
    return s.replace('\\\\', '\x00').replace('\\"', '"').replace('\\n', '\n').replace('\x00', '\\')


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "/tmp/hashcat"
    if arg == "--installed" or (os.path.isfile(arg) and arg.endswith(".json")):
        sys.path.insert(0, os.path.dirname(__file__))
        import _hashcat_io
        new, _ = _hashcat_io.load(None if arg == "--installed" else arg)
        dest = os.path.join(os.path.dirname(__file__), "..", "tests", "hashcat_examples.json")
        merged = {}
        if os.path.exists(dest):  # keep what we already have; your hashcat wins per mode
            merged = {e["mode"]: e for e in json.load(open(dest, encoding="utf-8"))}
        added = len([e for e in new if e["mode"] not in merged])
        merged.update({e["mode"]: e for e in new})
        out = [merged[k] for k in sorted(merged)]
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1, ensure_ascii=False)
        print(f"Read {len(new)} examples from your hashcat ({added} new modes). "
              f"{len(out)} total -> {os.path.normpath(dest)}")
        return
    root = arg
    out = []
    for path in sorted(glob.glob(os.path.join(root, "src", "modules", "module_*.c"))):
        mode = int(re.search(r"module_(\d+)\.c", path).group(1))
        src = open(path, encoding="utf-8", errors="replace").read()
        h = re.search(r'ST_HASH\s*=\s*"((?:[^"\\]|\\.)*)"', src)
        n = re.search(r'HASH_NAME\s*=\s*"((?:[^"\\]|\\.)*)"', src)
        if not h:
            continue
        out.append({"mode": mode,
                    "name": c_unescape(n.group(1)) if n else "",
                    "hash": c_unescape(h.group(1))})
    dest = os.path.join(os.path.dirname(__file__), "..", "tests", "hashcat_examples.json")
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print(f"Wrote {len(out)} real hashcat example hashes -> {os.path.normpath(dest)}")


if __name__ == "__main__":
    main()
