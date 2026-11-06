#!/usr/bin/env python3
"""
check_against_hashcat.py - Test HashScope against the hashcat YOU have installed.

hashcat adds new modes every release. This reads `hashcat --example-hashes`
(real example hash for every mode your version supports) and reports which
modes HashScope cannot identify yet, so you know what to add next.

Usage:
    python3 tools/check_against_hashcat.py                 # runs hashcat itself
    hashcat --example-hashes > ex.txt
    python3 tools/check_against_hashcat.py ex.txt          # or read a saved file
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hashscope import HashID


def main():
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        try:
            text = subprocess.run(["hashcat", "--example-hashes"], capture_output=True,
                                  text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.exit("Could not run hashcat (%s). Save its output to a file and pass the path." % exc)
    engine = HashID()
    ok, missing = 0, []
    for block in re.split(r"\n(?=Hash mode #)", text):
        m = re.match(r"Hash mode #(\d+)", block)
        name = re.search(r"Name\.+:\s*(.+)", block)
        h = re.search(r"Example\.Hash\.+:\s*(.+)", block)
        if not (m and h):
            continue
        mode = int(m.group(1))
        if mode in {x.hashcat for x in engine.identifyHash(h.group(1).strip())}:
            ok += 1
        else:
            missing.append((mode, name.group(1).strip() if name else "?", h.group(1).strip()[:60]))
    total = ok + len(missing)
    print("HashScope identifies %d of %d hashcat modes (%d%%)" % (ok, total, 100 * ok // max(total, 1)))
    print("\nNot identified (mode | name | example):")
    for mode, name, ex in missing:
        print("  %5d | %-45s | %s" % (mode, name[:45], ex))


if __name__ == "__main__":
    main()
