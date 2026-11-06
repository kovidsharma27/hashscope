#!/usr/bin/env python3
"""
check_john_formats.py - Verify every John the Ripper format name used in
HashScope really exists in YOUR john (jumbo) install, and list formats that
HashScope never mentions.

Usage:
    python3 tools/check_john_formats.py                   # runs `john --list=formats`
    john --list=formats > formats.txt
    python3 tools/check_john_formats.py formats.txt
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hashscope import all_prototypes


def main():
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        try:
            text = subprocess.run(["john", "--list=formats"], capture_output=True,
                                  text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.exit("Could not run john (%s). Save `john --list=formats` to a file and pass the path." % exc)
    known = {f.strip().lower() for f in text.replace("\n", ",").split(",") if f.strip()}
    used = {m.john for p in all_prototypes for m in p.modes if m.john}
    bad = sorted(j for j in used if j.lower() not in known)
    print("%d John format names used, %d not found in your john:" % (len(used), len(bad)))
    for j in bad:
        print("   ", j)
    print("\n%d of your john's formats are never referenced by HashScope." % len(known - {u.lower() for u in used}))


if __name__ == "__main__":
    main()
