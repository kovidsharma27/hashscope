#!/usr/bin/env python3
"""
check_against_hashcat.py - Test HashScope against the hashcat YOU have installed.

hashcat adds new modes every release. This reads the REAL example hash of every
mode in your hashcat (full length, via --machine-readable) and reports which
modes HashScope cannot identify yet, so you know what to add next.

Usage:
    python3 tools/check_against_hashcat.py              # runs hashcat itself
    python3 tools/check_against_hashcat.py ex.json      # or a saved file:
        hashcat --example-hashes --machine-readable > ex.json
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import _hashcat_io  # noqa: E402
from hashscope import HashID  # noqa: E402


def main():
    try:
        examples, truncated = _hashcat_io.load(sys.argv[1] if len(sys.argv) > 1 else None)
    except (OSError, ValueError, Exception) as exc:  # noqa: BLE001
        sys.exit("Could not read hashcat examples (%s).\nTry: hashcat --example-hashes --machine-readable > ex.json" % exc)
    engine = HashID()
    ok, missing = 0, []
    for ex in examples:
        if ex["mode"] in {x.hashcat for x in engine.identifyHash(ex["hash"])}:
            ok += 1
        else:
            missing.append(ex)
    total = ok + len(missing)
    print("HashScope identifies %d of %d hashcat modes (%d%%)" % (ok, total, 100 * ok // max(total, 1)))
    if truncated:
        print("NOTE: %d examples were truncated in the text output and skipped. "
              "Use --machine-readable for a full check." % truncated)
    print("\nNot identified (mode | name | example):")
    for ex in missing:
        print("  %5d | %-45s | %s" % (ex["mode"], ex["name"][:45], ex["hash"][:70]))


if __name__ == "__main__":
    main()
