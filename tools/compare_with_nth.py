#!/usr/bin/env python3
"""
compare_with_nth.py - Score HashScope (and Name-That-Hash, if installed)
against hashcat's real example hashes.

Metrics (per example, correct = the true hashcat mode number):
  any   - correct mode appears anywhere in the results
  top1  - correct mode is the first result that has a hashcat mode
  top5  - correct mode is within the first 5 results

Usage:
    pip install name-that-hash          # optional, for the comparison column
    python3 tools/compare_with_nth.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hashscope import HashID

DATA = os.path.join(os.path.dirname(__file__), "..", "tests", "hashcat_examples.json")


def score(name, fn, examples):
    any_ = top1 = top5 = 0
    for ex in examples:
        modes = [m for m in fn(ex["hash"]) if m is not None]
        if ex["mode"] in modes:
            any_ += 1
        if modes[:1] == [ex["mode"]]:
            top1 += 1
        if ex["mode"] in modes[:5]:
            top5 += 1
    n = len(examples)
    print(f"{name:14} any {any_:4}/{n} ({100*any_//n:3}%)   top5 {top5:4} ({100*top5//n:3}%)   top1 {top1:4} ({100*top1//n:3}%)")


def main():
    examples = json.load(open(DATA, encoding="utf-8"))
    engine = HashID()
    score("HashScope", lambda h: [m.hashcat for m in engine.identifyHash(h) if not m.extended], examples)  # default output only (fair vs NTH)
    try:
        from name_that_hash import runner
    except ImportError:
        print("(name-that-hash not installed; skipping comparison)")
        return

    def nth(h):
        res = json.loads(runner.api_return_hashes_as_json([h]))
        return [m.get("hashcat") for m in res.get(h, [])]
    score("Name-That-Hash", nth, examples)


if __name__ == "__main__":
    main()
