#!/usr/bin/env python3
"""
update_known_gaps.py - Rewrite tests/known_gaps.json from the CURRENT examples.

Run this after tools/sync_hashcat_examples.py + tools/generate_hashcat_patterns.py,
so pytest only expects failures for modes HashScope really cannot identify yet:

    python3 tools/update_known_gaps.py
"""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from hashscope import HashID  # noqa: E402

engine = HashID()
examples = json.load(open(os.path.join(ROOT, "tests", "hashcat_examples.json"), encoding="utf-8"))
gaps = sorted(ex["mode"] for ex in examples
              if ex["mode"] not in {m.hashcat for m in engine.identifyHash(ex["hash"])})
with open(os.path.join(ROOT, "tests", "known_gaps.json"), "w") as f:
    json.dump(gaps, f)
print("%d of %d modes not identified yet: %s" % (len(gaps), len(examples), gaps))
