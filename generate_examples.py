#!/usr/bin/env python3
"""
generate_examples.py - Regenerates pattern_examples.json from identifier.py.

Uses exrex to generate a random string matching each pattern's regex,
then verifies the generated string actually matches that same regex
(exrex can occasionally misparse complex patterns, so this check is
not optional). Run this whenever identifier.py's pattern list changes.

Usage:
    python3 generate_examples.py
"""
import json
import exrex
from hashscope.identifier import all_prototypes, modern_prototypes, newer_prototypes


def main():
    data = []
    for idx, p in enumerate(all_prototypes):
        pattern_src = p.regex.pattern
        example = exrex.getone(pattern_src)
        assert p.regex.match(example), f"Generated example failed self-check: {pattern_src}"
        if p in modern_prototypes:
            category = "modern"
        elif p in newer_prototypes:
            category = "newer"
        else:
            category = "legacy"
        data.append({
            "pattern_index": idx,
            "category": category,
            "regex": pattern_src,
            "example_hash": example,
            "names": [m.name for m in p.modes],
            "hashcat_modes": [m.hashcat for m in p.modes],
            "john_formats": [m.john for m in p.modes],
        })

    with open("pattern_examples.json", "w") as f:
        json.dump(data, f, indent=2)

    total_names = sum(len(d["names"]) for d in data)
    print(f"Generated {len(data)} pattern records covering {total_names} named hash types.")


if __name__ == "__main__":
    main()
