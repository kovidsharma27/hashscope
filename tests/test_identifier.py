"""
test_identifier.py - pytest suite for HashScope's identifier.

Loads pattern_examples.json (150 pattern groups, 277 named hash types,
each with an exrex-generated example string that is verified to match
its own regex at generation time) and checks that identifier.HashID
correctly recognizes every single one.

Run with:
    pytest tests/test_identifier.py -v
    pytest tests/test_identifier.py -v -k bcrypt      # run only bcrypt-related cases
    pytest tests/test_identifier.py --tb=short        # shorter failure output
"""

import json
import os
import sys
import pytest

# Make the hashscope package importable when running pytest from the
# project root (hashscope/tests/ -> hashscope/hashscope/identifier.py)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hashscope.identifier import HashID

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "pattern_examples.json")


def load_pattern_data():
    with open(DATA_PATH, "r") as f:
        return json.load(f)


# Build one test case per (pattern, name) pair, matching the 277 count,
# not just 150 - every named hash type gets its own pytest parametrize id.
def build_cases():
    data = load_pattern_data()
    cases = []
    for record in data:
        for name in record["names"]:
            cases.append(
                pytest.param(
                    record["example_hash"],
                    name,
                    record["category"],
                    id=f"{record['category']}-{name}".replace(" ", "_").replace("/", "_")[:80],
                )
            )
    return cases


CASES = build_cases()


@pytest.fixture(scope="module")
def engine():
    return HashID()


def test_total_case_count():
    """Sanity check: we should have exactly 290 named-hash-type test cases
    (163 pattern groups: 5 modern + 13 newer additions + 145 legacy)."""
    assert len(CASES) == 290, f"Expected 290 cases, got {len(CASES)}"


def test_no_duplicate_pattern_examples_missing():
    """Every pattern record must have produced a non-empty example."""
    data = load_pattern_data()
    for record in data:
        assert record["example_hash"], f"Missing example for pattern: {record['regex']}"


@pytest.mark.parametrize("example_hash,expected_name,category", CASES)
def test_hash_identified_correctly(engine, example_hash, expected_name, category):
    """
    For each generated example, the identifier must list the expected
    name among its matches. (Many patterns are intentionally ambiguous
    - e.g. a 32-char hex string matches MD5, NTLM, MD4, etc. at once -
    so we assert the expected name is PRESENT in the results, not that
    it's the ONLY result.)
    """
    found_names = [mode.name for mode in engine.identifyHash(example_hash)]
    assert expected_name in found_names, (
        f"'{expected_name}' ({category}) not found for example "
        f"'{example_hash}'. Got: {found_names}"
    )


@pytest.mark.parametrize(
    "bcrypt_hash",
    [
        "$2a$12$8r3gHkz3.ZEjOrwhKYX5QeVEhsVTJdjCjHw2GU2WjtI5SjeIUotyW",
        "$2b$12$8r3gHkz3.ZEjOrwhKYX5QeVEhsVTJdjCjHw2GU2WjtI5SjeIUotyW",
        "$2y$12$8r3gHkz3.ZEjOrwhKYX5QeVEhsVTJdjCjHw2GU2WjtI5SjeIUotyW",
    ],
)
def test_bcrypt_regression_all_variants(engine, bcrypt_hash):
    """
    Regression test for the original bug: hashid's upstream regex used
    [axy], silently excluding $2b$ (the most common modern bcrypt
    variant) from ever being recognized. This test locks in that all
    three real-world variants (2a, 2b, 2y) are now matched.
    """
    found_names = [mode.name for mode in engine.identifyHash(bcrypt_hash)]
    assert "bcrypt" in found_names, f"bcrypt variant {bcrypt_hash[:4]} not recognized: {found_names}"


def test_argon2id_real_example(engine):
    """Known-good real Argon2id hash (not exrex-generated) must be recognized."""
    real_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    found_names = [mode.name for mode in engine.identifyHash(real_hash)]
    assert "Argon2id (current recommended standard)" in found_names


def test_sha512crypt_real_vector(engine):
    """Published SHA-512 crypt test vector must be recognized."""
    real_hash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    found_names = [mode.name for mode in engine.identifyHash(real_hash)]
    assert "SHA-512 Crypt" in found_names


def test_unknown_input_returns_nothing(engine):
    """A string matching no known pattern should yield zero matches."""
    found = list(engine.identifyHash("this is definitely not a hash!!"))
    assert found == []
