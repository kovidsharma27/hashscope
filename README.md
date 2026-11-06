# HashScope

A hash identifier in the style of `hashid` / `hash-identifier` / Name-That-Hash:
give it a hash, it tells you what it probably is, **most likely first**, with the
matching **hashcat mode** and **John the Ripper format**.

```
$ hashscope -m -j -t 3 5f4dcc3b5aa765d61d8327deb882cf99
[+] MD5 [Hashcat Mode: 0][JtR Format: raw-md5]
[+] NTLM [Hashcat Mode: 1000][JtR Format: nt]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
```

## Install and use

```bash
python3 -m venv env && source env/bin/activate
pip install -e .                  # gives you the `hashscope` command
hashscope -m -j '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
hashscope hashes.txt              # one hash per line
echo 'AAAA...' | hashscope -      # from stdin
python3 -m hashscope <hash>       # works without installing
```

**Always put hashes in single quotes** - `$` has a special meaning in the shell
(`$2b$12$...` would otherwise be mangled before HashScope sees it).

| Option | Meaning |
|---|---|
| `-m` | show hashcat mode number |
| `-j` | show John the Ripper format |
| `-t N` | show only the N most likely results |
| `-e` | include "extended" (salted-variant) candidates |
| `--no-rank` | original hashid order (no popularity sorting) |
| `-o FILE` | write output to a file |

Use as a library:

```python
from hashscope import HashID
for info in HashID().identifyHash("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"):
    print(info.name, info.hashcat, info.john)
```

## How it works

1. **Pattern databases** (`hashscope/identifier.py`)
   * 100+ original hashid patterns (bcrypt `$2b$` bug fixed)
   * modern additions: Argon2, yescrypt, Kerberos, JWT, Cisco 8/9, SHA-3, BLAKE2 ...
   * `curated_prototypes`: hand-written fixes found by testing against real hashes
   * **229 auto-generated patterns** (`hashscope/data/auto_patterns.json`) built from the
     real example hash of every hashcat mode - see `tools/generate_hashcat_patterns.py`
2. **Popularity ranking**: every match gets a 0-100 score (`POPULARITY_BY_NAME`,
   `POPULARITY_BY_MODE`). A length-only match (32 hex chars) is weak; a distinctive prefix
   (`$krb5tgs$`, `WPA*`) is strong. Results are sorted by score. Edit the dictionaries to tune.

## Measured accuracy (be skeptical, read the caveats)

`python3 tools/compare_with_nth.py` scores against hashcat's own example hash for every mode
(759 modes). "any" = correct mode appears somewhere in the output.

| | any | top 5 | top 1 |
|---|---|---|---|
| HashScope v0.1 (before) | 17% | 11% | 9% |
| **HashScope v0.2** | **60%** | **49%** | **36%** |
| Name-That-Hash | 22% | 16% | 12% |

**Caveat:** the auto-patterns were derived from these same examples, so 60% is partly
circular. The honest independent check is `tools/heldout_john_check.py`, which uses John the
Ripper's *own* test hashes (different source): HashScope 113/289 vs Name-That-Hash 101/289.
Bare hashes with no marker (32 hex etc.) are inherently ambiguous - nobody can do better than
a ranked list. The benchmark is also hashcat-centric (many exotic modes), so it is not a
statement about everyday CTF hashes, where all tools do well.

## Known limitations

* Formats with no literal marker (`hex:salt` variants, raw binary) are only length-matched.
* Auto-patterns keep the first numeric field after the marker literally (e.g. `$krb5tgs$23$`),
  which is right for Kerberos but can be too strict for other formats.
* `password` (any 8-char alphanumeric string) matches the old hashid "Dahua" pattern.
* John format names for auto-generated patterns are blank; popularity scores are judgement calls.

## Testing

```bash
pytest                                  # ~1080 tests: 777 pass, 303 expected-fail (known gaps)
python3 tools/compare_with_nth.py       # accuracy table above
```

`tests/test_real_vectors.py` uses real hashcat hashes, ranking checks and junk-string checks.
`tests/test_identifier.py` (the original suite) only proves each regex matches a string
generated from itself, so treat it as a regression guard, not proof of accuracy.

## Maintenance (keep it modern)

| When | Run |
|---|---|
| new hashcat release | `git clone --depth 1 https://github.com/hashcat/hashcat /tmp/hashcat`, then `python3 tools/sync_hashcat_examples.py /tmp/hashcat` and `python3 tools/generate_hashcat_patterns.py` |
| see what YOUR hashcat supports that HashScope doesn't | `python3 tools/check_against_hashcat.py` |
| validate John names against YOUR john | `python3 tools/check_john_formats.py` |
| after fixing a gap | remove its mode from `tests/known_gaps.json` |

License: GPL-3.0-or-later (derived from hashid). See `NOTICE.md`.
