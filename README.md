# HashScope

A hash identifier in the style of `hashid` / `hash-identifier` / Name-That-Hash.
Give it a hash and it tells you what it probably is, **most likely first**, with the
matching **hashcat mode** and **John the Ripper format**.

```
$ hashscope -m -j -t 3 '5f4dcc3b5aa765d61d8327deb882cf99'
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD5 [Hashcat Mode: 0][JtR Format: raw-md5]
[+] NTLM [Hashcat Mode: 1000][JtR Format: nt]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100][JtR Format: mscash2]
```

## Why this exists

I built it while learning cybersecurity. `hashid` fails on modern bcrypt (`$2b$`) and has no
Argon2, yescrypt or Kerberos support, so HashScope:

* fixes the `$2b$` bcrypt bug,
* adds modern formats (Argon2, yescrypt, Kerberos, JWT, WPA, Cisco 8/9, SHA-3, BLAKE2 ...),
* **ranks** results by how common each format is, so MD5 comes before MD2,
* is tested against hashcat's own real example hashes, and its John names are checked against
  a real John install.

## Install

**Kali / Linux (recommended):**

```bash
sudo apt install -y pipx git
pipx ensurepath          # then open a new terminal
pipx install git+https://github.com/kovidsharma27/hashscope.git
hashscope -m -j -t 3 '5f4dcc3b5aa765d61d8327deb882cf99'
```

Update later with `pipx upgrade hashscope`.

**For development (editable, updates with `git pull`):**

```bash
git clone https://github.com/kovidsharma27/hashscope.git ~/hashscope
cd ~/hashscope
pipx install -e .
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/kovidsharma27/hashscope.git
cd hashscope
python -m venv venv
venv\Scripts\Activate.ps1
pip install -e .
```

No runtime dependencies (standard library only). You can also run it without installing:
`python3 -m hashscope '<hash>'`.

## Usage

```bash
hashscope '<hash>'                # names only
hashscope -m '<hash>'             # + hashcat mode (ready for hashcat -m)
hashscope -m -j -t 3 '<hash>'     # + John format, top 3 results only
hashscope hashes.txt              # a file, one hash per line
echo '<hash>' | hashscope -       # from stdin
hashscope -e -m '<hash>'          # include "extended" candidates (salted variants)
```

**Always put the hash in single quotes.** `$` has a special meaning in the shell, so an
unquoted `$2b$12$...` is mangled before HashScope ever sees it. (In old Windows `cmd`, use
double quotes.)

| Option | Meaning |
|---|---|
| `-m`, `--mode` | show hashcat mode number |
| `-j`, `--john` | show John the Ripper format |
| `-t N`, `--top N` | show only the N most likely results |
| `-e`, `--extended` | include extended candidates (bare `hash:salt` shapes) |
| `--no-rank` | original hashid order (no popularity sorting) |
| `-o FILE` | write output to a file |

As a library:

```python
from hashscope import HashID

for info in HashID().identifyHash("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"):
    print(info.name, info.hashcat, info.john)
```

## How it works

1. **Pattern databases** (`hashscope/identifier.py`)
   * the original hashid patterns, with the `$2b$` bug fixed
   * modern additions and hand-written fixes found by testing against real hashes
   * about 260 auto-generated patterns (`hashscope/data/auto_patterns.json`) built from the
     real example hash of every hashcat mode (`tools/generate_hashcat_patterns.py`)
2. **Shape families**: bare `hex` and `hex:salt` formats have no marker, so they are grouped by
   shape (for example "40 hex characters + one `:` field"). These are *candidates* only and
   are hidden unless you use `-e`.
3. **Popularity ranking**: every match gets a 0-100 score (`POPULARITY_BY_NAME`,
   `POPULARITY_BY_MODE`). A length-only match (32 hex characters) is weak, while a distinctive
   prefix (`$krb5tgs$`, `WPA*`) is strong. Edit the dictionaries to tune the order.

## Measured accuracy (read the caveats)

**Against hashcat 7.1.2's own example hashes** (578 modes, measured on Kali with
`python3 tools/check_against_hashcat.py`):

| Counting | Modes identified |
|---|---|
| Default output (what you normally see) | **66%** |
| Including `-e` candidates | 99% |

The 99% is loose. Listing many candidates makes it easy to include the right one, so treat the
**66%** as the honest figure.

**Compared with Name-That-Hash** on 757 example hashes from hashcat's source
(`python3 tools/compare_with_nth.py`, default output only):

| | any | top 5 | top 1 |
|---|---|---|---|
| HashScope v0.1 (original patterns) | 17% | 11% | 9% |
| **HashScope v0.2.x** | **59%** | **53%** | **36%** |
| Name-That-Hash | 22% | 16% | 12% |

**Caveats, please read:**

* The auto-generated patterns were derived from these same example hashes, so the numbers
  above are partly circular. An independent check using John the Ripper's *own* test hashes
  (`tools/heldout_john_check.py`, measured at v0.2) gave HashScope 113/289 and Name-That-Hash
  101/289, which is close, not a landslide.
* The benchmark is hashcat-centric (many exotic formats). It says little about everyday CTF
  hashes, where all of these tools do well.
* Bare hashes with no marker (32 hex characters and similar) are inherently ambiguous. Nobody
  can do better than a ranked list. For those, "first answer correct" is a guess, not a fact.
* Name-That-Hash is a mature, maintained project. HashScope is a student project and this
  is not a claim that it replaces it.

**John format names:** all 97 names used were checked against a real John install
(`tools/check_john_formats.py`). Formats where John has no matching name (Cisco types 4/8/9,
LDAP `{SHA}`/`{SSHA}`, AIX smd5, bigcrypt) show no John name rather than a wrong one.

## Known limitations

* Formats with no literal marker (`hash:salt` variants, raw binary) can only be matched by
  shape, so they appear as candidates, not answers.
* Auto-generated patterns keep the first numeric field after the marker literally (for
  example `$krb5tgs$23$`). That is right for Kerberos but can be too strict for other formats.
* Any 8-character alphanumeric string (such as `password`) still matches the old hashid
  "Dahua" pattern.
* John format names for auto-generated patterns are blank.
* Popularity scores are judgement calls, not measured frequencies.

## Testing

```bash
python3 -m venv venv && source venv/bin/activate
pip install pytest
pytest tests
```

Currently 1149 tests pass, with 20 expected failures (modes nothing can identify yet, plus
newer hashcat modes). `tests/test_real_vectors.py` uses real hashcat hashes, ranking checks
and junk-string checks. `tests/test_identifier.py` (the original suite) only proves each regex
matches a string generated from itself, so it is a regression guard and not proof of accuracy.

## Maintenance (keep it modern)

Run these on a machine with hashcat installed (for example Kali):

```bash
hashcat --example-hashes --machine-readable > ex.json
sed -n '/^{/,$p' ex.json > ex_clean.json     # remove the banner line
python3 tools/sync_hashcat_examples.py ex_clean.json
python3 tools/generate_hashcat_patterns.py
python3 tools/update_known_gaps.py
pytest tests
```

| Tool | What it does |
|---|---|
| `tools/check_against_hashcat.py` | scores HashScope against YOUR hashcat and lists the misses |
| `tools/check_john_formats.py` | verifies every John name exists in YOUR john |
| `tools/sync_hashcat_examples.py` | merges hashcat's real examples into `tests/` |
| `tools/generate_hashcat_patterns.py` | rebuilds `hashscope/data/auto_patterns.json` |
| `tools/update_known_gaps.py` | refreshes the list of expected test failures |
| `tools/compare_with_nth.py` | HashScope vs Name-That-Hash (`pip install name-that-hash`) |
| `tools/heldout_john_check.py` | independent check using John's own test hashes |

## License and credits

GPL-3.0-or-later, because the pattern list started from **hashid** by c0re (GPL-3.0). Example
hashes and mode names come from the **hashcat** source tree (MIT). See `NOTICE.md`.