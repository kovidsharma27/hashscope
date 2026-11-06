#!/usr/bin/env python3
"""
generate_hashcat_patterns.py - Build hashscope/data/auto_patterns.json.

For every hashcat mode whose REAL example hash is not already recognised by
HashScope's hand-written patterns, derive a regex from that example:

  * the leading literal marker ($krb5tgs$, WPA*, {SSHA}, pbkdf2_sha256$ ...)
    is kept exactly -> this is what makes the pattern specific
  * delimiters ($ : * # , ; ( ) ...) are kept exactly (field layout)
  * numeric fields become \\d+, long hex fields stay hex, everything else
    becomes "any non-delimiter characters"
  * the LAST field keeps its exact length when it is a normal digest size

Examples with no literal marker (bare hex, hex:salt ...) are NOT turned into
patterns: they would match hundreds of unrelated hashes. Those stay with the
hand-written length-based patterns.

Usage (after tools/sync_hashcat_examples.py):
    python3 tools/generate_hashcat_patterns.py
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from hashscope.identifier import base_prototypes  # noqa: E402

EXAMPLES = os.path.join(ROOT, "tests", "hashcat_examples.json")
OUT = os.path.join(ROOT, "hashscope", "data", "auto_patterns.json")

DELIM_CHARS = "$:*#,;(){}|@~&% \t<>\"'\\[]!^?"
DELIM_CLASS = "[" + re.escape(DELIM_CHARS) + "]"
NOT_DELIM = "[^" + re.escape(DELIM_CHARS) + "]"
# Readable placeholders; hashscope/identifier.py expands them when loading:
#   <W+> = one or more non-delimiter characters, <W*> = zero or more
WIDE = "<W+>"
WIDE_OPT = "<W*>"

PREFIX_RE = re.compile(
    r"^(\$[A-Za-z0-9_\-]+\$|\{[A-Za-z0-9_\-]+\}|[A-Za-z][A-Za-z0-9_\-]{2,}(?=[$:*#=]))"
)
HEX_DIGEST_LENS = {16, 32, 40, 48, 56, 64, 96, 128}
B64_DIGEST_LENS = {22, 27, 31, 43, 44, 53, 64, 86, 88}


def token_regex(tok, is_last):
    if tok.isdigit():
        return r"\d+"
    if re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) >= 16:
        if is_last and len(tok) in HEX_DIGEST_LENS:
            return "[0-9a-fA-F]{%d}" % len(tok)
        return "[0-9a-fA-F]+"
    kv = re.fullmatch(r"([A-Za-z_]+)=(.+)", tok)
    if kv:  # key=value, e.g. m=65536  rounds=5000
        return re.escape(kv.group(1)) + "=" + token_regex(kv.group(2), False)
    if is_last and len(tok) in B64_DIGEST_LENS and re.fullmatch(r"[A-Za-z0-9./+=_-]+", tok):
        return "[A-Za-z0-9./+=_-]{%d}" % len(tok)
    return WIDE


def generalize(h):
    """Return a regex string for example hash h, or None if it has no marker."""
    m = PREFIX_RE.match(h)
    if not m:
        return None
    prefix = m.group(1)
    if prefix[0] not in "${" and re.fullmatch(r"[0-9a-fA-F]+", prefix):
        return None  # bare hex-looking word (e.g. "abc:") is data, not a marker
    rest = h[len(prefix):]
    if prefix[0] != "$" and prefix[0] != "{" and rest.startswith("::"):
        return None  # looks like user::domain (NetNTLM style) - username is not a marker
    parts = re.findall(DELIM_CLASS + "|" + NOT_DELIM + "+", rest)
    last_tok = max((i for i, p in enumerate(parts) if not re.fullmatch(DELIM_CLASS, p)), default=None)
    out = [re.escape(prefix)]
    first_tok_done = False
    prev_delim = False
    for i, p in enumerate(parts):
        if re.fullmatch(DELIM_CLASS, p):
            if prev_delim:
                out.append(WIDE_OPT)
            out.append(re.escape(p))
            prev_delim = True
            continue
        prev_delim = False
        if not first_tok_done and p.isdigit() and len(p) <= 3:
            out.append(re.escape(p))  # version / etype / flag right after the marker
        else:
            out.append(token_regex(p, i == last_tok))
        first_tok_done = True
    return "^" + "".join(out) + "$"


def expand(rx):
    """Expand placeholders so the regex can be verified with plain re."""
    return rx.replace("<W+>", NOT_DELIM + "+").replace("<W*>", NOT_DELIM + "*")


def main():
    examples = json.load(open(EXAMPLES, encoding="utf-8"))
    groups = {}
    skipped_nomarker = []
    for ex in examples:
        h = ex["hash"]
        covered = {m.hashcat for p in base_prototypes if p.regex.match(h) for m in p.modes}
        if ex["mode"] in covered:
            continue
        rx = generalize(h)
        if rx is None:
            skipped_nomarker.append(ex)
            continue
        try:
            ok = re.fullmatch(expand(rx), h) is not None
        except re.error:
            ok = False
        if not ok:
            skipped_nomarker.append(ex)
            continue
        g = groups.setdefault(rx, {"regex": rx, "example": h, "modes": []})
        g["modes"].append({"name": ex["name"], "hashcat": ex["mode"], "john": None})

    # ---- families: bare hex / hex:salt formats have no marker, so group them by SHAPE ----
    # e.g. "40 hex chars + 1 ':' field" is shared by dozens of sha1($pass.$salt)-style modes.
    # These are CANDIDATES only, so they are flagged extended (shown with `hashscope -e`).
    families = {}
    for ex in skipped_nomarker:
        m = re.fullmatch(r"([0-9a-fA-F]{8,8192})((?::[^\s:]+)*)", ex["hash"])
        if not m:
            continue
        n, k = len(m.group(1)), m.group(2).count(":")
        if n < 16 and k == 0:
            continue  # too short to say anything useful
        rx = "^[0-9a-fA-F]{%d}$" % n if k == 0 else "^[0-9a-fA-F]{%d}(?::[^\\s:]+){%d}$" % (n, k)
        fam = families.setdefault(rx, {"regex": rx, "extended": True, "example": ex["hash"], "modes": []})
        fam["modes"].append({"name": ex["name"], "hashcat": ex["mode"], "john": None})
    data = sorted(groups.values(), key=lambda g: g["modes"][0]["hashcat"])
    data += sorted(families.values(), key=lambda g: g["modes"][0]["hashcat"])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    n_modes = sum(len(g["modes"]) for g in data)  # includes family modes
    print(f"Wrote {len(data)} auto patterns covering {n_modes} hashcat modes -> {os.path.normpath(OUT)}")
    print(f"{len(families)} shape families (extended candidates) cover "
          f"{sum(len(f['modes']) for f in families.values())} markerless modes")
    json.dump(skipped_nomarker, open("/tmp/skipped.json", "w"), indent=1)


if __name__ == "__main__":
    main()
