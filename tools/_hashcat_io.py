"""Shared helpers: read hashcat's example hashes from your INSTALLED hashcat.

`hashcat --example-hashes` (plain text) TRUNCATES long hashes ("abc...def [Truncated,
use --mach for full length]"), which makes formats look unrecognised when they are not.
`hashcat --example-hashes --machine-readable` prints full-length data, so we try that.

Different hashcat versions print different layouts, so this module accepts:
  * JSON (hashcat 7.x):   {"0": {"name": "MD5", "example_hash": "..."}, ...}
  * text blocks:          "Hash mode #0 / Name....: / Example.Hash....: "
  * old text blocks:      "MODE: 0 / TYPE: MD5 / HASH: ... / PASS: ..."
and, if none of them can be read, reports what the output actually looked like.
"""
import json
import re
import subprocess

# modes that are not real hash formats (STDOUT, plaintext) - nothing to identify
SKIP_MODES = {2000, 99999}


def run_hashcat(exe="hashcat"):
    out = subprocess.run([exe, "--example-hashes", "--machine-readable"],
                         capture_output=True, text=True)
    text = (out.stdout or "") + ("\n" + out.stderr if not out.stdout else "")
    if not text.strip():
        raise ValueError("hashcat printed nothing (exit code %s)" % out.returncode)
    return text


def _find_mode_dict(obj):
    """Find the dict whose keys are hashcat mode numbers, wherever it is nested."""
    if isinstance(obj, dict):
        if obj and all(str(k).isdigit() for k in obj):
            return obj
        for v in obj.values():
            found = _find_mode_dict(v)
            if found:
                return found
    if isinstance(obj, list):
        for v in obj:
            found = _find_mode_dict(v)
            if found:
                return found
    return None


def _example_hash(info):
    if not isinstance(info, dict):
        return None
    for key, val in info.items():
        k = str(key).lower()
        if "example" in k and "hash" in k and "format" not in k and isinstance(val, str):
            return val
    for key in ("hash", "st_hash"):
        if isinstance(info.get(key), str):
            return info[key]
    return None


def _from_json(text):
    dec = json.JSONDecoder()
    for m in re.finditer(r"^[ \t]*[\[{]", text, re.M):
        try:
            obj, _ = dec.raw_decode(text, m.end() - 1)
        except ValueError:
            continue
        modes = _find_mode_dict(obj)
        if not modes:
            continue
        out = []
        for key, info in modes.items():
            h = _example_hash(info)
            if not h or h == "N/A" or int(key) in SKIP_MODES:
                continue
            name = info.get("name") or info.get("hash_name") or "" if isinstance(info, dict) else ""
            out.append({"mode": int(key), "name": name, "hash": h})
        if out:
            return sorted(out, key=lambda x: x["mode"])
    return []


def _from_text_blocks(text):
    out, truncated = [], 0
    for block in re.split(r"\n(?=Hash mode #)", text):
        m = re.match(r"\s*Hash mode #(\d+)", block)
        name = re.search(r"Name\.+:\s*(.+)", block)
        h = re.search(r"Example\.Hash\.+:\s*(.+)", block)
        if not (m and h) or int(m.group(1)) in SKIP_MODES:
            continue
        if "[Truncated" in h.group(1):
            truncated += 1
            continue
        out.append({"mode": int(m.group(1)), "name": name.group(1).strip() if name else "",
                    "hash": h.group(1).strip()})
    return out, truncated


def _from_old_blocks(text):
    out = []
    for block in re.split(r"\n\s*\n", text):
        m = re.search(r"^MODE:\s*(\d+)", block, re.M)
        h = re.search(r"^HASH:\s*(.+)$", block, re.M)
        n = re.search(r"^TYPE:\s*(.+)$", block, re.M)
        if m and h and int(m.group(1)) not in SKIP_MODES:
            out.append({"mode": int(m.group(1)), "name": n.group(1).strip() if n else "",
                        "hash": h.group(1).strip()})
    return out


def parse(text):
    """-> (examples, number_truncated). Raises ValueError with a helpful message."""
    text = text.lstrip("\ufeff")
    ex = _from_json(text)
    if ex:
        return ex, 0
    ex, truncated = _from_text_blocks(text)
    if ex or truncated:
        return ex, truncated
    ex = _from_old_blocks(text)
    if ex:
        return ex, 0
    head = text.strip()[:400].replace("\n", "\\n") or "(empty)"
    raise ValueError("could not find any example hashes in the output. It began with: %s" % head)


def load(path_or_none=None, exe="hashcat"):
    """Load examples from a saved file, or by running hashcat. -> (examples, truncated_count)"""
    if path_or_none:
        text = open(path_or_none, encoding="utf-8-sig", errors="replace").read()
    else:
        text = run_hashcat(exe)
    return parse(text)
