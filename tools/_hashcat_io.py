"""Shared helpers: read hashcat's example hashes from your INSTALLED hashcat.

`hashcat --example-hashes` (plain text) TRUNCATES long hashes ("abc...def [Truncated,
use --mach for full length]"), which makes formats look unrecognised when they are not.
`hashcat --example-hashes --machine-readable` prints full-length JSON, so we use that.
"""
import json
import re
import subprocess

# modes that are not real hash formats (STDOUT, plaintext) - nothing to identify
SKIP_MODES = {2000, 99999}


def run_hashcat(exe="hashcat"):
    out = subprocess.run([exe, "--example-hashes", "--machine-readable"],
                         capture_output=True, text=True, check=True)
    return out.stdout


def _find_mode_dict(obj):
    """Find the dict whose keys are hashcat mode numbers, wherever it is nested."""
    if isinstance(obj, dict):
        if obj and all(str(k).isdigit() for k in obj):
            return obj
        for v in obj.values():
            found = _find_mode_dict(v)
            if found:
                return found
    return None


def parse_json(text):
    """-> list of {'mode', 'name', 'hash'} from --machine-readable output."""
    start = text.find("{")
    modes = _find_mode_dict(json.loads(text[start:]))
    if not modes:
        raise ValueError("no hash modes found in the JSON output")
    out = []
    for key, info in modes.items():
        h = info.get("example_hash")
        if not h or h == "N/A" or int(key) in SKIP_MODES:
            continue
        out.append({"mode": int(key), "name": info.get("name", ""), "hash": h})
    return sorted(out, key=lambda x: x["mode"])


def parse_text(text):
    """Fallback for plain --example-hashes output. Skips truncated examples.
    -> (examples, number_truncated)"""
    out, truncated = [], 0
    for block in re.split(r"\n(?=Hash mode #)", text):
        m = re.match(r"Hash mode #(\d+)", block)
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


def load(path_or_none=None, exe="hashcat"):
    """Load examples from a saved file, or by running hashcat. -> (examples, truncated_count)"""
    text = open(path_or_none, encoding="utf-8-sig", errors="replace").read() if path_or_none else run_hashcat(exe)
    stripped = text.lstrip("\ufeff \n\r\t")
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_json(stripped), 0
    return parse_text(text)
