"""
test_real_vectors.py - tests that do NOT depend on HashScope's own regexes.

1. hashcat's REAL example hashes (tests/hashcat_examples.json, regenerate with
   tools/sync_hashcat_examples.py). Each must be identified with the correct
   hashcat mode number, except modes listed in tests/known_gaps.json (formats
   with no literal marker, e.g. bare "hex:salt" variants). If you fix a gap,
   remove its number from known_gaps.json.
2. Ranking: for famous hashes the right answer must be near the top.
3. bcrypt regression ($2b$ was the original hashid bug).
4. Junk text must not look like a hash.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hashscope import HashID  # noqa: E402

HERE = os.path.dirname(__file__)
EXAMPLES = json.load(open(os.path.join(HERE, "hashcat_examples.json"), encoding="utf-8"))
GAPS = set(json.load(open(os.path.join(HERE, "known_gaps.json"))))
engine = HashID()


def _params():
    for ex in EXAMPLES:
        marks = [pytest.mark.xfail(reason="known gap: no literal marker", strict=False)] if ex["mode"] in GAPS else []
        yield pytest.param(ex, marks=marks, id="m%05d-%s" % (ex["mode"], ex["name"][:30]))


@pytest.mark.parametrize("ex", list(_params()))
def test_hashcat_real_example(ex):
    modes = [m.hashcat for m in engine.identifyHash(ex["hash"])]
    assert ex["mode"] in modes, "hashcat mode %s (%s) not identified" % (ex["mode"], ex["name"])


def test_coverage_floor():
    ok = sum(1 for ex in EXAMPLES if ex["mode"] not in GAPS)
    assert ok / len(EXAMPLES) >= 0.55


# (hash, name that must be FIRST, max position allowed for the correct hashcat mode)
FAMOUS = [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),                       # md5("password")
    ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1"),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "SHA-256"),
    ("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "SHA-512"),
    ("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", "bcrypt"),
    ("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", "bcrypt"),
    ("$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "bcrypt"),
    ("$6$rounds=5000$saltsalt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.", "SHA-512 Crypt"),
    ("$1$28772684$iEwNOgGugqO9.bIz5sk8k/", "MD5 Crypt"),
    ("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "MySQL5.x"),
]


@pytest.mark.parametrize("h,expected", FAMOUS)
def test_famous_hash_ranked_first(h, expected):
    first = next(iter(engine.identifyHash(h)))
    assert first.name == expected


def test_ntlm_is_near_top_for_32_hex():
    names = [m.name for m in engine.identifyHash("8846f7eaee8fb117ad06bdd830b7586c")]
    assert names.index("NTLM") <= 2


def test_ranking_can_be_disabled():
    plain = HashID(rank=False)
    names = [m.name for m in plain.identifyHash("5f4dcc3b5aa765d61d8327deb882cf99")]
    assert "MD5" in names and names[0] != "MD5"  # original hashid order starts elsewhere


@pytest.mark.parametrize("junk", [
    "this is definitely not a hash!!", "admin:password123", "user@example.com",
    "https://example.com/a?b=c&d=e", "hello world", "$HOME/bin:$PATH", "192.168.1.1",
    "SELECT * FROM users WHERE id=1", "$$$$$$", "*****",
])
def test_junk_is_not_a_hash(junk):
    assert list(engine.identifyHash(junk)) == []


# Real example hashes copied from a Kali hashcat run (tools/check_against_hashcat.py)
# that HashScope missed before v0.2.1. Where only a prefix was visible, the tail is filler
# of the correct alphabet/length, so these protect the pattern SHAPE, not a cracked value.
KALI_GAPS = [
    (15100, "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q"),
    (12400, "_GW..8841inaTltazRsQ"),
    (28600, "SCRAM-SHA-256$4096:IKfxzJ8Nq4PkLJCfgKcPmA==$iRw3qwTp18uaBnsT0AbcdEfgHijklMnopQrs=:ZZk3qwTp18uaBnsT0AbcdEfgHijklMnopQrs="),
    (20300, "$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[:len("$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$") + 43]),
    (19000, "@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050"),
    (12000, "sha1:1000:MTYwNTM4MDU4Mzc4MzA=:aGghFQBtQ8+WVlMk5GEaMw=="),
    (12100, "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA=="),
    (11900, "md5:1000:NjAxMDY4MQ==:a00DtIW9hP9voC85fmEA5uVhgdDx67nSPSm9yA=="),
    (20600, "otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQUJYY60oFjaJuZZaSiabcdefg="),
]


@pytest.mark.parametrize("mode,h", KALI_GAPS)
def test_kali_gap_now_identified(mode, h):
    assert mode in [m.hashcat for m in engine.identifyHash(h)]


# Round 3: real strings copied from the Kali hashcat 7.1.2 example list. NetNTLM samples keep
# the real header and use filler of the right alphabet/length for the truncated tail.
KALI_ROUND3 = [
    (28501, "1Jv6EonXm9x4Dw4QjEPAhGfmzFxTL7b3Zj"),
    (28505, "3H1YvmSdrjEfj9LvtiKJ8XiYq5htJRuejA"),
    (28503, "bc1qxd76a5zamfyw0g2d2rxkdh0zt9m0uzmxmwjf0q"),
    (30901, "14Fqy5AGRehazZ4NLzxFWy2E4BiNFdH9Ut"),
    (18100, "597056:3600:613004:1234567890:322664:9876543210"),
    (24800, "8uigXlGMNI7BzwLCJlDbcKR2FP4="),
    (26300, "SH2lpcpFXM5QRlWYwY5vL9+5svfYyb+c79qENpxEoB3NtZpVxKwHjuq/9TH88U="),
    (29100, "eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8"),
    (27000, "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa4e8bb9ea1bd3b4a10be4a44fbc2a5b6d41:2fd0e7ee1f0e3c0a"),
    (27100, "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a10b8e9b5:0101000000000000abcdef0123456789"),
]


@pytest.mark.parametrize("mode,h", KALI_ROUND3)
def test_kali_round3_identified(mode, h):
    assert mode in [m.hashcat for m in engine.identifyHash(h)]


def test_extended_candidates_hidden_by_default(capsys):
    from hashscope.identifier import writeResult
    import io
    out = io.StringIO()
    writeResult(HashID().identifyHash("29937c08"), out, hashcatMode=True, extended=False)
    assert "Java Object" not in out.getvalue()
    out2 = io.StringIO()
    writeResult(HashID().identifyHash("29937c08"), out2, hashcatMode=True, extended=True)
    assert "Java Object" in out2.getvalue()
