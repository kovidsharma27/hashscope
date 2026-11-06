#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
hash_id_complete.py - Complete hash identifier.

Base: the FULL database from Kali's /usr/lib/python3/dist-packages/hashid.py
(every single Prototype entry, reproduced exactly as pasted from the real
source file), PLUS:

  1. The confirmed bcrypt bug fixed. Original regex:
         r'^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$'
     [axy] matches a, x, y but NOT b, so real-world $2b$ bcrypt hashes
     (the most common modern variant) were never recognized. All three
     occurrences of this pattern (plain bcrypt, bcrypt-sha256, Django
     bcrypt, Django bcrypt-sha256) are fixed to [abxy] below.

  2. Modern algorithms that don't exist in hashid's database at all
     (Argon2id/i/d, yescrypt, scrypt crypt-style $7$) added as a
     separate block checked FIRST, since they're current best-practice.

Usage:
    python3 hash_id_complete.py '$2b$12$8r3gHkz3.ZEjOrwhKYX5QeVEhsVTJdjCjHw2GU2WjtI5SjeIUotyW'
    python3 hash_id_complete.py --file hashes.txt
    python3 hash_id_complete.py --mode --john '<hash>'
    python3 hash_id_complete.py --extended '<hash>'   # include salted-password variant guesses
"""

import re
import os
import io
import sys
import json
import argparse
from collections import namedtuple

Prototype = namedtuple('Prototype', ['regex', 'modes'])
HashInfo = namedtuple('HashInfo', ['name', 'hashcat', 'john', 'extended'])

# ---------------------------------------------------------------------------
# MODERN ADDITIONS - not present in hashid's database below at all.
# Checked FIRST, highest priority, since these are current (2020s+)
# best-practice algorithms you're more likely to actually meet.
# ---------------------------------------------------------------------------

modern_prototypes = [
    # NOTE: base64 is case-sensitive, so these no longer use re.IGNORECASE
    # (a previous version did, which let an uppercase-mangled Argon2 string
    # match even though real Argon2 output never contains uppercase).
    Prototype(regex=re.compile(r'^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'), modes=[
        HashInfo(name='Argon2id (current recommended standard)', hashcat=34000, john='argon2', extended=False)]),
    Prototype(regex=re.compile(r'^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'), modes=[
        HashInfo(name='Argon2i', hashcat=34000, john='argon2', extended=False)]),
    Prototype(regex=re.compile(r'^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'), modes=[
        HashInfo(name='Argon2d', hashcat=34000, john='argon2', extended=False)]),
    Prototype(regex=re.compile(r'^\$y\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$'), modes=[
        HashInfo(name='yescrypt (modern Linux /etc/shadow default: Debian 11+/Ubuntu 22.04+)', hashcat=None, john='crypt', extended=False)]),
    Prototype(regex=re.compile(r'^\$7\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$'), modes=[
        HashInfo(name='scrypt (crypt-style)', hashcat=None, john=None, extended=False)]),
]

# ---------------------------------------------------------------------------
# NEWER ADDITIONS (built Nov 2026) - formats that are common in current
# cybersecurity / pentest work but existed in neither hashid's original
# database nor HashScope's first version. Mode numbers below were checked
# against public hashcat references at build time; confirm with
# `hashcat --example-hashes -m <mode>` before relying on them for real work,
# since hashcat occasionally renumbers or splits a mode across versions.
#
# A few of these (7z, RAR3/5, KeePass, WinZip, Bitcoin wallet, iTunes
# backup) use a deliberately loose ".+" body instead of validating exact
# field lengths. These formats have long, structured, multi-field bodies
# that vary by version, and a wrong strict pattern would silently reject
# real output from the real tool (john/hashcat's own *2john helpers).
# Since the leading literal ($7z$, $rar5$, etc.) is unique to that format
# and shared by nothing else here, a loose body costs nothing in false
# positives - it only trades a little precision for not missing real hits,
# which matches this project's "don't miss a higher-probability match"
# priority. Tighten any of these yourself if you need strict validation.
# ---------------------------------------------------------------------------

newer_prototypes = [
    # --- Kerberos: Kerberoasting / AS-REP Roasting (mainstream AD attacks) ---
    Prototype(regex=re.compile(r'^\$krb5tgs\$23\$.+\$[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 TGS-REP etype 23 (Kerberoasting, RC4)', hashcat=13100, john='krb5tgs', extended=False)]),
    Prototype(regex=re.compile(r'^\$krb5tgs\$17\$.+\$[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 TGS-REP etype 17 (Kerberoasting, AES-128)', hashcat=19600, john='krb5tgs', extended=False)]),
    Prototype(regex=re.compile(r'^\$krb5tgs\$18\$.+\$[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 TGS-REP etype 18 (Kerberoasting, AES-256)', hashcat=19700, john='krb5tgs', extended=False)]),
    Prototype(regex=re.compile(r'^\$krb5asrep\$23\$.+$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 AS-REP etype 23 (AS-REP Roasting, RC4)', hashcat=18200, john='krb5asrep', extended=False)]),
    Prototype(regex=re.compile(r'^\$krb5asrep\$(17|18)\$.+$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 AS-REP etype 17/18 (AES) - verify 32100 vs 32200', hashcat=None, john='krb5asrep', extended=False)]),

    # --- Web / API tokens ---
    Prototype(regex=re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'), modes=[
        HashInfo(name='JWT (JSON Web Token, HS256/384/512)', hashcat=16500, john=None, extended=False)]),

    # --- Archives (output of hashcat's / john's *2john helper scripts) ---
    Prototype(regex=re.compile(r'^\$7z\$.+$'), modes=[
        HashInfo(name='7-Zip', hashcat=11600, john='7z', extended=False)]),
    Prototype(regex=re.compile(r'^\$RAR3\$\*.+$'), modes=[
        HashInfo(name='RAR3-hp', hashcat=12500, john='rar3', extended=False)]),
    Prototype(regex=re.compile(r'^\$rar5\$.+$'), modes=[
        HashInfo(name='RAR5', hashcat=13000, john='rar5', extended=False)]),
    Prototype(regex=re.compile(r'^\$zip2\$.*\$/zip2\$$'), modes=[
        HashInfo(name='WinZip', hashcat=13600, john='zip', extended=False)]),

    # --- Password managers / vaults ---
    Prototype(regex=re.compile(r'^\$keepass\$\*.+$'), modes=[
        HashInfo(name='KeePass 1 (AES/Twofish) / KeePass 2 (AES)', hashcat=13400, john='keepass', extended=False)]),

    # --- Cryptocurrency wallets ---
    Prototype(regex=re.compile(r'^\$bitcoin\$.+$'), modes=[
        HashInfo(name='Bitcoin/Litecoin wallet.dat', hashcat=11300, john='bitcoin', extended=False)]),

    # --- Mobile backups ---
    Prototype(regex=re.compile(r'^\$itunes_backup\$.+$'), modes=[
        HashInfo(name='iTunes backup (mode 14700 if <10.0, 14800 if >=10.0 - check which)', hashcat=14700, john=None, extended=False)]),
]

# ---------------------------------------------------------------------------
# FULL hashid DATABASE - every Prototype from the pasted source file,
# in original order, bcrypt entries fixed ([axy] -> [abxy]), marked
# inline with "# FIXED" on the three lines that changed.
# ---------------------------------------------------------------------------

legacy_prototypes = [
    Prototype(regex=re.compile(r'^[a-f0-9]{4}$', re.IGNORECASE), modes=[
        HashInfo(name='CRC-16', hashcat=None, john=None, extended=False),
        HashInfo(name='CRC-16-CCITT', hashcat=None, john=None, extended=False),
        HashInfo(name='FCS-16', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE), modes=[
        HashInfo(name='Adler-32', hashcat=None, john=None, extended=False),
        HashInfo(name='CRC-32B', hashcat=None, john=None, extended=False),
        HashInfo(name='FCS-32', hashcat=None, john=None, extended=False),
        HashInfo(name='GHash-32-3', hashcat=None, john=None, extended=False),
        HashInfo(name='GHash-32-5', hashcat=None, john=None, extended=False),
        HashInfo(name='FNV-132', hashcat=None, john=None, extended=False),
        HashInfo(name='Fletcher-32', hashcat=None, john=None, extended=False),
        HashInfo(name='Joaat', hashcat=None, john=None, extended=False),
        HashInfo(name='ELF-32', hashcat=None, john=None, extended=False),
        HashInfo(name='XOR-32', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{6}$', re.IGNORECASE), modes=[
        HashInfo(name='CRC-24', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$', re.IGNORECASE), modes=[
        HashInfo(name='CRC-32', hashcat=None, john='crc32', extended=False)]),
    Prototype(regex=re.compile(r'^\+[a-z0-9\/.]{12}$', re.IGNORECASE), modes=[
        HashInfo(name='Eggdrop IRC Bot', hashcat=None, john='bfegg', extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/.]{13}$', re.IGNORECASE), modes=[
        HashInfo(name='DES(Unix)', hashcat=1500, john='descrypt', extended=False),
        HashInfo(name='Traditional DES', hashcat=1500, john='descrypt', extended=False),
        HashInfo(name='DEScrypt', hashcat=1500, john='descrypt', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='MySQL323', hashcat=200, john='mysql', extended=False),
        HashInfo(name='DES(Oracle)', hashcat=3100, john=None, extended=False),
        HashInfo(name='Half MD5', hashcat=5100, john=None, extended=False),
        HashInfo(name='Oracle 7-10g', hashcat=3100, john=None, extended=False),
        HashInfo(name='FNV-164', hashcat=None, john=None, extended=False),
        HashInfo(name='CRC-64', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/.]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco-PIX(MD5)', hashcat=2400, john='pix-md5', extended=False)]),
    Prototype(regex=re.compile(r'^\([a-z0-9\/+]{20}\)$', re.IGNORECASE), modes=[
        HashInfo(name='Lotus Notes/Domino 6', hashcat=8700, john='dominosec', extended=False)]),
    Prototype(regex=re.compile(r'^_[a-z0-9\/.]{19}$', re.IGNORECASE), modes=[
        HashInfo(name='BSDi Crypt', hashcat=None, john='bsdicrypt', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{24}$', re.IGNORECASE), modes=[
        HashInfo(name='CRC-96(ZIP)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/.]{24}$', re.IGNORECASE), modes=[
        HashInfo(name='Crypt16', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$md2\$)?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='MD2', hashcat=None, john='md2', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}(:.+)?$', re.IGNORECASE), modes=[
        HashInfo(name='MD5', hashcat=0, john='raw-md5', extended=False),
        HashInfo(name='MD4', hashcat=900, john='raw-md4', extended=False),
        HashInfo(name='Double MD5', hashcat=2600, john=None, extended=False),
        HashInfo(name='LM', hashcat=3000, john='lm', extended=False),
        HashInfo(name='RIPEMD-128', hashcat=None, john='ripemd-128', extended=False),
        HashInfo(name='Haval-128', hashcat=None, john='haval-128-4', extended=False),
        HashInfo(name='Tiger-128', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-256(128)', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-512(128)', hashcat=None, john=None, extended=False),
        HashInfo(name='Lotus Notes/Domino 5', hashcat=8600, john='lotus5', extended=False),
        HashInfo(name='Skype', hashcat=23, john=None, extended=False),
        HashInfo(name='ZipMonster', hashcat=None, john=None, extended=True),
        HashInfo(name='PrestaShop', hashcat=11000, john=None, extended=True),
        HashInfo(name='md5(md5(md5($pass)))', hashcat=3500, john=None, extended=True),
        HashInfo(name='md5(strtoupper(md5($pass)))', hashcat=4300, john=None, extended=True),
        HashInfo(name='md5(sha1($pass))', hashcat=4400, john=None, extended=True),
        HashInfo(name='md5($pass.$salt)', hashcat=10, john=None, extended=True),
        HashInfo(name='md5($salt.$pass)', hashcat=20, john=None, extended=True),
        HashInfo(name='md5(unicode($pass).$salt)', hashcat=30, john=None, extended=True),
        HashInfo(name='md5($salt.unicode($pass))', hashcat=40, john=None, extended=True),
        HashInfo(name='HMAC-MD5 (key = $pass)', hashcat=50, john='hmac-md5', extended=True),
        HashInfo(name='HMAC-MD5 (key = $salt)', hashcat=60, john='hmac-md5', extended=True),
        HashInfo(name='md5(md5($salt).$pass)', hashcat=3610, john=None, extended=True),
        HashInfo(name='md5($salt.md5($pass))', hashcat=3710, john=None, extended=True),
        HashInfo(name='md5($pass.md5($salt))', hashcat=3720, john=None, extended=True),
        HashInfo(name='md5($salt.$pass.$salt)', hashcat=3810, john=None, extended=True),
        HashInfo(name='md5(md5($pass).md5($salt))', hashcat=3910, john=None, extended=True),
        HashInfo(name='md5($salt.md5($salt.$pass))', hashcat=4010, john=None, extended=True),
        HashInfo(name='md5($salt.md5($pass.$salt))', hashcat=4110, john=None, extended=True),
        HashInfo(name='md5($username.0.$pass)', hashcat=4210, john=None, extended=True)]),
    Prototype(regex=re.compile(r'^(\$snefru\$)?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='Snefru-128', hashcat=None, john='snefru-128', extended=False)]),
    Prototype(regex=re.compile(r'^(\$NT\$)?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='NTLM', hashcat=1000, john='nt', extended=False)]),
    Prototype(regex=re.compile(r'^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$', re.IGNORECASE), modes=[
        HashInfo(name='Domain Cached Credentials', hashcat=1100, john='mscash', extended=False)]),
    Prototype(regex=re.compile(r'^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='Domain Cached Credentials 2', hashcat=2100, john='mscash2', extended=False)]),
    Prototype(regex=re.compile(r'^{SHA}[a-z0-9\/+]{27}=$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-1(Base64)', hashcat=101, john='nsldap', extended=False),
        HashInfo(name='Netscape LDAP SHA', hashcat=101, john='nsldap', extended=False)]),
    Prototype(regex=re.compile(r'^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$', re.IGNORECASE), modes=[
        HashInfo(name='MD5 Crypt', hashcat=500, john='md5crypt', extended=False),
        HashInfo(name='Cisco-IOS(MD5)', hashcat=500, john='md5crypt', extended=False),
        HashInfo(name='FreeBSD MD5', hashcat=500, john='md5crypt', extended=False)]),
    Prototype(regex=re.compile(r'^0x[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='Lineage II C4', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$H\$[a-z0-9\/.]{31}$', re.IGNORECASE), modes=[
        HashInfo(name='phpBB v3.x', hashcat=400, john='phpass', extended=False),
        HashInfo(name='Wordpress v2.6.0/2.6.1', hashcat=400, john='phpass', extended=False),
        HashInfo(name="PHPass' Portable Hash", hashcat=400, john='phpass', extended=False)]),
    Prototype(regex=re.compile(r'^\$P\$[a-z0-9\/.]{31}$', re.IGNORECASE), modes=[
        HashInfo(name=u'Wordpress \u2265 v2.6.2', hashcat=400, john='phpass', extended=False),
        HashInfo(name=u'Joomla \u2265 v2.5.18', hashcat=400, john='phpass', extended=False),
        HashInfo(name="PHPass' Portable Hash", hashcat=400, john='phpass', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[a-z0-9]{2}$', re.IGNORECASE), modes=[
        HashInfo(name='osCommerce', hashcat=21, john=None, extended=False),
        HashInfo(name='xt:Commerce', hashcat=21, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$', re.IGNORECASE), modes=[
        HashInfo(name='MD5(APR)', hashcat=1600, john=None, extended=False),
        HashInfo(name='Apache MD5', hashcat=1600, john=None, extended=False),
        HashInfo(name='md5apr1', hashcat=1600, john=None, extended=True)]),
    Prototype(regex=re.compile(r'^{smd5}[a-z0-9$\/.]{31}$', re.IGNORECASE), modes=[
        HashInfo(name='AIX(smd5)', hashcat=6300, john='aix-smd5', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='WebEdition CMS', hashcat=3721, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:.{5}$', re.IGNORECASE), modes=[
        HashInfo(name=u'IP.Board \u2265 v2+', hashcat=2811, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:.{8}$', re.IGNORECASE), modes=[
        HashInfo(name=u'MyBB \u2265 v1.2+', hashcat=2811, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9]{34}$', re.IGNORECASE), modes=[
        HashInfo(name='CryptoCurrency(Adress)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{40}(:.+)?$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-1', hashcat=100, john='raw-sha1', extended=False),
        HashInfo(name='Double SHA-1', hashcat=4500, john=None, extended=False),
        HashInfo(name='RIPEMD-160', hashcat=6000, john='ripemd-160', extended=False),
        HashInfo(name='Haval-160', hashcat=None, john=None, extended=False),
        HashInfo(name='Tiger-160', hashcat=None, john=None, extended=False),
        HashInfo(name='HAS-160', hashcat=None, john=None, extended=False),
        HashInfo(name='LinkedIn', hashcat=190, john='raw-sha1-linkedin', extended=False),
        HashInfo(name='Skein-256(160)', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-512(160)', hashcat=None, john=None, extended=False),
        HashInfo(name='MangosWeb Enhanced CMS', hashcat=None, john=None, extended=True),
        HashInfo(name='sha1(sha1(sha1($pass)))', hashcat=4600, john=None, extended=True),
        HashInfo(name='sha1(md5($pass))', hashcat=4700, john=None, extended=True),
        HashInfo(name='sha1($pass.$salt)', hashcat=110, john=None, extended=True),
        HashInfo(name='sha1($salt.$pass)', hashcat=120, john=None, extended=True),
        HashInfo(name='sha1(unicode($pass).$salt)', hashcat=130, john=None, extended=True),
        HashInfo(name='sha1($salt.unicode($pass))', hashcat=140, john=None, extended=True),
        HashInfo(name='HMAC-SHA1 (key = $pass)', hashcat=150, john='hmac-sha1', extended=True),
        HashInfo(name='HMAC-SHA1 (key = $salt)', hashcat=160, john='hmac-sha1', extended=True),
        HashInfo(name='sha1($salt.$pass.$salt)', hashcat=4710, john=None, extended=True)]),
    Prototype(regex=re.compile(r'^\*[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='MySQL5.x', hashcat=300, john='mysql-sha1', extended=False),
        HashInfo(name='MySQL4.1', hashcat=300, john='mysql-sha1', extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco-IOS(SHA-256)', hashcat=5700, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^{SSHA}[a-z0-9\/+]{38}==$', re.IGNORECASE), modes=[
        HashInfo(name='SSHA-1(Base64)', hashcat=111, john='nsldaps', extended=False),
        HashInfo(name='Netscape LDAP SSHA', hashcat=111, john='nsldaps', extended=False),
        HashInfo(name='nsldaps', hashcat=111, john='nsldaps', extended=True)]),
    Prototype(regex=re.compile(r'^[a-z0-9=]{47}$', re.IGNORECASE), modes=[
        HashInfo(name='Fortigate(FortiOS)', hashcat=7000, john='fortigate', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{48}$', re.IGNORECASE), modes=[
        HashInfo(name='Haval-192', hashcat=None, john=None, extended=False),
        HashInfo(name='Tiger-192', hashcat=None, john='tiger', extended=False),
        HashInfo(name='SHA-1(Oracle)', hashcat=None, john=None, extended=False),
        HashInfo(name='OSX v10.4', hashcat=122, john='xsha', extended=False),
        HashInfo(name='OSX v10.5', hashcat=122, john='xsha', extended=False),
        HashInfo(name='OSX v10.6', hashcat=122, john='xsha', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{51}$', re.IGNORECASE), modes=[
        HashInfo(name='Palshop CMS', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9]{51}$', re.IGNORECASE), modes=[
        HashInfo(name='CryptoCurrency(PrivateKey)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$', re.IGNORECASE), modes=[
        HashInfo(name='AIX(ssha1)', hashcat=6700, john='aix-ssha1', extended=False)]),
    Prototype(regex=re.compile(r'^0x0100[a-f0-9]{48}$', re.IGNORECASE), modes=[
        HashInfo(name='MSSQL(2005)', hashcat=132, john='mssql05', extended=False),
        HashInfo(name='MSSQL(2008)', hashcat=132, john='mssql05', extended=False)]),
    Prototype(regex=re.compile(r'^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$', re.IGNORECASE), modes=[
        HashInfo(name='Sun MD5 Crypt', hashcat=3300, john='sunmd5', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-224', hashcat=None, john='raw-sha224', extended=False),
        HashInfo(name='Haval-224', hashcat=None, john=None, extended=False),
        HashInfo(name='SHA3-224', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-256(224)', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-512(224)', hashcat=None, john=None, extended=False)]),
    # FIXED: [axy] -> [abxy] (was missing $2b$, the modern bcrypt variant)
    Prototype(regex=re.compile(r'^(\$2[abxy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$', re.IGNORECASE), modes=[
        HashInfo(name='Blowfish(OpenBSD)', hashcat=3200, john='bcrypt', extended=False),
        HashInfo(name='Woltlab Burning Board 4.x', hashcat=None, john=None, extended=False),
        HashInfo(name='bcrypt', hashcat=3200, john='bcrypt', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{40}:[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='Android PIN', hashcat=5800, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$', re.IGNORECASE), modes=[
        HashInfo(name='Oracle 11g/12c', hashcat=112, john='oracle11', extended=False)]),
    # FIXED: [axy] -> [abxy]
    Prototype(regex=re.compile(r'^\$bcrypt-sha256\$(2[abxy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$', re.IGNORECASE), modes=[
        HashInfo(name='bcrypt(SHA-256)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:.{3}$', re.IGNORECASE), modes=[
        HashInfo(name='vBulletin < v3.8.5', hashcat=2611, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:.{30}$', re.IGNORECASE), modes=[
        HashInfo(name=u'vBulletin \u2265 v3.8.5', hashcat=2711, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$snefru\$)?[a-f0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='Snefru-256', hashcat=None, john='snefru-256', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{64}(:.+)?$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-256', hashcat=1400, john='raw-sha256', extended=False),
        HashInfo(name='RIPEMD-256', hashcat=None, john=None, extended=False),
        HashInfo(name='Haval-256', hashcat=None, john='haval-256-3', extended=False),
        HashInfo(name='GOST R 34.11-94', hashcat=6900, john='gost', extended=False),
        HashInfo(name='GOST CryptoPro S-Box', hashcat=None, john=None, extended=False),
        HashInfo(name='SHA3-256', hashcat=5000, john='raw-keccak-256', extended=False),
        HashInfo(name='Skein-256', hashcat=None, john='skein-256', extended=False),
        HashInfo(name='Skein-512(256)', hashcat=None, john=None, extended=False),
        HashInfo(name='Ventrilo', hashcat=None, john=None, extended=True),
        HashInfo(name='sha256($pass.$salt)', hashcat=1410, john=None, extended=True),
        HashInfo(name='sha256($salt.$pass)', hashcat=1420, john=None, extended=True),
        HashInfo(name='sha256(unicode($pass).$salt)', hashcat=1430, john=None, extended=True),
        HashInfo(name='sha256($salt.unicode($pass))', hashcat=1440, john=None, extended=True),
        HashInfo(name='HMAC-SHA256 (key = $pass)', hashcat=1450, john='hmac-sha256', extended=True),
        HashInfo(name='HMAC-SHA256 (key = $salt)', hashcat=1460, john='hmac-sha256', extended=True)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[a-z0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='Joomla < v2.5.18', hashcat=11, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f-0-9]{32}:[a-f-0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='SAM(LM_Hash:NT_Hash)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$', re.IGNORECASE), modes=[
        HashInfo(name='MD5(Chap)', hashcat=4800, john='chap', extended=False),
        HashInfo(name='iSCSI CHAP Authentication', hashcat=4800, john='chap', extended=False)]),
    Prototype(regex=re.compile(r'^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$', re.IGNORECASE), modes=[
        HashInfo(name='EPiServer 6.x < v4', hashcat=141, john='episerver', extended=False)]),
    Prototype(regex=re.compile(r'^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$', re.IGNORECASE), modes=[
        HashInfo(name='AIX(ssha256)', hashcat=6400, john='aix-ssha256', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{80}$', re.IGNORECASE), modes=[
        HashInfo(name='RIPEMD-320', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$', re.IGNORECASE), modes=[
        HashInfo(name=u'EPiServer 6.x \u2265 v4', hashcat=1441, john='episerver', extended=False)]),
    Prototype(regex=re.compile(r'^0x0100[a-f0-9]{88}$', re.IGNORECASE), modes=[
        HashInfo(name='MSSQL(2000)', hashcat=131, john='mssql', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-384', hashcat=10800, john='raw-sha384', extended=False),
        HashInfo(name='SHA3-384', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-512(384)', hashcat=None, john=None, extended=False),
        HashInfo(name='Skein-1024(384)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^{SSHA512}[a-z0-9\/+]{96}$', re.IGNORECASE), modes=[
        HashInfo(name='SSHA-512(Base64)', hashcat=1711, john='ssha512', extended=False),
        HashInfo(name='LDAP(SSHA-512)', hashcat=1711, john='ssha512', extended=False)]),
    Prototype(regex=re.compile(r'^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$', re.IGNORECASE), modes=[
        HashInfo(name='AIX(ssha512)', hashcat=6500, john='aix-ssha512', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{128}(:.+)?$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-512', hashcat=1700, john='raw-sha512', extended=False),
        HashInfo(name='Whirlpool', hashcat=6100, john='whirlpool', extended=False),
        HashInfo(name='Salsa10', hashcat=None, john=None, extended=False),
        HashInfo(name='Salsa20', hashcat=None, john=None, extended=False),
        HashInfo(name='SHA3-512', hashcat=None, john='raw-keccak', extended=False),
        HashInfo(name='Skein-512', hashcat=None, john='skein-512', extended=False),
        HashInfo(name='Skein-1024(512)', hashcat=None, john=None, extended=False),
        HashInfo(name='sha512($pass.$salt)', hashcat=1710, john=None, extended=True),
        HashInfo(name='sha512($salt.$pass)', hashcat=1720, john=None, extended=True),
        HashInfo(name='sha512(unicode($pass).$salt)', hashcat=1730, john=None, extended=True),
        HashInfo(name='sha512($salt.unicode($pass))', hashcat=1740, john=None, extended=True),
        HashInfo(name='HMAC-SHA512 (key = $pass)', hashcat=1750, john='hmac-sha512', extended=True),
        HashInfo(name='HMAC-SHA512 (key = $salt)', hashcat=1760, john='hmac-sha512', extended=True)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{136}$', re.IGNORECASE), modes=[
        HashInfo(name='OSX v10.7', hashcat=1722, john='xsha512', extended=False)]),
    Prototype(regex=re.compile(r'^0x0200[a-f0-9]{136}$', re.IGNORECASE), modes=[
        HashInfo(name='MSSQL(2012)', hashcat=1731, john='mssql12', extended=False),
        HashInfo(name='MSSQL(2014)', hashcat=1731, john='mssql12', extended=False)]),
    Prototype(regex=re.compile(r'^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$', re.IGNORECASE), modes=[
        HashInfo(name='OSX v10.8', hashcat=7100, john='pbkdf2-hmac-sha512', extended=False),
        HashInfo(name='OSX v10.9', hashcat=7100, john='pbkdf2-hmac-sha512', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{256}$', re.IGNORECASE), modes=[
        HashInfo(name='Skein-1024', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$', re.IGNORECASE), modes=[
        HashInfo(name='GRUB 2', hashcat=7200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha1\$[a-z0-9]+\$[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(SHA-1)', hashcat=124, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{49}$', re.IGNORECASE), modes=[
        HashInfo(name='Citrix Netscaler', hashcat=8100, john='citrix_ns10', extended=False)]),
    Prototype(regex=re.compile(r'^\$S\$[a-z0-9\/.]{52}$', re.IGNORECASE), modes=[
        HashInfo(name='Drupal > v7.x', hashcat=7900, john='drupal7', extended=False)]),
    Prototype(regex=re.compile(r'^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-256 Crypt', hashcat=7400, john='sha256crypt', extended=False)]),
    Prototype(regex=re.compile(r'^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='Sybase ASE', hashcat=8000, john='sybasease', extended=False)]),
    Prototype(regex=re.compile(r'^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-512 Crypt', hashcat=1800, john='sha512crypt', extended=False)]),
    Prototype(regex=re.compile(r'^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$', re.IGNORECASE), modes=[
        HashInfo(name='Minecraft(AuthMe Reloaded)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha256\$[a-z0-9]+\$[a-f0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(SHA-256)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha384\$[a-z0-9]+\$[a-f0-9]{96}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(SHA-384)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$', re.IGNORECASE), modes=[
        HashInfo(name='Clavister Secure Gateway', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{112}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco VPN Client(PCF-File)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{1329}$', re.IGNORECASE), modes=[
        HashInfo(name='Microsoft MSTSC(RDP-File)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='NetNTLMv1-VANILLA / NetNTLMv1+ESS', hashcat=5500, john='netntlm', extended=False)]),
    Prototype(regex=re.compile(r'^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='NetNTLMv2', hashcat=5600, john='netntlmv2', extended=False)]),
    Prototype(regex=re.compile(r'^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$', re.IGNORECASE), modes=[
        HashInfo(name='Kerberos 5 AS-REQ Pre-Auth', hashcat=7500, john='krb5pa-md5', extended=False)]),
    Prototype(regex=re.compile(r'^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$', re.IGNORECASE), modes=[
        HashInfo(name='SCRAM Hash', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{40}:[a-f0-9]{0,32}$', re.IGNORECASE), modes=[
        HashInfo(name='Redmine Project Management Web App', hashcat=7600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(.+)?\$[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='SAP CODVN B (BCODE)', hashcat=7700, john='sapb', extended=False)]),
    Prototype(regex=re.compile(r'^(.+)?\$[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='SAP CODVN F/G (PASSCODE)', hashcat=7800, john='sapg', extended=False)]),
    Prototype(regex=re.compile(r'^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$', re.IGNORECASE), modes=[
        HashInfo(name='Juniper Netscreen/SSG(ScreenOS)', hashcat=22, john='md5ns', extended=False)]),
    Prototype(regex=re.compile(r'^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='EPi', hashcat=123, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{40}:[^*]{1,25}$', re.IGNORECASE), modes=[
        HashInfo(name=u'SMF \u2265 v1.1', hashcat=121, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='Woltlab Burning Board 3.x', hashcat=8400, john='wbb3', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{130}(:[a-f0-9]{40})?$', re.IGNORECASE), modes=[
        HashInfo(name='IPMI2 RAKP HMAC-SHA1', hashcat=7300, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$', re.IGNORECASE), modes=[
        HashInfo(name='Lastpass', hashcat=6800, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/.]{16}([:$].{1,})?$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco-ASA(MD5)', hashcat=2410, john='asa-md5', extended=False)]),
    Prototype(regex=re.compile(r'^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='VNC', hashcat=None, john='vnc', extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$', re.IGNORECASE), modes=[
        HashInfo(name='DNSSEC(NSEC3)', hashcat=8300, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='RACF', hashcat=8500, john='racf', extended=False)]),
    Prototype(regex=re.compile(r'^\$3\$\$[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='NTHash(FreeBSD Variant)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-1 Crypt', hashcat=None, john='sha1crypt', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{70}$', re.IGNORECASE), modes=[
        HashInfo(name='hMailServer', hashcat=1421, john='hmailserver', extended=False)]),
    Prototype(regex=re.compile(r'^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='MediaWiki', hashcat=3711, john='mediawiki', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{140}$', re.IGNORECASE), modes=[
        HashInfo(name='Minecraft(xAuth)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2-SHA1(Generic)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2-SHA256(Generic)', hashcat=None, john='pbkdf2-hmac-sha256', extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2-SHA512(Generic)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2(Cryptacular)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2(Dwayne Litzenberger)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$', re.IGNORECASE), modes=[
        HashInfo(name='Fairly Secure Hashed Password', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$PHPS\$.+\$[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='PHPS', hashcat=2612, john='phps', extended=False)]),
    Prototype(regex=re.compile(r'^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$', re.IGNORECASE), modes=[
        HashInfo(name='1Password(Agile Keychain)', hashcat=6600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$', re.IGNORECASE), modes=[
        HashInfo(name='1Password(Cloud Keychain)', hashcat=8200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='IKE-PSK MD5', hashcat=5300, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='IKE-PSK SHA1', hashcat=5400, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/+]{27}=$', re.IGNORECASE), modes=[
        HashInfo(name='PeopleSoft', hashcat=133, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(DES Crypt Wrapper)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(PBKDF2-HMAC-SHA256)', hashcat=10000, john='django', extended=False)]),
    Prototype(regex=re.compile(r'^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(PBKDF2-HMAC-SHA1)', hashcat=None, john=None, extended=False)]),
    # FIXED: [axy] -> [abxy]
    Prototype(regex=re.compile(r'^bcrypt(\$2[abxy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(bcrypt)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^md5\$[a-f0-9]+\$[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(MD5)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\{PKCS5S2\}[a-z0-9\/+]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2(Atlassian)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^md5[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='PostgreSQL MD5', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\([a-z0-9\/+]{49}\)$', re.IGNORECASE), modes=[
        HashInfo(name='Lotus Notes/Domino 8', hashcat=9100, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$', re.IGNORECASE), modes=[
        HashInfo(name='scrypt', hashcat=8900, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco Type 8', hashcat=9200, john='cisco8', extended=False)]),
    Prototype(regex=re.compile(r'^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco Type 9', hashcat=9300, john='cisco9', extended=False)]),
    Prototype(regex=re.compile(r'^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='Microsoft Office 2007', hashcat=9400, john='office', extended=False)]),
    Prototype(regex=re.compile(r'^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='Microsoft Office 2010', hashcat=9500, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='Microsoft Office 2013', hashcat=9600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$', re.IGNORECASE), modes=[
        HashInfo(name=u'Android FDE \u2264 4.3', hashcat=8800, john='fde', extended=False)]),
    Prototype(regex=re.compile(r'^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name=u'Microsoft Office \u2264 2003 (MD5+RC4)', hashcat=9700, john='oldoffice', extended=False),
        HashInfo(name=u'Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #1', hashcat=9710, john='oldoffice', extended=False),
        HashInfo(name=u'Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #2', hashcat=9720, john='oldoffice', extended=False)]),
    Prototype(regex=re.compile(r'^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name=u'Microsoft Office \u2264 2003 (SHA1+RC4)', hashcat=9800, john=None, extended=False),
        HashInfo(name=u'Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #1', hashcat=9810, john=None, extended=False),
        HashInfo(name=u'Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #2', hashcat=9820, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$radmin2\$)?[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='RAdmin v2.x', hashcat=9900, john='radmin', extended=False)]),
    Prototype(regex=re.compile(r'^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$', re.IGNORECASE), modes=[
        HashInfo(name='SAP CODVN H (PWDSALTEDHASH) iSSHA-1', hashcat=10300, john='saph', extended=False)]),
    Prototype(regex=re.compile(r'^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$', re.IGNORECASE), modes=[
        HashInfo(name='CRAM-MD5', hashcat=10200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{16}:2:4:[a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='SipHash', hashcat=10100, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{4,}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco Type 7', hashcat=None, john=None, extended=True)]),
    Prototype(regex=re.compile(r'^[a-z0-9\/.]{13,}$', re.IGNORECASE), modes=[
        HashInfo(name='BigCrypt', hashcat=None, john='bigcrypt', extended=True)]),
    Prototype(regex=re.compile(r'^(\$cisco4\$)?[a-z0-9\/.]{43}$', re.IGNORECASE), modes=[
        HashInfo(name='Cisco Type 4', hashcat=None, john='cisco4', extended=False)]),
    # FIXED: [axy] -> [abxy]
    Prototype(regex=re.compile(r'^bcrypt_sha256\$\$(2[abxy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$', re.IGNORECASE), modes=[
        HashInfo(name='Django(bcrypt-SHA256)', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$', re.IGNORECASE), modes=[
        HashInfo(name='PostgreSQL Challenge-Response Authentication (MD5)', hashcat=11100, john='postgres', extended=False)]),
    Prototype(regex=re.compile(r'^\$siemens-s7\$\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='Siemens-S7', hashcat=None, john='siemens-s7', extended=False)]),
    Prototype(regex=re.compile(r'^(\$pst\$)?[a-f0-9]{8}$', re.IGNORECASE), modes=[
        HashInfo(name='Microsoft Outlook PST', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$', re.IGNORECASE), modes=[
        HashInfo(name='PBKDF2-HMAC-SHA256(PHP)', hashcat=10900, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^(\$dahua\$)?[a-z0-9]{8}$', re.IGNORECASE), modes=[
        HashInfo(name='Dahua', hashcat=None, john='dahua', extended=False)]),
    Prototype(regex=re.compile(r'^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='MySQL Challenge-Response Authentication (SHA1)', hashcat=11200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$', re.IGNORECASE), modes=[
        HashInfo(name='PDF 1.4 - 1.6 (Acrobat 5 - 8)', hashcat=10500, john='pdf', extended=False)]),
]


# ---------------------------------------------------------------------------
# CURATED ADDITIONS (v0.2) - gaps found by testing against hashcat's real
# example hashes. Hand-written, so reviewed and deliberately specific.
# ---------------------------------------------------------------------------

curated_prototypes = [
    Prototype(regex=re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), modes=[
        HashInfo(name='MySQL4.1/MySQL5 (without leading *)', hashcat=300, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='LM (single 8-byte half)', hashcat=3000, john='lm', extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA-224', hashcat=1300, john='raw-sha224', extended=False),
        HashInfo(name='SHA3-224', hashcat=17300, john=None, extended=False),
        HashInfo(name='Keccak-224', hashcat=17700, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA3-256', hashcat=17400, john=None, extended=False),
        HashInfo(name='Keccak-256 (Ethereum addresses/hashes)', hashcat=17800, john=None, extended=False),
        HashInfo(name='BLAKE2s-256', hashcat=None, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA3-384', hashcat=17500, john=None, extended=False),
        HashInfo(name='Keccak-384', hashcat=17900, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE), modes=[
        HashInfo(name='SHA3-512', hashcat=17600, john=None, extended=False),
        HashInfo(name='Keccak-512', hashcat=18000, john=None, extended=False),
        HashInfo(name='BLAKE2b-512', hashcat=600, john=None, extended=False)]),
    # NetNTLMv1 captured with an empty username:  ::DOMAIN:lmresp:ntresp:challenge
    Prototype(regex=re.compile(r'^[^:\s]*::[^:\s]*:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$', re.IGNORECASE), modes=[
        HashInfo(name='NetNTLMv1 / NetNTLMv1+ESS', hashcat=5500, john='netntlm', extended=False)]),
    # LastPass:  hash:iterations:email
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:\d{1,7}:[^:\s]+@[^:\s]+$', re.IGNORECASE), modes=[
        HashInfo(name='LastPass + LastPass sniffed', hashcat=6800, john=None, extended=False)]),
    # LDAP salted SHA-1 with any salt length (OpenLDAP default is {SSHA})
    Prototype(regex=re.compile(r'^\{SSHA\}[A-Za-z0-9+/]{27,}={0,2}$'), modes=[
        HashInfo(name='LDAP {SSHA} (salted SHA-1, base64)', hashcat=111, john='nsldaps', extended=False)]),
    Prototype(regex=re.compile(r'^\{SSHA256\}[A-Za-z0-9+/]{43,}={0,2}$'), modes=[
        HashInfo(name='LDAP {SSHA256} (salted SHA-256, base64)', hashcat=1411, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\{SSHA512\}[A-Za-z0-9+/]{86,}={0,2}$'), modes=[
        HashInfo(name='LDAP {SSHA512} (salted SHA-512, base64)', hashcat=1711, john=None, extended=False)]),
    # ---- gaps found by running tools/check_against_hashcat.py on Kali (round 2) ----------
    Prototype(regex=re.compile(r'^48435058[a-f0-9]{100,}$', re.IGNORECASE), modes=[
        HashInfo(name='WPA-EAPOL (hashcat .hccapx file, hex-encoded)', hashcat=2500, john=None, extended=False),
        HashInfo(name='WPA-EAPOL-PMK (hashcat .hccapx file, hex-encoded)', hashcat=2501, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[a-f0-9]{12}:[a-f0-9]{12}:[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='WPA-PMKID-PBKDF2 (old format; WPA*01* is current)', hashcat=16800, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:[a-f0-9]{12}:[a-f0-9]{12}$', re.IGNORECASE), modes=[
        HashInfo(name='WPA-PMKID-PMK (old format)', hashcat=16801, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[a-f0-9]{32}:\d{1,7}:[^:\s]+@[^:\s]+:[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='LastPass + LastPass sniffed (with trailing field)', hashcat=6800, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[^$:\s]{1,12}\$[A-F0-9]{16}$'), modes=[
        HashInfo(name='SAP CODVN B (BCODE) from RFC_READ_TABLE', hashcat=7701, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^[^$:\s]{1,12}\$[A-F0-9]{40}$'), modes=[
        HashInfo(name='SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE', hashcat=7801, john=None, extended=False)]),
    # ---- gaps found by running tools/check_against_hashcat.py on Kali (round 1) ----------
    Prototype(regex=re.compile(r'^\{PKCS5S2\}[A-Za-z0-9+/=]{60,}$'), modes=[
        HashInfo(name='Atlassian (PBKDF2-HMAC-SHA1)', hashcat=12001, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\{PBKDF2_SHA256\}[A-Za-z0-9+/=]{40,}$'), modes=[
        HashInfo(name='RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)', hashcat=10901, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$sha1\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{28}$'), modes=[
        HashInfo(name='Juniper/NetBSD sha1crypt', hashcat=15100, john='sha1crypt', extended=False)]),
    Prototype(regex=re.compile(r'^\$shiro1\$SHA-512\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='Apache Shiro 1 SHA-512', hashcat=12150, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^_[./0-9A-Za-z]{19}$'), modes=[
        HashInfo(name='BSDi Crypt, Extended DES', hashcat=12400, john='bsdicrypt', extended=False)]),
    Prototype(regex=re.compile(r'^SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='PostgreSQL SCRAM-SHA-256', hashcat=28600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$ml\$\d+\$[a-f0-9]{64}\$[a-f0-9]{128}$', re.IGNORECASE), modes=[
        HashInfo(name='macOS v10.8+ (PBKDF2-SHA512)', hashcat=7100, john='pbkdf2-hmac-sha512', extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2-sha512\$\d+\$[A-Za-z0-9./+]+\$[A-Za-z0-9./+]{86}$'), modes=[
        HashInfo(name='Python passlib pbkdf2-sha512', hashcat=20200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9./+]+\$[A-Za-z0-9./+]{43}$'), modes=[
        HashInfo(name='Python passlib pbkdf2-sha256', hashcat=20300, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\$pbkdf2\$\d+\$[A-Za-z0-9./+]+\$[A-Za-z0-9./+]{27}$'), modes=[
        HashInfo(name='Python passlib pbkdf2-sha1', hashcat=20400, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^@m@[a-f0-9]{32}@[^@\s]+$', re.IGNORECASE), modes=[
        HashInfo(name='QNX /etc/shadow (MD5)', hashcat=19000, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^@s@[a-f0-9]{64}@[^@\s]+$', re.IGNORECASE), modes=[
        HashInfo(name='QNX /etc/shadow (SHA256)', hashcat=19100, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^@S@[a-f0-9]{128}@[^@\s]+$', re.IGNORECASE), modes=[
        HashInfo(name='QNX /etc/shadow (SHA512)', hashcat=19200, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^v1;PPH1_MD4,\d+,\d+,[a-f0-9]{64}$', re.IGNORECASE), modes=[
        HashInfo(name='MS-AzureSync PBKDF2-HMAC-SHA256', hashcat=12800, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^otm_sha256:\d+:[^:\s]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='Oracle Transportation Management (SHA256)', hashcat=20600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^pbkdf2\(\d+,\d+,sha(1|256|512)\)\$[^$\s]+\$[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='Web2py pbkdf2-sha512', hashcat=21600, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^PBKDF1:sha1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='PBKDF1-SHA1', hashcat=32900, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^md5:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='PBKDF2-HMAC-MD5', hashcat=11900, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='PBKDF2-HMAC-SHA1', hashcat=12000, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^sha512:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='PBKDF2-HMAC-SHA512', hashcat=12100, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^S:"Config Passphrase"=\d+:[a-f0-9]+$', re.IGNORECASE), modes=[
        HashInfo(name='SecureCRT MasterPassphrase v2', hashcat=31400, john=None, extended=False)]),
    Prototype(regex=re.compile(r'^\{x-isSHA512, \d+\}[A-Za-z0-9+/=]+$'), modes=[
        HashInfo(name='SAP CODVN H (PWDSALTEDHASH) isSHA512', hashcat=35000, john=None, extended=False)]),
]

base_prototypes = modern_prototypes + newer_prototypes + legacy_prototypes + curated_prototypes

# ---------------------------------------------------------------------------
# AUTO PATTERNS - generated by tools/generate_hashcat_patterns.py from the
# REAL example hashes in hashcat's source tree (MIT licensed). They cover the
# hashcat modes the hand-written patterns above do not. Loaded from JSON so
# the package works without hashcat installed.
# ---------------------------------------------------------------------------

_AUTO_DELIMS = "$:*#,;(){}|@~&% \t<>\"'\\[]!^?"
_AUTO_NOT_DELIM = "[^" + re.escape(_AUTO_DELIMS) + "]"


def _expand(rx):
    """<W+> / <W*> are readable placeholders for 'non-delimiter characters'."""
    return rx.replace("<W+>", _AUTO_NOT_DELIM + "+").replace("<W*>", _AUTO_NOT_DELIM + "*")


def _load_auto_prototypes():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "auto_patterns.json")
    try:
        with io.open(path, "r", encoding="utf-8") as f:
            records = json.load(f)
    except (EnvironmentError, ValueError):
        return []
    protos = []
    for rec in records:
        try:
            rx = re.compile(_expand(rec["regex"]))
        except re.error:
            continue
        ext = bool(rec.get("extended", False))
        modes = [HashInfo(name=m["name"], hashcat=m.get("hashcat"), john=m.get("john"), extended=ext)
                 for m in rec["modes"]]
        protos.append(Prototype(regex=rx, modes=modes))
    return protos


auto_prototypes = _load_auto_prototypes()
all_prototypes = base_prototypes + auto_prototypes

# ---------------------------------------------------------------------------
# POPULARITY RANKING (0-100, higher = more likely to be what you hold).
# This is what makes the FIRST line of output useful: a 32-hex string is
# listed as MD5 / NTLM first, not MD2. Scores are judgement calls based on
# how often each format shows up in CTFs, pentests and real breaches; edit
# freely. Lookup order: exact name -> hashcat mode -> default by specificity.
# ---------------------------------------------------------------------------

POPULARITY_BY_MODE = {
    0: 100,      # MD5
    100: 100,    # SHA-1
    1400: 100,   # SHA-256
    1700: 99,    # SHA-512
    1000: 98,    # NTLM
    3200: 100,   # bcrypt
    1800: 100,   # sha512crypt
    7400: 99,    # sha256crypt
    500: 99,     # md5crypt
    5600: 97,    # NetNTLMv2
    5500: 90,    # NetNTLMv1
    2100: 92,    # DCC2
    13100: 96,   # Kerberoast RC4
    19600: 90, 19700: 90,
    18200: 95,   # AS-REP
    16500: 94,   # JWT
    22000: 96,   # WPA
    300: 93,     # MySQL5
    400: 92,     # phpass (WordPress/Joomla)
    34000: 95,   # Argon2
    900: 55,     # MD4
    3000: 70,    # LM
    1100: 50,    # DCC1
    11300: 85, 13400: 88, 11600: 88, 12500: 85, 13000: 85, 13600: 80,
}
POPULARITY_BY_NAME = {
    'MD5': 100, 'SHA-1': 100, 'SHA-256': 100, 'SHA-512': 100, 'NTLM': 98, 'bcrypt': 100,
    'SHA-512 Crypt': 100, 'SHA-256 Crypt': 99, 'MD5 Crypt': 99, 'SHA-384': 60, 'SHA-224': 55,
    'LM': 70, 'MD4': 55, 'MySQL5.x': 93, 'MySQL323': 60, 'NetNTLMv2': 97,
    'Domain Cached Credentials 2': 92, 'Argon2id (current recommended standard)': 98,
    'Argon2i': 90, 'Argon2d': 90, 'yescrypt (modern Linux /etc/shadow default: Debian 11+/Ubuntu 22.04+)': 97,
    'scrypt (crypt-style)': 80, "PHPass' Portable Hash": 92, 'Wordpress \u2265 v2.6.2': 93,
    'Joomla \u2265 v2.5.18': 85, 'Drupal > v7.x': 88, 'PostgreSQL MD5': 80, 'MSSQL(2012)': 75,
    'MSSQL(2005)': 70, 'Cisco Type 8': 80, 'Cisco Type 9': 80, 'Django(PBKDF2-HMAC-SHA256)': 88,
    'MySQL4.1/MySQL5 (without leading *)': 60, 'SHA3-256': 45, 'SHA3-512': 45, 'SHA3-384': 40,
    'SHA3-224': 35, 'Keccak-256 (Ethereum addresses/hashes)': 45, 'Keccak-512': 35, 'Keccak-384': 30,
    'Keccak-224': 30, 'BLAKE2b-512': 45, 'BLAKE2s-256': 30, 'LM (single 8-byte half)': 40,
    'Blowfish(OpenBSD)': 90, 'Woltlab Burning Board 4.x': 30, 'Whirlpool': 45, 'Double MD5': 45, 'Double SHA-1': 45, 'RIPEMD-160': 45,
}
_SPECIFIC_PREFIX = re.compile(r"^\^(\\\$|\\\{|[A-Za-z_][A-Za-z0-9_\-]{2,}[:$*\\])")


def popularity(info, regex):
    """Score one (HashInfo, compiled regex) pair; higher means more likely."""
    if info.name in POPULARITY_BY_NAME:
        return POPULARITY_BY_NAME[info.name]
    if info.hashcat in POPULARITY_BY_MODE:
        return POPULARITY_BY_MODE[info.hashcat]
    # A distinctive literal prefix ($krb5tgs$, {SSHA}, WPA* ...) is a strong signal;
    # a bare length-only match (32 hex chars) is weak.
    return 70 if _SPECIFIC_PREFIX.match(regex.pattern) else 10


class HashID(object):
    """Hash identifier with configurable prototypes and popularity ranking."""

    def __init__(self, prototypes=None, rank=True):
        self.prototypes = list(all_prototypes if prototypes is None else prototypes)
        self.rank = rank

    def identifyHash(self, phash):
        """Return matching HashInfo objects, most likely first (if rank=True)."""
        phash = phash.strip()
        scored = []
        order = 0
        for prototype in self.prototypes:
            if prototype.regex.match(phash):
                for mode in prototype.modes:
                    scored.append((-popularity(mode, prototype.regex), order, mode))
                    order += 1
        if self.rank:
            scored.sort(key=lambda t: (t[0], t[1]))
        return iter([m for _, _, m in scored])


def writeResult(identified_modes, outfile, hashcatMode=False, johnFormat=False, extended=False, top=None):
    """Write human readable output from identifyHash (best guess first)."""
    count = 0
    hashTypes = ""
    for mode in identified_modes:
        if mode.extended and not extended:
            continue
        if top is not None and count >= top:
            break
        count += 1
        hashTypes += u"[+] {0} ".format(mode.name)
        if hashcatMode and mode.hashcat is not None:
            hashTypes += "[Hashcat Mode: {0}]".format(mode.hashcat)
        if johnFormat and mode.john is not None:
            hashTypes += "[JtR Format: {0}]".format(mode.john)
        hashTypes += "\n"
    outfile.write(hashTypes)
    if count == 0:
        outfile.write(u"[+] Unknown hash\n")
    return (count > 0)


def main():
    usage = "hashscope [-h] [-e] [-m] [-j] [-t N] [--no-rank] [-o FILE] INPUT"
    description = "HashScope: hash identifier with popularity ranking (most likely first), hashid database (bcrypt bug fixed), modern algorithms and hashcat-derived patterns"

    parser = argparse.ArgumentParser(usage=usage, description=description, add_help=False)
    parser.add_argument("strings", metavar="INPUT", type=str, nargs="*",
                         help="input to analyze (default: STDIN)")
    group = parser.add_argument_group('options')
    group.add_argument("-e", "--extended", action="store_true",
                        help="list all possible hash algorithms including salted passwords")
    group.add_argument("-m", "--mode", action="store_true",
                        help="show corresponding Hashcat mode in output")
    group.add_argument("-j", "--john", action="store_true",
                        help="show corresponding JohnTheRipper format in output")
    group.add_argument("-t", "--top", metavar="N", type=int, default=None,
                        help="show only the N most likely results")
    group.add_argument("--no-rank", action="store_true",
                        help="do not sort by popularity (original hashid order)")
    group.add_argument("-o", "--outfile", metavar="FILE", type=str,
                        help="write output to file")
    group.add_argument("-h", "--help", action="help", help="show this help message and exit")
    args = parser.parse_args()

    hashID = HashID(rank=not args.no_rank)

    if not args.outfile:
        outfile = sys.stdout
    else:
        try:
            outfile = io.open(args.outfile, "w", encoding="utf-8")
        except EnvironmentError:
            parser.error("Could not open {0}".format(args.outfile))

    if not args.strings or args.strings[0] == "-":
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            outfile.write(u"Analyzing '{0}'\n".format(line.strip()))
            writeResult(hashID.identifyHash(line), outfile, args.mode, args.john, args.extended, args.top)
            sys.stdout.flush()
    else:
        for string in args.strings:
            if os.path.isfile(string):
                try:
                    with io.open(string, "r", encoding="utf-8") as infile:
                        outfile.write("--File '{0}'--\n".format(string))
                        for line in infile:
                            if line.strip():
                                outfile.write(u"Analyzing '{0}'\n".format(line.strip()))
                                writeResult(hashID.identifyHash(line), outfile, args.mode, args.john, args.extended, args.top)
                except (EnvironmentError, UnicodeDecodeError):
                    outfile.write("--File '{0}' - could not open--".format(string))
                else:
                    outfile.write("--End of file '{0}'--".format(string))
            else:
                outfile.write(u"Analyzing '{0}'\n".format(string.strip()))
                writeResult(hashID.identifyHash(string), outfile, args.mode, args.john, args.extended, args.top)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
