#!/usr/bin/env python3
"""Held-out check: how well do HashScope / Name-That-Hash identify John the Ripper's
OWN test hashes (a different source than hashcat, so not circular).
  git clone --depth 1 https://github.com/openwall/john.git /tmp/john
  python3 tools/heldout_john_check.py /tmp/john
"""
import re,glob,json,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..'))
from hashscope import HashID
from name_that_hash import runner
e=HashID()
vecs=[]
for f in glob.glob(os.path.join(sys.argv[1] if len(sys.argv)>1 else '/tmp/john','src','*_fmt_plug.c')):
    s=open(f,errors='replace').read()
    lab=re.search(r'FORMAT_LABEL\s+"([^"]+)"',s)
    blk=re.search(r'fmt_tests\s+\w+\[\]\s*=\s*\{(.*?)\n\};',s,re.S)
    if not (lab and blk): continue
    cnt=0
    for m in re.finditer(r'\{\s*"((?:[^"\\]|\\.)*)"\s*,\s*"[^"]*"\s*\}',blk.group(1)):
        h=m.group(1).encode().decode('unicode_escape',errors='ignore') if '\\' in m.group(1) else m.group(1)
        if re.match(r'^(\$[A-Za-z0-9_\-]+\$|\{[A-Za-z0-9_\-]+\}|[A-Za-z][A-Za-z0-9_\-]{2,}[$:*#])',h) and len(h)<400 and '\n' not in h:
            vecs.append((lab.group(1),h)); cnt+=1
        if cnt>=2: break
print(len(vecs),'john vectors with a literal marker (from',len({l for l,_ in vecs}),'formats)')
def hs(h): return [m.name for m in e.identifyHash(h)]
def nth(h):
    r=json.loads(runner.api_return_hashes_as_json([h])); return [m['name'] for m in r.get(h,[])]
a=sum(1 for _,h in vecs if hs(h)); b=sum(1 for _,h in vecs if nth(h))
sp=sum(1 for _,h in vecs if hs(h) and len(hs(h))<=5)
print(f'HashScope matched {a}/{len(vecs)}  (specific, <=5 candidates: {sp})   Name-That-Hash matched {b}/{len(vecs)}')
miss=[(l,h[:60]) for l,h in vecs if not hs(h)]
print('sample misses:',miss[:12])
