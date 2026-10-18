#!/usr/bin/env python3
"""Unit test for ferric.maps 0.5.1 stride by content on an NT-heap-shaped heap (no glibc size field before
any block), the condition of every Windows image. Reproduces the first Windows matrix (Session 77): 0.4.1
read 240/248/232/208 for tables whose true strides are 32/48/48/72. Run: python3 tests/test_maps_ntheap.py"""
import os, random, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.maps import block_len, infer_stride, GROUP_WIDTH
from ferric.strings import Regions, HEAP
mem = bytearray(0x200000); BASE = 0x10000000
def write(a, b): mem[a-BASE:a-BASE+len(b)] = b
def read(a, n):
    o = a - BASE
    if o < 0 or o + n > len(mem): return bytes(n)
    return bytes(mem[o:o+n])
regions = Regions([(BASE, BASE + len(mem), HEAP, "[heap]")])
Q = lambda *v: struct.pack("<" + "Q"*len(v), *v)
bump = [BASE + 0x1000]
def alloc(n):                     # NT-heap-like: 16-aligned, an 8..16 byte opaque header, no glibc size field
    p = (bump[0] + 16 + 15) & ~15
    write(p - 16, b"\x5a" * 16)   # random-looking heap entry header (encoded on real NT heaps)
    bump[0] = p + n
    return p
def string(t, cap=None):
    b = t.encode(); cap = cap or len(b); p = alloc(cap); write(p, b); return Q(cap, p, len(b))
def table(stride, buckets, full):
    ctrl_off, total = block_len(stride, buckets); base = alloc(total); ctrl = base + ctrl_off
    rnd = random.Random(stride * 1000 + buckets)
    idx = sorted(rnd.sample(range(buckets), len(full)))
    arr = bytearray([0xFF] * (buckets + GROUP_WIDTH))
    for i, e in zip(idx, full):
        arr[i] = rnd.randrange(0, 0x80); write(ctrl - (i + 1) * stride, e.ljust(stride, b"\0"))
    for i in range(GROUP_WIDTH): arr[buckets + i] = arr[i] if buckets >= GROUP_WIDTH else 0xFF
    write(ctrl, bytes(arr)); return ctrl, buckets
east = table(32, 4, [string(f"east-{i}") + Q(i * 10) for i in range(3)])
west = table(32, 8, [string(f"west-{i}") + Q(i * 10) for i in range(5)])
def hmap(t, items): c, b = t; return Q(c, b - 1, 0, items) + Q(0x1111, 0x2222)   # RawTableInner + RandomState
nested = table(72, 4, [string("east") + hmap(east, 3), string("west") + hmap(west, 5)])
big = table(48, 128, [string(f"key-{i:03d}") + string(f"value-{i:03d}-" + "x" * (i % 7)) for i in range(70)])
ids = table(32, 32, [Q(1000 + 7 * i) + string(f"host-{i}") for i in range(20)])
blobs = table(48, 4, [string("iv") + string("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"), string("salt") + string("".join(chr(c) for c in range(32)))])
cfg = table(48, 4, [string("mode") + string("control"), string("targets") + string("docx,xlsx,pdf")])
regions.allocator = "nt"
fails = 0
for name, (c, b), want in (("big (String,String) 70/128", big, 48), ("ids (u64,String) 20/32", ids, 32), ("blobs (String,Vec<u8>) 2/4", blobs, 48), ("cfg (String,String) 2/4", cfg, 48), ("nested (String,HashMap) 2/4", nested, 72), ("east (String,u64) 3/4", east, 32)):
    got = infer_stride(read, regions, c, b)
    ok = got == (want, "content")
    fails += not ok
    print(("ok   " if ok else "FAIL ") + f"{name}: true stride {want}, inferred {got}")
blob_entry = read(blobs[0] - 48 * 4, 48 * 4)
from ferric.maps import read_entries, decode_entry
kinds = [tuple(f[0] for f in decode_entry(read, regions, d, a)) for _i, _h, d, a in read_entries(read, regions, blobs[0], blobs[1], 48, 8)]
ok = all(k[:2] == ("String", "Vec<u8>") for k in kinds) and len(kinds) == 2
fails += not ok
print(("ok   " if ok else "FAIL ") + f"Vec<u8> values typed without a glibc chunk: {kinds}")
# 0.5.2: a (u64, String) table next to a (String, String) table in one process, headers on a stack.
# Without a glibc chunk the u64 key also reads as the capacity of a String under the field order
# cap,len,ptr; the process-wide vote (the 70-entry table) must win over the 20-entry table's own vote.
from ferric.maps import scan_process
from ferric.strings import STACK
STK = BASE + 0x1F0000
regions2 = Regions([(BASE, STK, HEAP, "[heap]"), (STK, BASE + len(mem), STACK, "[stack]")])
regions2.allocator = "nt"
def header(at, t, items):
    c, b = t
    write(at, Q(c, b - 1, (b - 1) * 7 // 8 - items if b > 8 else b - 1 - items, items))
header(STK + 0x100, big, 70)
header(STK + 0x140, ids, 20)
rows = [r for _, r in scan_process(read, regions2, 1, "t")]
ids_rows = [r for r in rows if r[2] == "entry" and int(r[5]) == ids[0]]
texts = sorted(r[13] for r in ids_rows)
want = sorted(f'u64 {1000 + 7 * i} | String "host-{i}"' for i in range(20))
ok = len(ids_rows) == 20 and all(t.startswith("u64 ") and '| String "host-' in t for t in texts)
fails += not ok
print(("ok   " if ok else "FAIL ") + f"ids (u64,String) decoded as u64 + String under the process-wide order: {texts[:2]}")
ok = all(r[14] == "layout=cap,ptr,len" for r in ids_rows)
fails += not ok
print(("ok   " if ok else "FAIL ") + "ids entries carry the process layout cap,ptr,len, not their own minority reading")

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
