#!/usr/bin/env python3
"""Unit tests for ferric.maps v0.4 entry recovery — pure, synthetic memory. Run:
  python3 tests/test_maps_entries.py   (needs volatility3 importable; pinned 2.28.2)

Builds a glibc-shaped heap by hand: a hashbrown allocation (data buckets, then control bytes with the
replicated group) behind an 8-byte malloc size field, String payload chunks, and a 4-word RawTableInner
header in a permuted field order. Checks stride inference by chunk and by content, typed decoding of
(String,String), (u64,String) and (String,Vec<u8>) entries, the nested-table cross reference, and that
scan_process emits one 'table' row plus one 'entry' row per FULL bucket with the gl-corroborated header.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.maps import (block_len, stride_by_chunk, infer_stride, read_entries, decode_entry,  # noqa: E402
                         scan_process, render_fields, GROUP_WIDTH)
from ferric.strings import Regions, HEAP, STACK, glibc_chunk_expected  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

mem = {}
def region(a, b): mem[a] = bytearray(b - a)
def write(a, b):
    for s, buf in mem.items():
        if s <= a < s + len(buf): buf[a - s:a - s + len(b)] = b; return
    raise ValueError(hex(a))
def read(a, n):
    out = bytearray(n)
    for s, buf in mem.items():
        lo, hi = max(a, s), min(a + n, s + len(buf))
        if lo < hi: out[lo - a:hi - a] = buf[lo - s:hi - s]
    return bytes(out)
HEAP0, HEAP1 = 0x100000, 0x140000
STK0, STK1 = 0x7f0000, 0x7f4000
region(HEAP0, HEAP1); region(STK0, STK1)
regions = Regions([(HEAP0, HEAP1, HEAP, "[heap]"), (STK0, STK1, STACK, "[stack]")])
Q = lambda *v: struct.pack("<" + "Q" * len(v), *v)

bump = [HEAP0 + 0x100]
def malloc(n):
    """glibc-style: size field (with the in-use bit) 8 bytes before a 16-aligned user pointer."""
    user = (bump[0] + 8 + 15) & ~15
    size = glibc_chunk_expected(n)
    write(user - 8, Q(size | 1))
    bump[0] = user + size
    return user

def string(text, cap=None):
    b = text.encode(); cap = cap or len(b)
    p = malloc(cap); write(p, b)
    return Q(cap, p, len(b))                     # measured rustc >= 1.77 order: cap, ptr, len

def table(stride, slots, entries):
    """Allocate a hashbrown block for `len(slots)` buckets; entries[i] = bytes for FULL bucket i."""
    buckets = len(slots)
    ctrl_offset, total = block_len(stride, buckets)
    base = malloc(total)
    ctrl = base + ctrl_offset
    arr = bytearray(buckets + GROUP_WIDTH)
    for i, b in enumerate(slots): arr[i] = b
    if buckets >= GROUP_WIDTH:
        for i in range(GROUP_WIDTH): arr[buckets + i] = arr[i]
    else:
        for i in range(buckets, GROUP_WIDTH): arr[i] = 0xFF
        for i in range(buckets): arr[GROUP_WIDTH + i] = slots[i]
    write(ctrl, bytes(arr))
    for i, e in entries.items():
        write(ctrl - (i + 1) * stride, e.ljust(stride, b"\0"))
    return ctrl

# ---- table A: HashMap<String,String>, 4 buckets, 2 full, stride 48 ---------------------------------
ctrlA = table(48, [0x12, 0xFF, 0x7a, 0xFF], {0: string("mode") + string("control"), 2: string("targets") + string("docx,xlsx,pdf")})
check("block_len: stride 48 x 4 buckets -> ctrl at 192, block 212 bytes", block_len(48, 4) == (192, 212))
check("stride_by_chunk pins 48", stride_by_chunk(read, regions, ctrlA, 4) == 48)
check("infer_stride -> (48, chunk)", infer_stride(read, regions, ctrlA, 4) == (48, "chunk"))
ents = list(read_entries(read, regions, ctrlA, 4, 48))
check("read_entries yields the 2 FULL buckets with their h2 tags", [(i, h) for i, h, _d, _a in ents] == [(0, 0x12), (2, 0x7a)])
f = decode_entry(read, regions, ents[0][2], ents[0][3])
check("entry 0 decodes as String,String", [x[0] for x in f] == ["String", "String"] and (f[0][2], f[1][2]) == ("mode", "control"))
check("render: String \"mode\" | String \"control\"", render_fields(f) == 'String "mode" | String "control"')
check("String fields carry the chunk check", "chunk" in f[0][6])

# header on the stack in a NON-source permutation: (items, growth_left, ctrl, bucket_mask)
HDR = STK0 + 0x100
write(HDR, Q(2, 1, ctrlA, 3))
rows = [r for _, r in scan_process(read, regions, 1, "t")]
tabs = [r for r in rows if r[2] == "table"]; ers = [r for r in rows if r[2] == "entry"]
check("scan_process: one table row", len(tabs) == 1 and int(tabs[0][3]) == HDR and tabs[0][7] == 2)
check("scan_process: stride column 48, note says chunk", tabs[0][10] == 48 and "stride=48:chunk" in tabs[0][14])
check("scan_process: two entry rows, buckets 0 and 2", sorted(r[11] for r in ers) == [0, 2])
check("entry rows carry the decoded fields", any('String "targets" | String "docx,xlsx,pdf"' == r[13] for r in ers))

# a SHIFTED window of the same ctrl exists two words earlier when the preceding words happen to fit:
# (x, items=2, growth_left=1... ) the gl-corroborated window must win and be reported as the header
write(HDR - 16, Q(2, 0))                       # words[-2..-1] = 2, 0 -> (items=2 at -2, gl=0 at -1, ctrl, mask) also accepts
rows = [r for _, r in scan_process(read, regions, 1, "t")]
tabs = [r for r in rows if r[2] == "table"]
check("gl-corroborated header wins over an earlier shifted window", len(tabs) == 1 and int(tabs[0][3]) == HDR and " gl " in tabs[0][14] + " ")

# ---- table B: HashMap<u64,String>, stride 32 ------------------------------------------------------
ctrlB = table(32, [0x05, 0xFF, 0xFF, 0x33], {0: Q(1000) + string("host-0"), 3: Q(1007) + string("host-1")})
check("stride_by_chunk pins 32 for (u64,String)", stride_by_chunk(read, regions, ctrlB, 4) == 32)
f = decode_entry(read, regions, list(read_entries(read, regions, ctrlB, 4, 32))[0][2], 0)
check("(u64,String) decodes as u64 1000 | String host-0", render_fields(f) == 'u64 1000 | String "host-0"')

# ---- table C: HashMap<String,Vec<u8>> ------------------------------------------------------------
blob = malloc(12); write(blob, bytes(range(1, 13)))
ctrlC = table(48, [0x4d, 0xFF, 0xFF, 0xFF], {0: string("iv") + Q(12, blob, 12)})
f = decode_entry(read, regions, list(read_entries(read, regions, ctrlC, 4, 48))[0][2], 0)
check("Vec<u8> value rendered as bytes", render_fields(f) == 'String "iv" | Vec<u8>[12] 0102030405060708090a0b0c')

# ---- nested: an entry holding another table's RawTableInner is labelled by cross reference ---------
inner = Q(ctrlB, 3, 1, 2, 0xdead, 0xbeef)
f = decode_entry(read, regions, string("east") + inner, 0, tables={ctrlB: 2})
check("nested RawTableInner cross-referenced as HashMap", f[1][0] == "HashMap" and f"ctrl={ctrlB:#x} items=2" in f[1][2])
# 0.4.1: the 1.71 field order (ctrl, bucket_mask, growth_left, items) with printable control bytes used to read as
# String (ptr=ctrl, cap=mask, len=growth_left); the cross reference now wins (s5sweep-01 'west': 1/2 -> 2/2)
ctrlP = table(32, [0x4c, 0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], {0: Q(1, 2, 3, 4)})      # ctrl bytes "L`" printable
inner171 = Q(ctrlP, 7, 2, 5)
f = decode_entry(read, regions, string("west") + inner171, 0, tables={ctrlP: 5})
check("1.71-order nested table with printable ctrl bytes is a HashMap, not a String", f[1][0] == "HashMap" and f"ctrl={ctrlP:#x} items=5" in f[1][2])
f = decode_entry(read, regions, string("west") + inner171, 0)
check("without the cross reference the same words still read as before (String or raw)", f[0][0] == "String" and f[0][2] == "west")
f = decode_entry(read, regions, string("foo") + Q(ctrlP, 7, 2, 5), 0, tables={ctrlP: 5})
check("a 3-byte String key followed by a nested table is still String then HashMap (ctrl must lead the struct)",
      f[0][0] == "String" and f[0][2] == "foo" and f[1][0] == "HashMap")
f = decode_entry(read, regions, string("west") + Q(7, ctrlP, 2, 5), 0, tables={ctrlP: 5})
check("declared field order (mask, ctrl, growth, items) is also recognised", f[1][0] == "HashMap")

# ---- no chunk field (musl/jemalloc): content decides -----------------------------------------------
ctrlD = table(48, [0x12, 0xFF, 0xFF, 0xFF], {0: string("k") + string("v")})
write(ctrlD - block_len(48, 4)[0] - 8, Q(0))   # wipe the size field: no allocator corroboration
st, how = infer_stride(read, regions, ctrlD, 4)
check("without a chunk field the stride comes from content", (st, how) == (48, "content"))

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
