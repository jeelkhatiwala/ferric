#!/usr/bin/env python3
"""Unit tests for ferric.maps — pure, no memory image. Run:
  python3 tests/test_maps_validate.py   (needs volatility3 importable; pinned 2.28.2)

v0.2/v0.3 properties tested:
  * the hashbrown invariant: a live table always has >= 1 EMPTY bucket, so items == capacity is rejected
    (the false positive v0.1 reported on real malware at "100% load");
  * field-order independence: scan_window recovers a table whatever permutation the four RawTableInner
    words appear in, because ctrl is found by "points into memory" and items by the control-byte count;
  * the replication signature (v0.3): the control array's leading group is echoed at its tail; a region
    without that echo (ordinary C/Python heap, the systemd/python3 false positives measured on a real
    image) is rejected even when the numbers line up.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.maps import (validate_table, scan_window, read_ctrl, usable_capacity, mirror_ok,  # noqa: E402
                         iter_candidates, popcount_full, GROUP_WIDTH)
from ferric.strings import Regions, HEAP  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

# ---- synthetic memory ---------------------------------------------------------
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
region(0x100000, 0x140000)                 # heap
regions = Regions([(0x100000, 0x140000, HEAP, "[heap]")])
Q = lambda *v: struct.pack("<" + "Q" * len(v), *v)

def ctrl_array(slots):
    """Lay out a real hashbrown control array (buckets + GROUP_WIDTH) with the trailing group replicated,
    exactly as hashbrown maintains it, from the `buckets` real control bytes in `slots`."""
    buckets, w = len(slots), GROUP_WIDTH
    arr = bytearray(buckets + w)
    for i, b in enumerate(slots):
        arr[i] = b
    if buckets >= w:
        for i in range(w):
            arr[buckets + i] = arr[i]
    else:
        for i in range(buckets, w):
            arr[i] = 0xFF
        for i in range(buckets):
            arr[w + i] = slots[i]
    return bytes(arr)

def write_ctrl(addr, slots):
    write(addr, ctrl_array(slots))

check("usable_capacity: mask<8 -> mask", (usable_capacity(3), usable_capacity(7)) == (3, 7))
check("usable_capacity: mask>=8 -> (mask+1)/8*7", (usable_capacity(15), usable_capacity(31)) == (14, 28))
check("mirror_ok accepts a correct sub-group array",
      mirror_ok(ctrl_array([0x12, 0xFF, 0x7a, 0x80, 0xFF, 0x05, 0xFF, 0xFF]), 8))
check("mirror_ok rejects a non-replicated tail",
      not mirror_ok(bytes([1, 2, 3, 4, 5, 6, 7, 0xFF]) + b"\x00" * GROUP_WIDTH, 8))

# a table: capacity 8, items 3, 1 deleted, 4 empty. 3 FULL (hash<0x80), 1 DELETED (0x80), rest EMPTY(0xFF)
CTRL = 0x110000
write_ctrl(CTRL, [0x12, 0xFF, 0x7a, 0x80, 0xFF, 0x05, 0xFF, 0xFF])
check("popcount: 3 full / 1 deleted", popcount_full(read(CTRL, 8)) == (3, 1))

# validate_table keeps SOURCE order (bucket_mask, ctrl, growth_left, items)
v = validate_table(read, regions, (7, CTRL, 2, 3))
check("valid table accepted", v is not None)
check("capacity 8, items 3, deleted 1", v and v[0] == 8 and v[1] == 3 and v[3] == 1)

# negatives via validate_table
check("bucket_mask not 2^k-1 rejected", validate_table(read, regions, (6, CTRL, 2, 3)) is None)
check("empty singleton (cap 1) rejected", validate_table(read, regions, (0, CTRL, 0, 0)) is None)
check("items disagrees with control bytes rejected", validate_table(read, regions, (7, CTRL, 2, 4)) is None)
check("ctrl not in a readable region rejected", validate_table(read, regions, (7, 0xDEAD0000, 2, 3)) is None)
check("growth_left > usable rejected", validate_table(read, regions, (7, CTRL, 99, 3)) is None)

# THE v0.2 invariant: a table with no EMPTY bucket is not a real hashbrown table.
CTRLF = 0x111000
write_ctrl(CTRLF, [0x01, 0x02, 0x03, 0x04])                 # capacity 4, all FULL, 0 empty
check("full table (no empty bucket) rejected by validate_table",
      validate_table(read, regions, (3, CTRLF, 0, 4)) is None)
acc, _ = scan_window(read, regions, (3, CTRLF, 0, 4))
check("full table (100% load) produces NO accepted row (the BlackCat false positive)", acc == [])

# THE v0.3 signature: numbers line up but the control array's tail does not replicate the head ->
# this is exactly the systemd/python3 shape on a real image. Must be rejected.
CTRLBAD = 0x111800
write(CTRLBAD, bytes([0x12, 0xFF, 0x7a, 0x80, 0xFF, 0x05, 0xFF, 0xFF]) + b"\x00" * GROUP_WIDTH)
check("non-replicated control tail rejected (the non-Rust-heap false positive)",
      validate_table(read, regions, (7, CTRLBAD, 2, 3) ) is None)
check("read_ctrl returns None when replication fails", read_ctrl(read, regions, CTRLBAD, 7) is None)

# FIELD-ORDER INDEPENDENCE: ctrl not first, fields permuted. capacity 16, items 5, 1 deleted, 10 empty.
CTRL3 = 0x112000
write_ctrl(CTRL3, [0x01, 0x02, 0x03, 0x04, 0x05] + [0xFF] * 10 + [0x80])
# memory order here: (bucket_mask=15, growth_left=1, ctrl=CTRL3, items=5) -- a non-source permutation
acc, _ = scan_window(read, regions, (15, 1, CTRL3, 5))
check("permuted header (ctrl in slot 2) recovered",
      any(cap == 16 and items == 5 and deleted == 1 and ctrl == CTRL3
          for (cap, items, gl, deleted, ctrl, usable, gl_ok) in acc))
acc2, _ = scan_window(read, regions, (15, CTRL3, 1, 5))
check("source-ordered header recovered",
      any(cap == 16 and items == 5 for (cap, items, *_rest) in acc2))

# read_ctrl surfaces the control-byte facts independent of any header
facts = read_ctrl(read, regions, CTRL3, 15)
check("read_ctrl: cap16 full5 del1 empty10", facts == (16, 14, 5, 1, 10))

# --explain surfaces a no-empty near-miss (full in range) rather than silently dropping it
CTRLND = 0x112800
write_ctrl(CTRLND, [1, 2, 3, 4, 5, 6, 7, 0x80])             # 7 full + 1 tombstone, 0 empty
check("no-empty table rejected", validate_table(read, regions, (7, CTRLND, 0, 7)) is None)
_, near = scan_window(read, regions, (7, CTRLND, 0, 7), explain=True)
check("explain surfaces the no-empty near-miss",
      any(ctrl == CTRLND and empty == 0 for (ctrl, cap, full, deleted, empty, rest) in near))

# iter_candidates finds the header 4-tuple and handles window boundaries
HDR = 0x120000
write(HDR, Q(7, CTRL, 2, 3))
got = [(a, w0, w1, w2, w3) for a, w0, w1, w2, w3 in iter_candidates(read, 0x120000, 0x120040, window=64, overlap=32)
       if (w0, w1, w2, w3) == (7, CTRL, 2, 3)]
check("iter_candidates surfaces the header window", len(got) == 1 and got[0][0] == HDR)

region(0x200000, 0x200000 + 3 * 4096)      # separate region for the boundary test
write(0x200000 + 4096 - 16, Q(7, CTRL, 2, 3))     # 32-byte header straddling the 4096 boundary
hits = [a for a, *w in iter_candidates(read, 0x200000, 0x200000 + 3 * 4096, window=4096, overlap=32)
        if tuple(w) == (7, CTRL, 2, 3)]
check("straddling header seen exactly once", hits == [0x200000 + 4096 - 16])

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
