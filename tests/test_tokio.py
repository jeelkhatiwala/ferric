#!/usr/bin/env python3
"""Unit tests for ferric.tokio — pure, no memory image. Run:
  python3 tests/test_tokio.py   (needs volatility3 importable; pinned 2.28.2)

Synthetic memory: a run of 8 code pointers in read-only data (a tokio-style task Vtable), a too-short run
that must be ignored, a trait-object-shaped table that must be ignored, and three heap words pointing at
the 8-run (the live-task proxy).
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.tokio import find_fn_tables, count_refs, looks_like_trait_vtable, MIN_FNS  # noqa: E402
from ferric.strings import Regions, RODATA, EXEC, HEAP  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

RO0, RO1 = 0x400000, 0x410000
TX0, TX1 = 0x500000, 0x510000
HP0, HP1 = 0x600000, 0x610000
regions = Regions([(RO0, RO1, RODATA, "bin"), (TX0, TX1, EXEC, "bin"), (HP0, HP1, HEAP, "[heap]")])

mem = {RO0: bytearray(RO1 - RO0), HP0: bytearray(HP1 - HP0)}
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
Q = lambda *v: struct.pack("<" + "Q" * len(v), *v)
code = lambda k: TX0 + 0x10 * (k + 1)

check("MIN_FNS run threshold is >= 5", MIN_FNS >= 5)

# an 8-pointer task-vtable-shaped run, isolated by non-code words
T = RO0 + 0x2000
write(T - 8, Q(0))
write(T, Q(*[code(k) for k in range(8)]))
write(T + 64, Q(0))

# a too-short run (3 pointers) that must not qualify
SHORT = RO0 + 0x3000
write(SHORT - 8, Q(0))
write(SHORT, Q(code(0), code(1), code(2)))
write(SHORT + 24, Q(0))

# a trait-object vtable shape: [drop, size, align, m0, m1] -- words[1],[2] are size/align, not code ptrs
U = RO0 + 0x4000
write(U, Q(code(0), 24, 8, code(1), code(2), 0))
check("trait-vtable shape recognised (and thus skipped by tokio)",
      looks_like_trait_vtable(regions, [code(0), 24, 8, code(1), code(2), 0], 0, 6))

tables = find_fn_tables(read, regions)
check("the 8-pointer table is found", tables.get(T) == 8)
check("the 3-pointer run is ignored (below MIN_FNS)", SHORT not in tables)
check("the trait-vtable shape is not reported as a tokio table", U not in tables)

# three heap words point at T (three live tasks); one decoy points elsewhere
write(HP0 + 0x100, Q(T))
write(HP0 + 0x108, Q(T))
write(HP0 + 0x200, Q(T))
write(HP0 + 0x208, Q(0x99999))
refs = count_refs(read, regions, set(tables))
check("count_refs counts the three live references to the task vtable", refs.get(T) == 3)

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
