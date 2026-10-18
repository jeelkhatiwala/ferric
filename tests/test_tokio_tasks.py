#!/usr/bin/env python3
"""Unit tests for ferric.tokio v0.2 — pure, synthetic memory. Run:
  python3 tests/test_tokio_tasks.py   (needs volatility3 importable; pinned 2.28.2)

Lays out two ADJACENT 7-pointer task vtables with trailing offsets (the tokio >= 1.28 shape), task cells
in the heap whose Header holds the vtable pointer at +16, a stale copy on the stack, a freed cell, and a
5-pointer vtable (tokio 1.0 shape) whose cells keep the vtable pointer at +40. Checks discovery through
references (adjacency must not merge the tables), offset parsing, header validation at the right offset
only, state decoding, task ids, and String locals inside the future.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.tokio import (find_task_tables_by_refs, describe_offsets, header_at, decode_state,  # noqa: E402
                          scan_process, locals_in)
from ferric.strings import Regions, RODATA, EXEC, HEAP, STACK, glibc_chunk_expected  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

RO0, RO1 = 0x400000, 0x410000
TX0, TX1 = 0x500000, 0x510000
HP0, HP1 = 0x600000, 0x620000
ST0, ST1 = 0x7f0000, 0x7f4000
regions = Regions([(RO0, RO1, RODATA, "bin"), (TX0, TX1, EXEC, "bin"), (HP0, HP1, HEAP, "[heap]"), (ST0, ST1, STACK, "[stack]")])
mem = {RO0: bytearray(RO1 - RO0), HP0: bytearray(HP1 - HP0), ST0: bytearray(ST1 - ST0)}
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

# two adjacent task vtables (7 fns + offsets each), then a 5-fn vtable (1.0 shape)
VT_A = RO0 + 0x100
write(VT_A, Q(*[code(k) for k in range(7)]) + Q(0xe8, 0x20, 0x28))           # async tasks
VT_B = VT_A + 10 * 8
write(VT_B, Q(*[code(k) for k in range(7, 14)]) + Q(0x58, 0x20, 0x30))       # blocking tasks
VT_OLD = RO0 + 0x400
write(VT_OLD, Q(*[code(k) for k in range(20, 25)]) + Q(0, 8))                # tokio 1.0 shape, no offsets
check("describe_offsets parses (trailer, scheduler, id)", describe_offsets(struct.unpack("<10Q", read(VT_A, 80)), 0, 7, 10) == (0xe8, 0x20, 0x28))
check("describe_offsets accepts id_offset == scheduler_offset", describe_offsets((1,) * 7 + (0x48, 0x20, 0x20), 0, 7, 10) == (0x48, 0x20, 0x20))
check("describe_offsets rejects a non-header scheduler offset", describe_offsets((1,) * 7 + (0x48, 0x18, 0x20), 0, 7, 10) is None)

# heap cells for VT_A: Header{state, queue_next, vtable, owner_id} + scheduler + id + future(184 B) ...
bump = [HP0 + 0x1000]
def malloc(n):
    user = (bump[0] + 8 + 15) & ~15
    write(user - 8, Q(glibc_chunk_expected(n) | 1)); bump[0] = user + glibc_chunk_expected(n); return user
def string(text):
    b = text.encode(); p = malloc(len(b)); write(p, b); return Q(len(b), p, len(b))
cells = []
for i in range(4):
    cell = malloc(0xe8 + 0x40)
    state = (3 << 6) | 8                                  # refs 3 + JOIN_INTEREST  = 0xC8
    write(cell, Q(state, 0, VT_A, 1) + Q(HP0 + 0x10) + Q(3 + i))   # header, scheduler ptr, task id
    write(cell + 0x30, string(f"worker-{i}") + Q(0xdeadbeef))     # a String local inside the future
    cells.append(cell)
# a stale copy of a cell on the stack (initial state 0xCC)
write(ST0 + 0x200, Q(0xCC, 0, VT_A, 0, HP0 + 0x10, 6))
# a freed cell: refs 0
freed = malloc(0xe8 + 0x40); write(freed, Q(0, 0, VT_A, 0))
# two blocking cells for VT_B
for i in range(2):
    cell = malloc(0x80)
    write(cell, Q((2 << 6) | 1, 0, VT_B, 0) + Q(0) + Q(0) + Q(1 + i))   # scheduler ZST at 0x20, id at 0x30
# old-layout cells for VT_OLD: Header{state, owned.prev, owned.next, queue_next, stack_next, vtable}, then the
# 1.0 scheduler Arc. Three cells linked through the OwnedTasks list (0.3.0 reads the back-links), one lone
# cell (null links, accepted once the table has list evidence), one cell whose next link is not reciprocated
# (rejected: that is what the Go runtime's look-alikes do).
old_cells = [malloc(0x100) for _ in range(5)]
O1, O2, O3, O4, O5 = old_cells
sched_arc = HP0 + 0x20
write(O1, Q((4 << 6) | 8, 0, O2, 0, 0, VT_OLD, sched_arc))
write(O2, Q((4 << 6) | 8, O1, O3, 0, 0, VT_OLD, sched_arc))
write(O3, Q((4 << 6) | 8, O2, 0, 0, 0, VT_OLD, sched_arc))
write(O4, Q((4 << 6) | 8, 0, 0, 0, 0, VT_OLD, sched_arc))
write(O5, Q((4 << 6) | 8, 0, O1, 0, 0, VT_OLD, sched_arc))          # claims O1 follows it; O1.prev is null
# the 1.28+ cells: link cells[0] <-> cells[1] through the trailer (trailer_offset 0xe8), the rest stay lone
write(cells[0] + 0xe8, Q(0, cells[1])); write(cells[1] + 0xe8, Q(cells[0], 0))

tables, refs = find_task_tables_by_refs(read, regions)
check("both adjacent tables found separately", VT_A in tables and VT_B in tables)
check("adjacent tables are 7-pointer runs with their own offsets", tables[VT_A] == (7, (0xe8, 0x20, 0x28)) and tables[VT_B] == (7, (0x58, 0x20, 0x30)))
check("old 5-pointer table found with no offsets", tables.get(VT_OLD) == (5, None))
check("references collected per table (4 heap + 1 stack + 1 freed for A)", len(refs[VT_A]) == 6)

check("header_at validates at +16 for the new layout", header_at(read, regions, cells[0] + 16, 16) is not None)
check("header_at rejects +32 for the new layout (state would be the chunk size)", header_at(read, regions, cells[0] + 16, 32) is None)
check("decode_state 0xC8 -> refs 3, join-interest", decode_state(0xC8) == (3, ["join-interest"]))
check("decode_state 0x81 -> refs 2, running", decode_state(0x81) == (2, ["running"]))
check("locals_in finds the String inside the future", locals_in(read, regions, cells[1] + 0x30, 0xb8) == ["worker-1"])

rows = [r for _, r in scan_process(read, regions, 1, "t")]
vt = [r for r in rows if r[2] == "vtable"]; tasks = [r for r in rows if r[2] == "task"]
stale = [r for r in rows if r[2] == "stale"]; rem = [r for r in rows if r[2] == "remnant"]
check("three vtable rows", len(vt) == 3)
a_row = [r for r in vt if int(r[3]) == VT_A][0]
check("VT_A: 4 live tasks, 1 stale, 1 remnant", a_row[8] == "live=4 stale=1 remnant=1" and a_row[9] == 4)
a_tasks = sorted(r for r in tasks if int(r[3]) == VT_A)
check("task ids 3..6 recovered", sorted(r[10] for r in a_tasks) == [3, 4, 5, 6])
check("task flags and refs decoded", all(r[8] == "join-interest" and r[9] == 3 for r in a_tasks))
check("future size = trailer - (id_offset + 8) = 184", all(r[13] == 0xe8 - 0x30 for r in a_tasks))
check("String locals attributed to each task", sorted(r[14] for r in a_tasks) == ['"worker-0"', '"worker-1"', '"worker-2"', '"worker-3"'])
b_tasks = [r for r in tasks if int(r[3]) == VT_B]
check("blocking tasks: 2 running, ids 1 and 2", len(b_tasks) == 2 and sorted(r[10] for r in b_tasks) == [1, 2] and all(r[8] == "running" for r in b_tasks))
old_row = [r for r in vt if int(r[3]) == VT_OLD][0]
check("old layout: vtable found at header+40 with 4 live tasks (3 linked + 1 lone); the bad-link cell is a remnant",
      "header+40" in old_row[15] and old_row[9] == 4 and old_row[8] == "live=4 stale=0 remnant=1")
old_tasks = [r for r in tasks if int(r[3]) == VT_OLD]
check("old-layout task notes carry the list status", sorted(r[15].split("list=")[1] for r in old_tasks) == ["linked", "linked", "linked", "lone"])
check("1.28+ cells: the trailer-linked pair reads 'linked', the others 'lone'", sorted(r[15].split("list=")[1] for r in a_tasks) == ["linked", "linked", "lone", "lone"])
check("remnant rows: the freed cell and the bad-link cell", len(rem) == 2)
check("stale row carries the initial state 0xCC", len(stale) == 1 and int(stale[0][7]) == 0xCC)

# a referenced code-pointer table that fronts no task header (a RawWakerVTable, a C ops table): hidden by
# default, shown as 'candidate' only when asked (negative-control images show 3 per image, all non-Rust)
VT_WAKER = RO0 + 0x600
write(VT_WAKER, Q(*[code(k) for k in range(30, 35)]) + Q(0, 0))   # 5 code pointers, then zeros
write(HP0 + 0x7000, Q(VT_WAKER))                      # one heap word references it; no header anywhere
rows_default = [r for _, r in scan_process(read, regions, 1, "t")]
rows_cand = [r for _, r in scan_process(read, regions, 1, "t", candidates=True)]
check("candidate tables hidden by default", not any(r[2] == "candidate" for r in rows_default))
check("--candidates shows the non-task table once, as kind=candidate", sum(1 for r in rows_cand if r[2] == "candidate" and int(r[3]) == VT_WAKER) == 1)
check("task rows unchanged either way", [int(r[6]) for r in rows_default if r[2] == "task"] == [int(r[6]) for r in rows_cand if r[2] == "task"])

# 0.3.0: the checks that remove the Go runtime's look-alikes (Session 71 negative control: 15 "tasks" whose
# state words were data-segment addresses, ref counts 74k-89k, owner words pointing into the data segment)
from ferric.tokio import validate_header  # noqa: E402
VT_LEG = RO0 + 0x700
write(VT_LEG, Q(*[code(k) for k in range(40, 46)]) + Q(0, 0))     # 6-pointer run: 1.1-1.19 shape, no offsets
def legacy_cell(state, after=0, prev=0, nxt=0):
    c = malloc(0x100); write(c, Q(state, prev, nxt, 0, VT_LEG, after)); return c      # vtable at +32
g1 = legacy_cell(RO0 + 0x10)                                  # state = an address inside the binary
g2 = legacy_cell((74893 << 6) | 32)                           # refs 74,893
g3 = legacy_cell((4 << 6) | 1, after=RO0 + 0x8)               # 0x101 with a data-segment "owner" word
g4 = legacy_cell((2 << 6) | 1 | 2)                            # RUNNING and COMPLETE together
g5 = legacy_cell((4 << 6) | 1, after=HP0 + 0x40)              # a plausible 1.1-1.7 cell (scheduler Arc on the heap), lone
check("state that is a mapped address is rejected", validate_header(read, regions, g1 + 32, 32)[1] == "state is a mapped address")
check("ref count 74,893 is rejected", validate_header(read, regions, g2 + 32, 32)[1] == "refs=74893")
check("owner word pointing into the data segment is rejected at +32", validate_header(read, regions, g3 + 32, 32)[1].startswith("owner/scheduler word="))
check("RUNNING together with COMPLETE is rejected", validate_header(read, regions, g4 + 32, 32)[1] == "running+complete")
check("a plausible lone legacy cell validates with links=lone", validate_header(read, regions, g5 + 32, 32)[0][4] == "lone")
rows_d = [r for _, r in scan_process(read, regions, 1, "t")]
rows_c = [r for _, r in scan_process(read, regions, 1, "t", candidates=True)]
check("a legacy table with only a lone cell is not a vtable row", not any(int(r[3]) == VT_LEG for r in rows_d))
cand = [r for r in rows_c if r[2] == "candidate" and int(r[3]) == VT_LEG]
check("--candidates shows it with the rejection histogram", len(cand) == 1 and "no owned-list link" in cand[0][8] and "refs=74893 x1" in cand[0][15] and "state is a mapped address x1" in cand[0][15])
check("the other tables are unaffected", sum(1 for r in rows_d if r[2] == "vtable") == 3)

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
