#!/usr/bin/env python3
"""Unit tests for ferric.vtables — pure, no memory image. Run:
  python3 tests/test_vtables.py   (needs volatility3 importable; pinned 2.28.2)

Synthetic memory: a vtable in read-only data ([drop, size, align, method, method]) with the drop glue and
methods pointing into an executable region, plus two fat pointers in the heap referencing it.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.vtables import classify_vtable, find_vtables, count_objects, module_base, scan_process, COLUMNS  # noqa: E402
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

DROP, M0, M1 = TX0 + 0x10, TX0 + 0x100, TX0 + 0x200

# classify_vtable on explicit word lists (regions resolves which words are code pointers)
check("valid vtable: size 24 align 8, 2 methods",
      classify_vtable(regions, [DROP, 24, 8, M0, M1, 0], 0, 6) == (24, 8, 2, DROP))
check("align not power of two rejected",
      classify_vtable(regions, [DROP, 24, 3, M0, M1, 0], 0, 6) is None)
check("size not a multiple of align rejected",
      classify_vtable(regions, [DROP, 12, 8, M0, M1, 0], 0, 6) is None)
check("drop not into executable memory rejected",
      classify_vtable(regions, [HP0 + 8, 24, 8, M0, M1, 0], 0, 6) is None)
check("no trait methods rejected",
      classify_vtable(regions, [DROP, 24, 8, 0, 0, 0], 0, 6) is None)
check("ZST trait object (size 0, align 1) accepted",
      classify_vtable(regions, [DROP, 0, 1, M0, 0], 0, 5) == (0, 1, 1, DROP))

# whole-region scan: one vtable at V, methods then a non-code terminator
V = RO0 + 0x2000
write(V, Q(DROP, 24, 8, M0, M1))
write(V + 40, Q(0))                       # terminator (not a code pointer)
vts = find_vtables(read, regions)
check("find_vtables locates the vtable exactly once", list(vts) == [V] and vts[V] == (24, 8, 2, DROP))

# object counting: two fat pointers (data in heap, vtable = V); one decoy whose 2nd word is not a vtable
write(HP0 + 0x80, Q(HP0 + 0x800, V))      # Box<dyn Trait> #1
write(HP0 + 0x90, Q(HP0 + 0x900, V))      # Box<dyn Trait> #2
write(HP0 + 0xA0, Q(HP0 + 0xA00, 0x1234))  # not a trait object
refs = count_objects(read, regions, set(vts))
check("count_objects counts exactly the two live trait objects", refs.get(V) == 2)

# v0.2 forms, through the plugin's own row generator
#   V2: null drop, no drop glue, 1 method, referenced by a RIP-relative LEA in code -> reported
#   V3: null drop, nothing references it -> gated out unless all_candidates
#   both sit apart from V so V's method run is unaffected
V2 = RO0 + 0x3000; write(V2, Q(0, 8, 8, M0)); write(V2 + 32, Q(0))
V3 = RO0 + 0x3100; write(V3, Q(0, 16, 8, M1)); write(V3 + 32, Q(0))
# lea rdi, [rip + disp32] at TX0+0x300 targeting V2: 48 8d 3d <disp32>; target = next_ip + disp
LEA = TX0 + 0x300
disp = V2 - (LEA + 7)
mem[TX0] = bytearray(TX1 - TX0)
write(LEA, b"\x48\x8d\x3d" + struct.pack("<i", disp))
rows = [r for _, r in scan_process(read, regions, 7, "t", objects=True)]
check("rows have one cell per COLUMNS entry", all(len(r) == len(COLUMNS) for r in rows))
by = {int(r[2]): r for r in rows}
check("fn-drop vtable V reported with Refs=2 (objects), CodeRefs=0", int(by[V][2]) == V and by[V][4] == "fn" and by[V][10] == 2 and by[V][9] == 0)
check("null-drop vtable with a code reference is reported (Drop=null, CodeRefs=1)", V2 in by and by[V2][4] == "null" and by[V2][9] == 1)
check("null-drop vtable nobody references is gated out", V3 not in by)
check("--all-candidates lifts the gate", V3 in {int(r[2]) for _, r in scan_process(read, regions, 7, "t", all_candidates=True)})
check("Module/Base columns: backing file 'bin' and its lowest mapping", by[V][12] == "bin" and int(by[V][13]) == RO0)
check("Refs/StackRefs render as absent without --objects", str(type([r for _, r in scan_process(read, regions, 7, "t")][0][10]).__name__) == "NotAvailableValue")

# v0.2.2: a vtable in the executable's WRITABLE file-backed data (static-pie musl leaves .data.rel.ro
# unprotected) is found when the scan knows which module is the executable; a library's data is not scanned
from ferric.strings import DATA  # noqa: E402
DT0, DT1 = 0x700000, 0x701000
LB0, LB1 = 0x710000, 0x711000
r3 = Regions([(RO0, RO1, RODATA, "bin"), (TX0, TX1, EXEC, "bin"), (HP0, HP1, HEAP, "[heap]"),
              (DT0, DT1, DATA, "bin"), (LB0, LB1, DATA, "libc.so.6")])
mem[DT0] = bytearray(DT1 - DT0); mem[LB0] = bytearray(LB1 - LB0)
write(DT0 + 0x40, Q(DROP, 24, 8, M0, M1, 0))      # vtable in the exe's writable data
write(LB0 + 0x40, Q(DROP, 24, 8, M0, M1, 0))      # same bytes in a library's writable data
found = find_vtables(read, r3, exe="bin")
check("exe writable data scanned when exe is named (musl static-pie case)", DT0 + 0x40 in found and V in found)
check("library writable data is never scanned", LB0 + 0x40 not in found)
check("without an exe name only read-only data is scanned (v0.2.1 behaviour)", DT0 + 0x40 not in find_vtables(read, r3))
check("VTableIn reports 'data' for such a row (when referenced)", any(r[3] == "data" for _, r in scan_process(read, r3, 7, "t", exe="bin", all_candidates=True)))
# v0.2.3: in writable data a candidate needs a reference (C function-pointer tables live there too)
check("unreferenced candidate in writable data is gated out", not any(int(r[2]) == DT0 + 0x40 for _, r in scan_process(read, r3, 7, "t", exe="bin")))
LEA2 = TX0 + 0x400
write(LEA2, b"\x48\x8d\x3d" + struct.pack("<i", (DT0 + 0x40) - (LEA2 + 7)))
check("the same candidate is reported once code references it", any(int(r[2]) == DT0 + 0x40 and r[9] == 1 for _, r in scan_process(read, r3, 7, "t", exe="bin")))

# v0.2.4: a lone code pointer right after a vtable is a separate object when code addresses it directly
from ferric.vtables import lea_targets  # noqa: E402
V4 = RO0 + 0x5000
write(V4, Q(DROP, 40, 8, M0, M1, M0))             # a 2-method vtable followed by a lone fn pointer (M0)
write(V4 + 48, Q(0))
check("without boundaries the lone pointer is counted as a third method (the s3sweep-04 Triangle case)",
      classify_vtable(regions, struct.unpack("<7Q", read(V4, 56)), 0, 7, V4) == (40, 8, 3, DROP))
LEA3 = TX0 + 0x500
write(LEA3, b"\x48\x8d\x05" + struct.pack("<i", (V4 + 40) - (LEA3 + 7)))   # lea rax, [rip + (V4+40)]
leas = lea_targets(read, regions)
check("lea_targets collects the referenced address with its count", leas.get(V4 + 40) == 1)
check("with boundaries the run ends at the referenced address: 2 methods",
      classify_vtable(regions, struct.unpack("<7Q", read(V4, 56)), 0, 7, V4, set(leas)) == (40, 8, 2, DROP))
check("scan_process reports 2 methods for it", any(int(r[2]) == V4 and r[8] == 2 for _, r in scan_process(read, regions, 7, "t")))

# module/base: the two "bin" VMAs share a backing name, so the base is the lowest of them (the rodata one)
check("module_base names the backing file and its lowest mapping", module_base(regions, RO0 + 0x100) == ("bin", RO0))
check("module_base is ('', 0) for anonymous memory", module_base(regions, HP0 + 0x10) == ("", 0))
r2 = Regions([(0x7f0000000, 0x7f0001000, RODATA, "/usr/lib/libx.so"), (0x7f0001000, 0x7f0002000, EXEC, "/usr/lib/libx.so"),
              (0x555555554000, 0x555555555000, EXEC, "/opt/app/seed"), (0x555555556000, 0x555555557000, RODATA, "/opt/app/seed")])
check("module_base keys by path, reports the basename, lowest start per module",
      module_base(r2, 0x555555556010) == ("seed", 0x555555554000) and module_base(r2, 0x7f0001010) == ("libx.so", 0x7f0000000))

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
