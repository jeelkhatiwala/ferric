#!/usr/bin/env python3
"""D-023: &str and panic Location recovered from a merged-text executable, controls provably unmoved.

Some link layouts (measured on det-blackcat-f8c08d00-exit, Session 92) place the program's read-only
literals inside its r-x text segment, with no separate r-- rodata. The RODATA-only target test then
rejected every &str and Location on such a binary even after the gate let it be scanned (D-022). 0.4.2
admits the exe's own text as a literal target, and reads header quadwords from it, but only when
Regions.merged_text is set, which scan_process sets solely for that layout.

The safety claim this test pins down: with merged_text False (every separate-rodata control), the
admissibility test and the scanned region set are byte-for-byte the old behaviour, so no control can gain
or lose a row. Run:  python3 tests/test_merged_text_str.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.strings import (Regions, validate_str, validate_location, scan_regions,   # noqa: E402
                            RODATA, DATA, EXEC, HEAP, STACK)

FAILS = []


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


# ------------------------------------------------------------------ a tiny synthetic address space
EXE = "/run/sample"
TEXT = 0x400000                      # the merged r-x mapping: code + constants
RO = 0x500000                        # a separate r-- rodata mapping (ordinary layout)
STR_BYTES = b"config loaded"         # a &str literal
LOC_BYTES = b"src/main.rs"           # a panic Location file literal (must end .rs, NUL-terminated >= 1.90)
STR_AT_TEXT = TEXT + 0x100
LOC_AT_TEXT = TEXT + 0x200
STR_AT_RO = RO + 0x100


def make_read(placements):
    """read(off,n) backed by a dict of {address: bytes}."""
    def read(off, n):
        out = bytearray(n)
        for at, b in placements.items():
            lo, hi = at, at + len(b)
            s, e = max(off, lo), min(off + n, hi)
            if s < e:
                out[s - off:e - off] = b[s - lo:e - lo]
        return bytes(out)
    return read


# the target literals, plus header quadwords inside the text segment (D-023 reads these):
#   &str header at STR_HDR  = (ptr=STR_AT_TEXT, len=len(STR_BYTES))
#   Location header at LOC_HDR = (ptr=LOC_AT_TEXT, len=len(LOC_BYTES)+1, line|col)
import struct
STR_HDR = TEXT + 0x300
LOC_HDR = TEXT + 0x320
placements = {
    STR_AT_TEXT: STR_BYTES,
    LOC_AT_TEXT: LOC_BYTES + b"\x00",
    STR_HDR: struct.pack("<QQ", STR_AT_TEXT, len(STR_BYTES)),
    LOC_HDR: struct.pack("<QQQ", LOC_AT_TEXT, len(LOC_BYTES) + 1, (7 << 32) | 42),  # line 42 col 7
}
read = make_read(placements)

merged = Regions([(TEXT, TEXT + 0x1000, EXEC, EXE)])
merged.exe = EXE
merged.merged_text = True

# 1. the admissibility test: exe text accepted only when merged_text is set
check("merged: target in exe text admitted", merged.str_target_ok(STR_AT_TEXT), True)
merged.merged_text = False
check("not merged: same target refused", merged.str_target_ok(STR_AT_TEXT), False)
merged.merged_text = True

# 2. a library's text is never admitted, merged or not
lib = Regions([(TEXT, TEXT + 0x1000, EXEC, "/usr/lib/libc.so.6")])
lib.exe = EXE
lib.merged_text = True
check("merged: library text never admitted", lib.str_target_ok(STR_AT_TEXT), False)

# 3. validate_str / validate_location reach the literal through the exe text
check("validate_str through text", validate_str(read, merged, STR_AT_TEXT, len(STR_BYTES), 0.9), STR_BYTES)
vl = validate_location(read, merged, LOC_AT_TEXT, len(LOC_BYTES) + 1, 42, 7)
check("validate_location through text", vl is not None and vl[0], LOC_BYTES)

# 4. end to end: scan_regions over the exe text yields one str and one location row
rows = list(scan_regions(read, merged, {HEAP, STACK, DATA, RODATA}, {"str", "location"},
                         max_cap=1 << 20, min_printable=0.9, str_anywhere=False))
kinds = [r[0] for r in rows]
check("merged scan yields a str row", kinds.count("str"), 1)
check("merged scan yields a location row", kinds.count("location"), 1)

# 5. control safety: the SAME bytes under an ordinary separate-rodata layout, merged_text False.
#    The headers sit in the r-- rodata mapping (as they do on every control), targets in rodata.
ro_read = make_read({
    STR_AT_RO: STR_BYTES,
    RO + 0x300: struct.pack("<QQ", STR_AT_RO, len(STR_BYTES)),
})
ordinary = Regions([(RO, RO + 0x1000, RODATA, EXE)])
ordinary.exe = EXE
# merged_text stays False (its default)
check("ordinary: merged_text default False", ordinary.merged_text, False)
check("ordinary: rodata target admitted", ordinary.str_target_ok(STR_AT_RO), True)
ord_rows = list(scan_regions(ro_read, ordinary, {HEAP, STACK, DATA, RODATA}, {"str", "location"},
                             max_cap=1 << 20, min_printable=0.9, str_anywhere=False))
check("ordinary scan still finds the rodata str", [r[0] for r in ord_rows].count("str"), 1)

# 6. the exe's text is NOT scanned when merged_text is False, even though exe is set (no row from text)
ordinary_text = Regions([(TEXT, TEXT + 0x1000, EXEC, EXE)])
ordinary_text.exe = EXE
nrows = list(scan_regions(read, ordinary_text, {HEAP, STACK, DATA, RODATA}, {"str", "location"},
                          max_cap=1 << 20, min_printable=0.9, str_anywhere=False))
check("not merged: exe text not scanned", nrows, [])

if FAILS:
    print("\n".join(FAILS))
    print(f"FAILED {len(FAILS)}")
    sys.exit(1)
print("ALL PASS")
