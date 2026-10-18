#!/usr/bin/env python3
"""Regions.exe_const_rows and the widened fingerprint gate (D-022).

Some link layouts merge .rodata into the text segment, so the program's own constants live in a
readable+executable mapping. Measured on det-blackcat-f8c08d00-exit (Session 92): all 27 /rustc/ hits sat
in the executable's 1.8 MB r-x mapping and none in its 48 KB r-- mapping, so the RODATA-only gate refused
a genuine Rust sample that ferric.provenance had already fingerprinted. The gate now also reads the main
executable's EXEC pages; libraries' code is still excluded.

Run:  python3 tests/test_exe_const_rows.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.strings import Regions, detect_rustc, RODATA, EXEC, DATA, HEAP   # noqa: E402

FAILS = []
COMMIT = b"b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"
PATH = b"x/rustc/" + COMMIT + b"/library/core/src/option.rs" + b"\0" * 64
EXE, RO = 0x400000, 0x500000


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


def reader(at):
    """A read() whose only content is PATH, placed at address `at`."""
    def read(off, n):
        out = bytearray(n)
        if at <= off < at + 0x1000:
            seg = PATH[off - at:off - at + n]
            out[:len(seg)] = seg
        return bytes(out)
    return read


def regions(rows, exe):
    r = Regions(rows)
    r.exe = exe
    return r


exe_rows = [(EXE, EXE + 0x1000, EXEC, "/run/sample"), (RO, RO + 0x1000, RODATA, "/run/sample")]

# the BlackCat layout: constants merged into the text segment
r = regions(exe_rows, "/run/sample")
check("exe EXEC counted as const", len(r.exe_const_rows()), 2)
check("gate passes on exe EXEC fingerprint", detect_rustc(reader(EXE), r, {})[1], COMMIT.decode())

# the ordinary layout still works, and is unaffected
check("gate passes on RODATA fingerprint", detect_rustc(reader(RO), r, {})[1], COMMIT.decode())

# the executable was not identified: old, conservative behaviour
check("exe unknown -> EXEC not counted", len(regions(exe_rows, None).exe_const_rows()), 1)
check("exe unknown -> gate refuses", detect_rustc(reader(EXE), regions(exe_rows, None), {})[1], None)

# a library's code is never scanned, even when it holds the pattern
lib_rows = [(EXE, EXE + 0x1000, EXEC, "/usr/lib/libc.so.6"), (RO, RO + 0x1000, RODATA, "/run/sample")]
check("library EXEC excluded", len(regions(lib_rows, "/run/sample").exe_const_rows()), 1)
check("library EXEC -> gate refuses", detect_rustc(reader(EXE), regions(lib_rows, "/run/sample"), {})[1], None)

# no fingerprint anywhere: still refused
check("no fingerprint", detect_rustc(lambda o, n: b"\0" * n, r, {})[1], None)

# writable and heap regions are not const, whatever the exe is
mixed = regions([(EXE, EXE + 0x1000, DATA, "/run/sample"), (RO, RO + 0x1000, HEAP, "[heap]")], "/run/sample")
check("data/heap not const", len(mixed.exe_const_rows()), 0)

if FAILS:
    print("\n".join(FAILS))
    print(f"FAILED {len(FAILS)}")
    sys.exit(1)
print("ALL PASS")
