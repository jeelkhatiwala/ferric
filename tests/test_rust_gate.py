#!/usr/bin/env python3
"""strings.rust_gate (D-021): maps, vtables and tokio scan a process only when its read-only data carries
the /rustc/<commit>/ fingerprint, unless --force-scan.   Run: python3 tests/test_rust_gate.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.strings import Regions, rust_gate, RODATA, HEAP   # noqa: E402

FAILS = []
COMMIT = b"b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"


def mem(blobs):
    def read(off, n):
        out = bytearray(n)
        for base, data in blobs:
            lo, hi = max(off, base), min(off + n, base + len(data))
            if lo < hi:
                out[lo - off:hi - off] = data[lo - base:hi - base]
        return bytes(out)
    return read


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got}, want {want}")


path = b"xx/rustc/" + COMMIT + b"/library/core/src/option.rs" + b"\0" * 64
ro, heap = 0x400000, 0x10000000
# fingerprint in read-only data of the executable -> scanned
r1 = Regions([(ro, ro + 0x1000, RODATA, "seed"), (heap, heap + 0x1000, HEAP, "[heap]")])
check("rodata fingerprint", rust_gate(mem([(ro, path)]), r1), True)
# Windows form (backslash after the commit)
wpath = b"/rustc/" + COMMIT + b"\\library\\core\\src\\x.rs" + b"\0" * 64
check("windows separator", rust_gate(mem([(ro, wpath)]), r1), True)
# fingerprint only in heap (e.g. a non-Rust process that read a Rust file: Defender, an indexer) -> skipped
check("heap-only fingerprint", rust_gate(mem([(heap, path)]), r1), False)
# no fingerprint anywhere -> skipped; --force-scan -> scanned
check("no fingerprint", rust_gate(mem([]), r1), False)
check("force-scan", rust_gate(mem([]), r1, force=True), True)

if FAILS:
    print("\n".join(FAILS)); print(f"FAILED {len(FAILS)}"); sys.exit(1)
print("ALL PASS")
