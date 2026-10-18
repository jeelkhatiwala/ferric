#!/usr/bin/env python3
"""Runs the Windows provenance path (provenance.iter_pattern_offsets + classify, win.pe_import_dlls,
win.infer_windows_target) over every Windows seed build in control-corpus/build/windows/, each mapped into
its in-memory layout from its section table, and checks the result against the build the file name states:
compiler commit = the rustc version's commit, target = the linker in the name, std-dep set non-empty.
Skips cleanly when the build directory is absent.   Run: python3 tests/test_win_target_builds.py"""
import glob
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "plugins"))
from ferric import provenance as P          # noqa: E402
from ferric import win as W                 # noqa: E402

BUILD = os.path.join(HERE, "..", "control-corpus", "build", "windows")
COMMIT = {v: c for c, v in P.KNOWN_COMMITS.items()}


def map_pe(raw):
    """Lay a PE file out as the loader would (headers + each section at its RVA)."""
    e = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec, opt_size = struct.unpack_from("<H", raw, e + 6)[0], struct.unpack_from("<H", raw, e + 20)[0]
    opt = e + 24
    size_img = struct.unpack_from("<I", raw, opt + 56)[0]
    size_hdr = struct.unpack_from("<I", raw, opt + 60)[0]
    img = bytearray(size_img)
    img[:size_hdr] = raw[:size_hdr]
    for i in range(nsec):
        o = opt + opt_size + 40 * i
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", raw, o + 8)
        n = min(rsize, vsize or rsize)
        img[va:va + n] = raw[rptr:rptr + n]
    return bytes(img)


def main():
    files = sorted(glob.glob(os.path.join(BUILD, "*.exe")))
    if not files:
        print("SKIP: no Windows builds in", BUILD)
        return 0
    fails = []
    for f in files:
        name = os.path.basename(f)
        ver = name.split("__")[1].split("_")[0]
        abi = "msvc" if name.endswith("_msvc.exe") else "gnu"
        img = map_pe(open(f, "rb").read())
        base = 0x140000000
        read = lambda off, n: img[off - base:off - base + n].ljust(n, b"\0")
        tiers = {}
        for off in P.iter_pattern_offsets(read, base, base + len(img)):
            data = read(off, P.CONTEXT_BYTES)
            lb = max(off - P.LOOKBEHIND_BYTES, base)
            for t, ev, _ in P.classify(data, read(lb, off - lb)):
                tiers.setdefault(t, set()).add(ev)
        triple, why, n = W.infer_windows_target(W.pe_import_dlls(read, base), tiers.get("std-dep", ()))
        problems = []
        if tiers.get("compiler") != {COMMIT[ver]}:
            problems.append(f"compiler {tiers.get('compiler')}")
        if triple != f"x86_64-pc-windows-{abi}" or n != 2:
            problems.append(f"target {triple} ({why}) signals={n}")
        if not tiers.get("std-dep"):
            problems.append("no std-dep")
        if "runneradmin" in tiers.get("author", set()):
            problems.append("runneradmin reported as author")
        line = f"{name:<62} {triple:<24} std-dep={len(tiers.get('std-dep', ()))} authors={sorted(tiers.get('author', ()))}"
        print(("FAIL " if problems else "ok   ") + line + ("  <- " + "; ".join(problems) if problems else ""))
        if problems:
            fails.append(name)
    print(f"{len(files) - len(fails)}/{len(files)} builds correct")
    print("ALL PASS" if not fails else f"FAILED {len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
