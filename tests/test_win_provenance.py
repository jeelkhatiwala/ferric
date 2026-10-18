#!/usr/bin/env python3
"""Pure-function tests for the Windows provenance additions (provenance 0.3.3, win.Provenance 0.1.4):
the /rust/deps\\ std-dep form, the rustc <= 1.71 Windows CI cargo home, PE import parsing and the
MSVC-vs-gnu target inference. No image needed.   Run: python3 tests/test_win_provenance.py"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric import provenance as P          # noqa: E402
from ferric import win as W                 # noqa: E402

FAILS = []


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


def tiers(data, prefix=b""):
    return [(t, e) for t, e, _ in P.classify(data, prefix)]


# --- std-dep forms
check("win std-dep", tiers(b"/rust/deps\\hashbrown-0.17.1\\src\\raw\\mod.rs\0"), [("std-dep", "hashbrown-0.17.1")])
check("linux std-dep unchanged", tiers(b"/rust/deps/hashbrown-0.17.1/src/raw/mod.rs\0"), [("std-dep", "hashbrown-0.17.1")])
check("win compiler", tiers(b"/rustc/" + b"b940084d7eb6a299eb4bfeb8e34901bc051e7ac4" + b"\\library\\core\\src\\x.rs"),
      [("compiler", "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4")])

# --- rustc <= 1.71 Windows CI cargo home
REG = b".cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\"
check("ci std crate -> std-dep", tiers(REG + b"hashbrown-0.13.1\\src\\raw\\mod.rs", b"xx C:\\Users\\runneradmin\\"),
      [("std-dep", "hashbrown-0.13.1")])
check("user home std-named crate stays dependency", tiers(REG + b"hashbrown-0.13.1\\src\\lib.rs", b"C:\\Users\\alice\\"),
      [("dependency", "hashbrown-0.13.1")])
check("ci non-std crate stays dependency", tiers(REG + b"reqwest-0.11.0\\src\\lib.rs", b"C:\\Users\\runneradmin\\"),
      [("dependency", "reqwest-0.11.0")])
check("ci std path is not an author", tiers(b"C:\\Users\\runneradmin\\" + REG + b"rustc-demangle-0.1.21\\src\\v0.rs\0"), [])
check("ci non-std path is still an author", tiers(b"C:\\Users\\runneradmin\\" + REG + b"reqwest-0.11.0\\src\\lib.rs\0"),
      [("author", "runneradmin")])
check("real author unchanged", tiers(b"C:\\Users\\alice\\" + REG + b"reqwest-0.11.0\\src\\lib.rs\0"), [("author", "alice")])


# --- PE import directory
def make_pe(dlls, magic=0x20B):
    img = bytearray(0x3000)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    img[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", img, 0x80 + 6, 1)
    struct.pack_into("<H", img, 0x80 + 20, 0xF0)
    struct.pack_into("<H", img, 0x80 + 24, magic)
    dd = 0x80 + 24 + (112 if magic == 0x20B else 96)
    struct.pack_into("<II", img, dd + 8, 0x1000, 20 * (len(dlls) + 1))
    for i, d in enumerate(dlls):
        name_rva = 0x2000 + 64 * i
        struct.pack_into("<I", img, 0x1000 + 20 * i + 12, name_rva)
        img[name_rva:name_rva + len(d)] = d.encode()
    base = 0x140000000
    return base, (lambda off, n: bytes(img[off - base:off - base + n]).ljust(n, b"\0"))


base, rd = make_pe(["KERNEL32.dll", "VCRUNTIME140.dll", "api-ms-win-crt-heap-l1-1-0.dll"])
check("imports pe32+", W.pe_import_dlls(rd, base), ["KERNEL32.dll", "VCRUNTIME140.dll", "api-ms-win-crt-heap-l1-1-0.dll"])
base, rd = make_pe(["msvcrt.dll", "KERNEL32.dll"], magic=0x10B)
check("imports pe32", W.pe_import_dlls(rd, base), ["msvcrt.dll", "KERNEL32.dll"])
check("imports bad header", W.pe_import_dlls(lambda o, n: b"\0" * n, 0x1000), None)

# --- target inference
check("msvc both", W.infer_windows_target(["VCRUNTIME140.dll"], ["hashbrown-0.17.1", "rustc-demangle-0.1.28"])[0::2],
      ("x86_64-pc-windows-msvc", 2))
check("gnu both", W.infer_windows_target(["msvcrt.dll"], ["gimli-0.34.0", "hashbrown-0.17.1"])[0::2],
      ("x86_64-pc-windows-gnu", 2))
check("imports only", W.infer_windows_target(["msvcrt.dll"], [])[0::2], ("x86_64-pc-windows-gnu", 1))
check("std only", W.infer_windows_target(None, ["addr2line-0.27.1"])[0::2], ("x86_64-pc-windows-gnu", 1))
check("conflict", W.infer_windows_target(["VCRUNTIME140.dll"], ["gimli-0.34.0"])[0::2], ("conflict", 0))
check("unknown", W.infer_windows_target([], [])[0::2], ("unknown", 0))
check("static crt msvc via std", W.infer_windows_target(["KERNEL32.dll"], ["hashbrown-0.17.1"])[0::2],
      ("x86_64-pc-windows-msvc", 1))

if FAILS:
    print("\n".join(FAILS))
    print(f"FAILED {len(FAILS)}")
    sys.exit(1)
print("ALL PASS")
