#!/usr/bin/env python3
"""Unit tests for ferric.win's pure parts: VAD protection mapping, PE section parsing from memory, and
the region table built from VADs + TEB stacks. Run: python3 tests/test_win_regions.py (volatility3 importable).
The Volatility glue (build_regions over a real process) is proven on win-img01, not here.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.win import prot_rwx, section_rwx, pe_sections, regions_from_table, scan_vad  # noqa: E402
from ferric.strings import HEAP, STACK, DATA, RODATA, EXEC, OTHER  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

check("PAGE_EXECUTE_WRITECOPY -> rwx", prot_rwx("PAGE_EXECUTE_WRITECOPY") == "rwx")
check("PAGE_READONLY -> r--", prot_rwx("PAGE_READONLY") == "r--")
check("PAGE_READWRITE|PAGE_GUARD -> rw-", prot_rwx("PAGE_READWRITE|PAGE_GUARD") == "rw-")
check("PAGE_EXECUTE_READ -> r-x", prot_rwx("PAGE_EXECUTE_READ") == "r-x")
check("PAGE_NOACCESS / empty -> ---", prot_rwx("PAGE_NOACCESS") == "---" and prot_rwx("") == "---")
check("section characteristics: .text r-x, .rdata r--, .data rw-",
      section_rwx(0x60000020) == "r-x" and section_rwx(0x40000040) == "r--" and section_rwx(0xC0000040) == "rw-")

# a synthetic PE32+ image in memory: headers at base, three sections
BASE = 0x7FF6_1234_0000
def build_pe():
    img = bytearray(0x4000)
    img[:2] = b"MZ"; struct.pack_into("<I", img, 0x3C, 0x80)
    nt = 0x80
    img[nt:nt + 4] = b"PE\0\0"
    struct.pack_into("<H", img, nt + 4, 0x8664)        # machine
    struct.pack_into("<H", img, nt + 6, 3)             # sections
    struct.pack_into("<H", img, nt + 20, 0xF0)         # optional header size (PE32+)
    opt = nt + 24
    struct.pack_into("<H", img, opt, 0x20B)            # magic PE32+
    struct.pack_into("<I", img, opt + 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", img, opt + 60, 0x400)       # SizeOfHeaders
    sec = opt + 0xF0
    for i, (name, vsize, va, raw, chars) in enumerate([
            (b".text", 0x0F00, 0x1000, 0x1000, 0x60000020), (b".rdata", 0x0800, 0x2000, 0x0800, 0x40000040),
            (b".data", 0x0300, 0x3000, 0x0200, 0xC0000040)]):
        o = sec + 40 * i
        img[o:o + 8] = name.ljust(8, b"\0")
        struct.pack_into("<III", img, o + 8, vsize, va, raw)
        struct.pack_into("<I", img, o + 36, chars)
    return bytes(img)
IMG = build_pe()
def read(a, n):
    off = a - BASE
    if 0 <= off < len(IMG):
        return IMG[off:off + n].ljust(n, b"\0")
    return b"\0" * n
secs = pe_sections(read, BASE, BASE + 0x4000)
check("pe_sections: headers + 3 sections", secs is not None and len(secs) == 4)
check("pe_sections: .text r-x at base+0x1000..0x2000", (BASE + 0x1000, BASE + 0x2000, "r-x", ".text") in secs)
check("pe_sections: .rdata r--, .data rw-", any(s[2] == "r--" and s[3] == ".rdata" for s in secs) and any(s[2] == "rw-" and s[3] == ".data" for s in secs))
check("pe_sections: not a PE -> None", pe_sections(lambda a, n: b"\0" * n, 0x1000, 0x5000) is None)

# region table: the exe (sections), a DLL (sections), private rw memory (heap), a stack VAD, a mapped data file
dll_secs = [(0x7FFA0000_0000, 0x7FFA0000_1000, "r--", "[pe-headers]"), (0x7FFA0000_1000, 0x7FFA0000_5000, "r-x", ".text"),
            (0x7FFA0000_5000, 0x7FFA0000_6000, "r--", ".rdata"), (0x7FFA0000_6000, 0x7FFA0000_7000, "rw-", ".data")]
vads = [
    (BASE, BASE + 0x4000, "rwx", True, r"\Users\victim\seed.exe", secs),
    (0x7FFA0000_0000, 0x7FFA0000_7000, "rwx", True, r"\Windows\System32\ntdll.dll", dll_secs),
    (0x1A0000, 0x1B0000, "rw-", False, "[anon]", None),              # heap segment
    (0x3F0000, 0x400000, "rw-", False, "[anon]", None),              # will be a stack (TEB range inside)
    (0x5000000, 0x5010000, "r--", True, r"\Windows\Fonts\x.ttf", None),
    (0x6000000, 0x6010000, "r--", False, "[anon]", None),            # anonymous read-only (unpacked image)
]
regions = regions_from_table(vads, stacks=[(0x3F8000, 0x400000)], exe_name=r"\Users\victim\seed.exe")
k = regions.kind
check("exe .text -> exec, .rdata -> rodata, .data -> data, headers -> rodata",
      k(BASE + 0x1800) == EXEC and k(BASE + 0x2100) == RODATA and k(BASE + 0x3010) == DATA and k(BASE + 0x100) == RODATA)
check("DLL .text -> exec, DLL .rdata -> other (library read-only pages are not scanned), DLL .data -> data",
      k(0x7FFA0000_2000) == EXEC and k(0x7FFA0000_5100) == OTHER and k(0x7FFA0000_6100) == DATA)
check("private rw memory -> heap", k(0x1A5000) == HEAP)
check("VAD holding a TEB stack range -> stack", k(0x3F9000) == STACK and regions.lookup(0x3F9000)[3] == "[stack]")
check("mapped data file read-only -> other", k(0x5001000) == OTHER)
check("anonymous read-only -> rodata (UPX-style unpacked image)", k(0x6001000) == RODATA)

# reserved-only private VADs are skipped (win-img01: a 4 GB PAGE_READWRITE reservation with CommitCharge 0)
check("scan_vad: private, 0 committed pages -> skipped", scan_vad(False, 0) is False)
check("scan_vad: private, 1 committed page -> scanned", scan_vad(False, 1) is True)
check("scan_vad: file-backed, 0 committed (shared pages) -> scanned", scan_vad(True, 0) is True)

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
