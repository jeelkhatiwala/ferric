#!/usr/bin/env python3
"""Unit tests for ferric.strings — pure-function tests on a synthetic process memory, no image needed.
NOTE: lives outside plugins/ on purpose: Volatility imports every .py under -p as a plugin module.
Run:  python3 tests/test_strings_validate.py   (needs volatility3 importable)

Synthetic layout (x86-64, 8-byte words):
  heap   0x1000-0x3000  anonymous rw-   glibc-style chunks with 8-byte size fields
  rodata 0x10000-0x11000 exe file r--   packed literals, no terminators (as rustc emits them)
  data   0x20000-0x21000 exe file rw-   headers: Location, &str pieces
  stack  0x7f000-0x80000 anonymous rw-  a stale String header
  text   0x30000-0x31000 exe file r-x   (pointers here must never be accepted as strings)
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.strings import (Regions, classify_vma, glibc_chunk_expected, iter_qwords, scan_regions,  # noqa: E402
                            validate_location, validate_string, validate_str, HEAP, RODATA, DATA, STACK, EXEC, OTHER)

fails = 0
def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    if not cond: fails += 1

# ---------------------------------------------------------------- synthetic memory
mem = {}
def region(start, end): mem[start] = bytearray(end - start)
def write(addr, b):
    for s, buf in mem.items():
        if s <= addr < s + len(buf):
            buf[addr - s: addr - s + len(b)] = b; return
    raise ValueError(hex(addr))
def read(addr, n):
    out = bytearray(n)
    for s, buf in mem.items():
        lo, hi = max(addr, s), min(addr + n, s + len(buf))
        if lo < hi: out[lo - addr: hi - addr] = buf[lo - s: hi - s]
    return bytes(out)
for a, b in [(0x1000, 0x3000), (0x10000, 0x11000), (0x20000, 0x21000), (0x7f000, 0x80000), (0x30000, 0x31000)]:
    region(a, b)
regions = Regions([(0x1000, 0x3000, HEAP, "[heap]"), (0x10000, 0x11000, RODATA, "/bin/seed"),
                   (0x20000, 0x21000, DATA, "/bin/seed"), (0x7f000, 0x80000, STACK, "[stack]"),
                   (0x30000, 0x31000, EXEC, "/bin/seed")])
Q = lambda *v: struct.pack("<" + "Q" * len(v), *v)

# heap chunks: size field 8 bytes before user data; PREV_INUSE bit set
def chunk(user_addr, cap, payload):
    write(user_addr - 8, struct.pack("<Q", glibc_chunk_expected(cap) | 1)); write(user_addr, payload)
chunk(0x1010, 4, b"mode")                       # String::from("mode"): cap == len
chunk(0x1040, 10, b"item-3")                    # format!("item-{i}"): cap 10, len 6
chunk(0x1080, 13, b"docx,xlsx,pdf")
chunk(0x10c0, 8, b"ab\xff\xfecdef")             # not UTF-8
chunk(0x1100, 16, b"abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")   # UTF-8 but zero padded
# packed rodata literals, no terminators
rod = b"modecontroltargetsdocx,xlsx,pdfitem-mode must exist" + b"src/main.rs" + b"t1 reached (pid " + b"); holding for capture\n" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
write(0x10000, rod)
MAIN_RS = 0x10000 + rod.index(b"src/main.rs"); T1 = 0x10000 + rod.index(b"t1 reached"); BIN = 0x10000 + rod.index(b"\x01\x02")
# headers
write(0x2000, Q(0x1010, 4, 4))                  # String, ambiguous order (cap == len)
write(0x2018, Q(0x1040, 10, 6))                 # String (ptr,cap,len)
write(0x2030, Q(0x1040, 6, 10))                 # swapped header: (ptr,len,cap)
write(0x2048, Q(0x1080, 13, 13))
write(0x2060, Q(0x10c0, 8, 8))                  # invalid UTF-8 -> rejected
write(0x2078, Q(0x1100, 16, 16))                # zero padded -> rejected by default, accepted with all-utf8
write(0x2090, Q(0x30000, 8, 8))                 # ptr into text -> rejected
write(0x20a8, Q(0x1040, 6, 3))                  # len > cap in both orders? (cap=6,len=3 valid!) -> accepted len 3 "ite"
write(0x7f100, Q(0x1040, 10, 6))                # stale header on the stack
write(0x20000, Q(MAIN_RS, 11) + struct.pack("<II", 12, 29))     # Location src/main.rs:12:29
write(0x20018, Q(T1, 16))                                        # &str "t1 reached (pid "
write(0x20028, Q(T1 + 16, 23))                                   # &str "); holding for capture\n"
write(0x20038, Q(BIN, 8))                                        # (ptr,len) to binary junk -> not printable -> rejected
write(0x20048, Q(0x10000 + 4, 7) + struct.pack("<II", 3, 3))    # "control" with line/col but no .rs -> &str, not Location

# ---------------------------------------------------------------- unit checks
check("chunk size: cap 4 -> 32", glibc_chunk_expected(4) == 32)
check("chunk size: cap 10 -> 32", glibc_chunk_expected(10) == 32)
check("chunk size: cap 25 -> 48", glibc_chunk_expected(25) == 48)
check("classify: anon rw- -> heap", classify_vma("rw-", False, "[anon]", False) == HEAP)
check("classify: anon rw- [stack] -> stack", classify_vma("rw-", False, "[stack]", False) == STACK)
check("classify: anon r-- -> rodata (unpacked image)", classify_vma("r--", False, "[anon]", False) == RODATA)
check("classify: exe file r-- -> rodata", classify_vma("r--", True, "/bin/x", True) == RODATA)
check("classify: lib file r-- -> other", classify_vma("r--", True, "/lib/libc.so.6", False) == OTHER)
check("classify: exe file rw- -> data", classify_vma("rw-", True, "/bin/x", True) == DATA)
check("classify: r-x -> exec", classify_vma("r-x", True, "/bin/x", True) == EXEC)

v = validate_string(read, regions, 0x1040, 10, 6, 1 << 20)
check("String (ptr,cap,len): cap 10 len 6 'item-3'", v and v[0] == "ptr,cap,len" and v[1] == 10 and v[2] == 6 and v[3] == b"item-3")
check("String: chunk check passes for a real glibc chunk", v and "chunk" in v[4])
v = validate_string(read, regions, 0x1040, 6, 10, 1 << 20)
check("String swapped order detected as ptr,len,cap", v and v[0] == "ptr,len,cap" and v[1] == 10 and v[2] == 6)
check("String: invalid UTF-8 rejected", validate_string(read, regions, 0x10c0, 8, 8, 1 << 20) is None)
check("String: zero-padded rejected by default", validate_string(read, regions, 0x1100, 16, 16, 1 << 20) is None)
check("String: zero-padded accepted with min_printable=0", validate_string(read, regions, 0x1100, 16, 16, 1 << 20, 0.0) is not None)
check("String: ptr into exec rejected", validate_string(read, regions, 0x30000, 8, 8, 1 << 20) is None)
check("String: cap above max rejected", validate_string(read, regions, 0x1040, 10, 6, 8) is None)
check("String: len 0 rejected", validate_string(read, regions, 0x1040, 10, 0, 1 << 20) is None)
check("Location: src/main.rs:12:29 (str variant)", validate_location(read, regions, MAIN_RS, 11, 12, 29) == (b"src/main.rs", "str"))
write(0x10800, b"src/main.rs\x00")
check("Location: 1.89 variant, len includes trailing NUL", validate_location(read, regions, 0x10800, 12, 12, 29) == (b"src/main.rs", "len-with-nul"))
check("Location: interior NUL rejected", validate_location(read, regions, 0x10800 - 4, 16, 12, 29) is None)
check("Location: no .rs suffix rejected", validate_location(read, regions, 0x10004, 7, 3, 3) is None)
check("Location: line 0 rejected", validate_location(read, regions, MAIN_RS, 11, 0, 29) is None)
check("&str: exact literal boundary inside packed rodata", validate_str(read, regions, T1, 16, 0.9) == b"t1 reached (pid ")
check("&str: binary junk rejected by printable floor", validate_str(read, regions, BIN, 8, 0.9) is None)
check("&str: ptr into heap rejected (static-data only)", validate_str(read, regions, 0x1010, 4, 0.9) is None)

# ---------------------------------------------------------------- scan end to end (declared layout, ptr first)
from ferric.strings import LAYOUTS, validate_string_layout, vote_layout  # noqa: E402
hits = list(scan_regions(read, regions, {HEAP, STACK, DATA, RODATA}, {"string", "str", "location"}, 1 << 20, 0.9, False))
kinds = {}
for h in hits: kinds.setdefault(h[0], []).append(h)
strings = kinds.get("string", []); locs = kinds.get("location", []); strs = kinds.get("str", []); lay = kinds.get("layout", [])
check("scan: layout vote reported", len(lay) == 1 and lay[0][7] == "ptr,cap,len")
texts = sorted(h[9] for h in strings)
check("scan (ptr-first memory): voted layout ptr,cap,len yields mode, item-3 x2 (heap + stale stack), docx..., 'ite'",
      texts == sorted(["mode", "item-3", "item-3", "docx,xlsx,pdf", "ite"]))
check("scan: the swapped-order header is NOT emitted once the layout is voted", not any(h[1] == 0x2030 for h in strings))
check("scan: stale stack header reported with HeaderIn=stack", any(h[2] == STACK and h[9] == "item-3" for h in strings))
check("scan: exactly one Location, src/main.rs:12:29", len(locs) == 1 and locs[0][9] == "src/main.rs:12:29")
check("scan: &str pieces recovered with exact boundaries",
      sorted(h[9] for h in strs) == sorted(["t1 reached (pid ", "); holding for capture\\n", "control"]))
check("scan: Location's own (ptr,len) not double-reported as &str", not any(h[1] == 0x20000 for h in strs))

# ---------------------------------------------------------------- scan end to end (measured rustc 1.99 layout: cap,ptr,len)
# A hashbrown data array of (String, String) entries laid out as rustc 1.99 does: [cap,ptr,len][cap,ptr,len]...
# Session 44 host run showed one-word-shifted false readings ("docx" len 4 borrowed from the next entry's cap)
# when only ptr-first orders were tried. The vote must pick cap,ptr,len and suppress the shifted readings.
region(0x40000, 0x41000); region(0x5000, 0x6000)
regions3 = Regions([(0x40000, 0x41000, HEAP, "[heap]"), (0x5000, 0x6000, HEAP, "[heap]"),
                    (0x10000, 0x11000, RODATA, "/bin/seed")])
def chunk2(user_addr, cap, payload):
    write(user_addr - 8, struct.pack("<Q", glibc_chunk_expected(cap) | 1)); write(user_addr, payload)
chunk2(0x5010, 7, b"targets"); chunk2(0x5040, 13, b"docx,xlsx,pdf"); chunk2(0x5070, 4, b"mode"); chunk2(0x50a0, 7, b"control")
items = [(0x5100 + 0x30 * i, b"item-%d" % i) for i in range(8)]
for a, t in items: chunk2(a, 10, t)
# entries adjacent in the table: (targets -> docx,xlsx,pdf), (mode -> control)
write(0x40000, Q(7, 0x5010, 7, 13, 0x5040, 13, 4, 0x5070, 4, 7, 0x50a0, 7))
# Vec<String> buffer of 8 items, exact capacity, followed by the next chunk's size field (not a plausible cap)
vec = b"".join(Q(10, a, 6) for a, _ in items) + Q(0x21)
write(0x40100, vec)
hits = list(scan_regions(read, regions3, {HEAP, STACK, DATA, RODATA}, {"string"}, 1 << 20, 0.9, False))
lay = [h for h in hits if h[0] == "layout"]; strings = [h for h in hits if h[0] == "string"]
check("1.99 layout: vote picks cap,ptr,len", len(lay) == 1 and lay[0][7] == "cap,ptr,len")
texts = sorted(h[9] for h in strings)
check("1.99 layout: all 12 strings recovered, nothing shifted",
      texts == sorted(["targets", "docx,xlsx,pdf", "mode", "control"] + [t.decode() for _, t in items]))
caps = {h[9]: (h[6], h[5]) for h in strings}
check("1.99 layout: item caps 10 / lens 6, mode cap 4, docx,xlsx,pdf cap 13",
      caps["item-3"] == (10, 6) and caps["mode"] == (4, 4) and caps["docx,xlsx,pdf"] == (13, 13))
check("1.99 layout: every hit chunk-consistent", all("chunk" in h[8] for h in strings))
hits_all = list(scan_regions(read, regions3, {HEAP, STACK, DATA, RODATA}, {"string"}, 1 << 20, 0.9, False, None, True))
check("1.99 layout: --all-layouts exposes the shifted 'docx' reading under ptr,cap,len",
      any(h[9] == "docx" and h[7] == "ptr,cap,len" for h in hits_all))
forced = list(scan_regions(read, regions3, {HEAP, STACK, DATA, RODATA}, {"string"}, 1 << 20, 0.9, False, "ptr,len,cap"))
check("forced layout honoured (no vote row)", all(h[7] == "ptr,len,cap" for h in forced) and not any(h[0] == "layout" for h in forced))
check("String data must be on the heap: a stack-pointing triple is rejected",
      validate_string_layout(read, regions, (0x7f200, 56, 1), "ptr,cap,len", 1 << 20) is None)

# ---------------------------------------------------------------- fmt::Arguments templates (rustc >= 1.93)
from ferric.strings import parse_template, scan_templates, template_text, escape  # noqa: E402
# the two templates observed in vsweep-05's .rodata (Session 45 hex dump) and the format!("item-{i}") one
T1 = b"\x10t1 reached (pid \xc0\x17); holding for capture\n\x00"
T2 = b"\xc0\x0b (os error \xc0\x01)\x00"
T3 = b"\x05item-\xc0\x00"
r = parse_template(T1, 0)
check("template: eprintln template parses (2 literals, 1 placeholder)", r is not None and r[0] == len(T1) and len(r[1]) == 2 and r[2] == 1)
check("template: rendered as a format string", template_text(T1, 0, len(T1)) == "t1 reached (pid {}); holding for capture\\n")
r = parse_template(T2, 0)
check("template: io::Error template (placeholder first) parses", r is not None and r[2] == 2 and r[1] == [b" (os error ", b")"])
check("template: item- template", template_text(T3, 0, len(T3)) == "item-{}")
check("template: 0x81..0xBF cannot start a part", parse_template(b"\x81abc\x00", 0) is None)
check("template: truncated (no end byte) rejected", parse_template(b"\x05item-\xc0", 0) is None)
check("template: long form 0x80 + u16 length", parse_template(b"\x80\x03\x00abc\xc0\x00", 0) == (8, [b"abc"], 1))
check("template: placeholder with width field (0xC2 + u16) consumes 3 bytes", parse_template(b"\x01a\xc2\x05\x00\x00", 0) == (6, [b"a"], 1))
check("template: non-UTF-8 literal rejected", parse_template(b"\x02\xff\xfe\xc0\x00", 0) is None)
check("escape: control characters are hex-escaped, newline stays \\n", escape(b"a\x01b\n") == "a\\x01b\\n")
# sequential scan over a rodata-like blob: literal-only sequences (no placeholder) are not templates
blob = b"modecontroltargets" + b"\x00" + T1 + T2 + b"/rustc/abc.rs" + b"\x00\x00" + T3 + b"\x00"
found = list(scan_templates(blob, 0x10000))
check("template scan: exactly the three templates, in order, with exact texts",
      [t for *_, t in found] == ["t1 reached (pid {}); holding for capture\\n", "{} (os error {})", "item-{}"])
check("template scan: offsets are absolute", found[0][0] == 0x10000 + blob.index(T1))
check("template scan: no template without a placeholder (packed literals are not reported)",
      not any("modecontrol" in t for *_, t in found))

# ---------------------------------------------------------------- window boundary
W = 4096
region(0x100000, 0x100000 + 3 * W); regions2 = Regions([(0x100000, 0x100000 + 3 * W, HEAP, "[heap]"), (0x1000, 0x3000, HEAP, "[heap]")])
write(0x100000 + W - 16, Q(0x1040, 10, 6))      # header straddling the first window boundary
write(0x100000 + 2 * W - 8, Q(0x1040, 10, 6))   # straddling the second
write(0x100000 + 3 * W - 24, Q(0x1040, 10, 6))  # last 24 bytes of the region
got = [a for a, *_ in iter_qwords(read, 0x100000, 0x100000 + 3 * W, window=W, overlap=32) if _[0] == 0x1040]
check("window iterator: boundary-straddling headers each seen exactly once",
      got == [0x100000 + W - 16, 0x100000 + 2 * W - 8, 0x100000 + 3 * W - 24])

# v0.3.2: the fmt-template recogniser is gated on the process's compiler version, read from its own
# /rustc/<commit>/ paths (the provenance tier). Synthetic rodata with 1.89 paths -> not supported;
# 1.99 -> supported; no path -> unknown (scanned, tagged).
from ferric.strings import rustc_minor, templates_supported, detect_rustc, RODATA  # noqa: E402
check("rustc_minor parses 1.89.0 / rejects 'unknown (...)'", rustc_minor("1.89.0") == (1, 89) and rustc_minor("unknown (add to --commit-map)") is None)
check("templates_supported: 1.92 no, 1.93 yes, unknown None", templates_supported("1.92.0") is False and templates_supported("1.93.0") is True and templates_supported(None) is None)
RO = 0x400000
def mk(commit, n=3):
    body = b"".join(b"/rustc/" + commit.encode() + b"/library/core/src/fmt/mod.rs\0" for _ in range(n))
    buf = bytearray(0x2000); buf[0x100:0x100 + len(body)] = body
    return bytes(buf)
def reader(buf):
    return lambda a, n: buf[a - RO:a - RO + n].ljust(n, b"\0") if RO <= a < RO + len(buf) else b"\0" * n
reg = Regions([(RO, RO + 0x2000, RODATA, "bin")])
v, c, h = detect_rustc(reader(mk("29483883eed69d5fb4db01964cdf2af4d86e9cb2")), reg)
check("detect_rustc finds the 1.89 commit (3 hits) and names the version", (v, h) == ("1.89.0", 3) and c.startswith("29483883"))
check("1.89 -> templates not supported", templates_supported(v) is False)
v, c, h = detect_rustc(reader(mk("b940084d7eb6a299eb4bfeb8e34901bc051e7ac4")), reg)
check("1.99 -> templates supported", templates_supported(v) is True)
v, c, h = detect_rustc(reader(mk("0123456789abcdef0123456789abcdef01234567")), reg)
check("unknown commit -> version None, commit reported, hits counted", v is None and c.startswith("01234567") and h == 3)
check("no path at all -> (None, None, 0)", detect_rustc(reader(bytes(0x2000)), reg) == (None, None, 0))


# ---------------------------------------------------------------- v0.4.0: scan_process policy (D-018)
# Synthetic process: rodata with (or without) the /rustc/<commit>/ fingerprint and three fmt templates;
# code with one RIP-relative LEA that computes template A; data with one pointer to template C; nothing
# refers to template B.
from ferric.strings import scan_process, template_refs  # noqa: E402
RO2, EX2, DA2 = 0x500000, 0x510000, 0x520000
FP99 = b"/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/fmt/mod.rs\0"
FP89 = b"/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2/library/core/src/fmt/mod.rs\0"
TA, TB, TC = RO2 + 0x200, RO2 + 0x210, RO2 + 0x220
def mem2(fp=FP99, code=True):
    ro, ex, da = bytearray(0x1000), bytearray(0x1000), bytearray(0x1000)
    if fp:
        ro[0x10:0x10 + len(fp)] = fp
    ro[0x200:0x208] = b"\x05item-\xC0\x00"          # "item-{}"
    ro[0x210:0x215] = b"\x02ab\xC0\x00"             # "ab{}"
    ro[0x220:0x226] = b"\x03xyz\xC0\x00"            # "xyz{}"
    if code:
        L = EX2 + 0x100
        ex[0x100:0x107] = b"\x48\x8d\x05" + struct.pack("<i", TA - (L + 7))   # lea rax, [rip+disp] -> TA
    da[0x40:0x48] = struct.pack("<Q", TC)
    bufs = {RO2: ro, EX2: ex, DA2: da}
    def read(a, n):
        for base, b in bufs.items():
            if base <= a < base + len(b):
                return bytes(b[a - base:a - base + n]).ljust(n, b"\0")
        return b"\0" * n
    return read
regs2 = Regions([(RO2, RO2 + 0x1000, RODATA, "bin"), (EX2, EX2 + 0x1000, EXEC, "bin"), (DA2, DA2 + 0x1000, DATA, "bin")])
WANT = {"string", "str", "location", "template"}
def rows_of(read, **kw):
    return list(scan_process(read, regs2, WANT, **kw))
def templates(rows):
    return {r[1]: r[8] for r in rows if r[0] == "template"}

refs, seen = template_refs(mem2(), regs2, [TA, TB, TC])
check("template_refs: A by lea, C by data pointer, B by nothing; code seen", refs[TA] == ["lea:1"] and refs[TC] == ["ptr:1"] and refs[TB] == [] and seen)
refs, seen = template_refs(mem2(code=False), regs2, [TA, TB, TC])
check("template_refs: without any decodable LEA, code_seen is False", not seen and refs[TA] == [])

r = rows_of(mem2(fp=None))
check("no fingerprint -> exactly one 'compiler' row saying not scanned", len(r) == 1 and r[0][0] == "compiler" and "not scanned" in r[0][9] and "--force-scan" in r[0][9])
r = rows_of(mem2(fp=None), force_scan=True)
check("no fingerprint + force_scan -> scanned, compiler row says so", any(x[0] == "template" for x in r) and "force-scan" in r[0][9])

r = rows_of(mem2())
t = templates(r)
check("fingerprint 1.99 -> compiler row names the version and 'templates scanned'", r[0][0] == "compiler" and r[0][9].startswith("rustc 1.99.0 (b940084d7eb6, 1 hits): templates scanned"))
check("template A kept with lea:1, C kept with ptr:1, B dropped", set(t) == {TA, TC} and "lea:1" in t[TA] and "ptr:1" in t[TC])
ps = [x for x in r if x[0] == "templates"]
check("'templates' pseudo-row: kept 2 of 3 candidates (lea 1, ptr 1)", len(ps) == 1 and ps[0][5] == 2 and ps[0][6] == 3 and "(lea 1, ptr 1)" in ps[0][9] and "--all-candidates" in ps[0][9])
check("template rows come after every other kind (buffered for the reference gate)", [x[0] for x in r].index("template") > max(i for i, x in enumerate(r) if x[0] not in ("template", "templates")))

r = rows_of(mem2(), all_candidates=True)
t = templates(r)
check("all_candidates -> B listed tagged ref=none, A and C unchanged", set(t) == {TA, TB, TC} and "ref=none" in t[TB] and "lea:1" in t[TA])
ps = [x for x in r if x[0] == "templates"][0]
check("pseudo-row says unreferenced are listed", "listed as ref=none" in ps[9] and ps[5] == 2)

r = rows_of(mem2(code=False))
t = templates(r)
check("no decodable code -> all three kept, tagged ref=unverifiable (C still carries ptr:1)", set(t) == {TA, TB, TC} and "ref=unverifiable" in t[TA] and "ref=unverifiable" in t[TB] and "ptr:1" in t[TC] and "ref=unverifiable" not in t[TC])
ps = [x for x in r if x[0] == "templates"][0]
check("pseudo-row explains: kept unverified, no LEA decoded", "kept unverified" in ps[9] and ps[5] == 3)

r = rows_of(mem2(fp=FP89))
check("fingerprint 1.89 -> no template rows, compiler row says format exists from 1.93", not templates(r) and "format exists from 1.93" in r[0][9] and not any(x[0] == "templates" for x in r))
r = rows_of(mem2(fp=FP89), force_templates=True)
check("1.89 + force_templates -> templates scanned and reference-gated (A, C)", set(templates(r)) == {TA, TC})
r = list(scan_process(mem2(), regs2, {"string", "str"}))
check("kinds without template -> no template work, compiler row without a template note", r[0][9] == "rustc 1.99.0 (b940084d7eb6, 1 hits)" and not any(x[0] in ("template", "templates") for x in r))

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)
