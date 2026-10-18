# ferric.strings — Rust string objects recovered from process memory by their headers, not by byte runs.
#
# Written against Volatility 3 framework 2.28.2 (pslist 4.1.1). Linux, x86-64 (8-byte usize).
#
# Why a strings tool needs to know about Rust
#   Rust string literals are laid out in .rodata back to back with no terminator; `strings` prints
#   them merged into one run ("modecontroltargetsdocx,xlsx,pdf..."). Rust never needs terminators
#   because every string is reached through a header that carries its length:
#     &str   = (ptr, len)              16 bytes, a "fat pointer"
#     String = (ptr, cap, len)         24 bytes (RawVec{ptr,cap} + len), bytes on the heap, len <= cap
#     core::panic::Location = (&str file, u32 line, u32 col)   24 bytes, file always ends in ".rs"
#   Recovering the HEADERS gives exact boundaries, lengths, capacities, and (for Location) the source
#   file:line:col of every panicking call site compiled into the binary, including the author's own.
#
# What it does
#   For each selected task: classify VMAs (anonymous writable = heap-like; file-backed read-only
#   non-exec = rodata-like; file-backed writable = data-like), then slide an 8-byte-aligned window over
#   the chosen regions and validate candidate headers against the bytes they point to:
#     String   header in heap-/data-/stack-like memory, ptr into heap-like memory, 1<=len<=cap<=max,
#              bytes valid UTF-8 (a String invariant); plus a glibc-malloc chunk-size consistency check
#              reported as a flag (and required with --strict-chunk).
#     Location header in rodata-/data-like memory, ptr into rodata-like memory, 1<=len<=4096, UTF-8,
#              ends with ".rs", 1<=line<=1e6, 1<=col<=1e4.
#     &str     header in rodata-/data-like memory, ptr into rodata-like memory, 1<=len<=4096, UTF-8,
#              mostly printable (ratio >= --min-printable, default 0.9), not already a Location; also the
#              fmt::Arguments literal-only form (ptr, len<<1|1) of rustc >= 1.93.
#     template fmt::Arguments byte templates (rustc >= 1.93): literal pieces length-prefixed inline,
#              placeholders 0b11xxxxxx, end 0x00; parsed in rodata-like memory, rendered as a format
#              string with {} marks. Before 1.93 pieces were &str arrays and appear under 'str'.
#   All six field orders of the String header are tested; the process-wide layout is chosen by vote
#   (the order most chunk-consistent candidates agree on) and reported, so the layout is a measurement,
#   not an assumption. Measured on rustc 1.99: (cap, ptr, len), not the declared (ptr, cap, len).
#
# What decides whether a process is scanned at all (0.4.0, scan_process)
#   The header heuristics are specific inside a Rust process (seed01: 12 String rows, all 12 in the truth)
#   and unspecific outside one: run over every process of a stock Ubuntu guest they report ~6,400 String
#   rows, ~3,800 &str rows and 440 template rows per image in 27 non-Rust processes (bash alone 4,200
#   String rows, 14% of them chunk-consistent). So a process is scanned only when its read-only data
#   carries the /rustc/<commit>/ compiler fingerprint that ferric.provenance keys on (--force-scan lifts
#   this, and the unscanned process still gets one 'compiler' row saying why). fmt templates are further
#   required to be referenced from the process's own code (a RIP-relative LEA computes their address,
#   the way rustc builds a fmt::Arguments) or from its static data; a template nothing refers to is a
#   false parse of adjacent literals and is dropped (--all-candidates lists them tagged ref=none).
#
# Known limits (stated)
#   * Headers that live in registers or were optimised away are not in memory and are not found.
#   * A freed String whose bytes are still on the heap has no live header; this plugin reports headers.
#   * The chunk check assumes glibc malloc; other allocators (musl, mimalloc, jemalloc) report chunk=no.
#   * &str recovery is restricted to headers in static data to keep false positives low; --str-anywhere
#     extends it to heap-/stack-like memory at a higher false-positive rate.

import bisect
import logging
import struct
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

STR_MAX_LEN = 4096
STRING_MAX_CAP_DEFAULT = 1024 * 1024
LOC_MAX_LINE = 1_000_000
LOC_MAX_COL = 10_000
WINDOW_BYTES = 8 * 1024 * 1024
WINDOW_OVERLAP = 32                 # a header is at most 24 bytes

# region kinds
HEAP, RODATA, DATA, STACK, EXEC, OTHER = "heap", "rodata", "data", "stack", "exec", "other"


# ----------------------------------------------------------------------------- pure helpers
def is_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13) or c >= 128)
    return ok / len(b)


def glibc_chunk_expected(cap: int) -> int:
    """glibc malloc: request2size(cap) on 64-bit = max(32, (cap + 8 + 15) & ~15)."""
    return max(32, (cap + 8 + 15) & ~15)


def glibc_chunk_ok(read: Callable[[int, int], bytes], ptr: int, cap: int) -> bool:
    """True when the 8-byte size field just before ptr matches what malloc would have given for cap."""
    try:
        (size,) = struct.unpack("<Q", read(ptr - 8, 8))
    except Exception:
        return False
    return (size & ~0x7) == glibc_chunk_expected(cap)


def escape(b: bytes, limit: int = 96) -> str:
    s = b.decode("utf-8", errors="replace")
    s = s.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    s = "".join(c if (ord(c) >= 32 and ord(c) != 127) else f"\\x{ord(c):02x}" for c in s)
    return s if len(s) <= limit else s[:limit] + f"...(+{len(s) - limit})"


class Regions:
    """Sorted VMA table with kind classification and bisect lookup."""

    def __init__(self, rows: List[Tuple[int, int, str, str]]):
        # rows: (start, end, kind, name)
        self.rows = sorted(rows)
        self.starts = [r[0] for r in self.rows]
        self.exe = None      # backing name of the main executable, set by the callers' build_regions
        self.allocator = "glibc"   # the Linux default maps.py assumes; win.py sets "nt"
        self.merged_text = False   # D-023: set True by scan_process when the exe's constants are linked
        #                            into its text segment (rustc paths in r-x, none in r--). Off for every
        #                            ordinary binary, so the &str/Location target test below is unchanged
        #                            and no separate-rodata control can move.

    def exe_const_rows(self) -> List[Tuple[int, int, str, str]]:
        """Regions that may hold the main executable's own constant data: its RODATA, plus its EXEC
        pages. Some link layouts merge .rodata into the text segment, so a readable+executable mapping of
        the executable itself carries the program's constants (measured on det-blackcat-f8c08d00-exit:
        all 27 /rustc/ hits were in the 1.8 MB r-x mapping and none in the 48 KB r-- one, Session 92).
        Libraries' EXEC pages are deliberately excluded: only the program under analysis is scanned."""
        out = [r for r in self.rows if r[2] == RODATA]
        if self.exe:
            out += [r for r in self.rows if r[2] == EXEC and r[3] == self.exe]
        return sorted(set(out))

    def lookup(self, addr: int) -> Optional[Tuple[int, int, str, str]]:
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0 and self.rows[i][0] <= addr < self.rows[i][1]:
            return self.rows[i]
        return None

    def str_target_ok(self, ptr: int) -> bool:
        """Where the bytes behind a &str or a panic Location may legitimately sit. Normally RODATA only.
        On a merged-text executable (D-023) the program's own read-only literals live physically inside
        its r-x mapping, so that one mapping is admitted too; libraries' code and every other region stay
        out. With merged_text False this is exactly the former `kind(ptr) == RODATA` test, so an ordinary
        separate-rodata binary behaves as before and no such control can gain or lose a row."""
        r = self.lookup(ptr)
        if r is None:
            return False
        if r[2] == RODATA:
            return True
        return self.merged_text and r[2] == EXEC and r[3] == self.exe

    def str_scan_rows(self, base_kinds) -> List[Tuple[int, int, str, str]]:
        """Regions whose quadwords are read as candidate String/&str/Location headers: those of
        base_kinds, plus, on a merged-text executable, the exe's own EXEC pages (where its &str and
        Location structs are linked alongside the code). Ordinary binaries get base_kinds only."""
        rows = self.of_kinds(base_kinds)
        if self.merged_text and self.exe:
            extra = [r for r in self.rows if r[2] == EXEC and r[3] == self.exe and r not in rows]
            rows = sorted(rows + extra)
        return rows

    def is_exe_text(self, hk: str, hname: str) -> bool:
        """True when a region is the main executable's own text and that text is carrying merged
        constants, so header quadwords found there should be read as &str/Location candidates."""
        return self.merged_text and hk == EXEC and hname == self.exe

    def kind(self, addr: int) -> str:
        r = self.lookup(addr)
        return r[2] if r else OTHER

    def of_kinds(self, kinds) -> List[Tuple[int, int, str, str]]:
        return [r for r in self.rows if r[2] in kinds]


def classify_vma(prot: str, file_backed: bool, name: str, is_exe: bool) -> str:
    """prot is 'rwx' with '-' for absent bits (vm_area_struct.get_protection())."""
    r, w, x = prot[0] == "r", prot[1] == "w", prot[2] == "x"
    if not r:
        return OTHER
    if x:
        return EXEC
    if not file_backed:
        if not w:
            return RODATA                   # anonymous read-only: constants of an unpacked (e.g. UPX) image
        return STACK if name == "[stack]" else HEAP
    if w:
        return DATA
    return RODATA if is_exe else OTHER      # read-only file pages of shared libraries are not scanned


# All six field orders of a 3-word String/Vec header. rustc reorders struct fields (the capacity newtype
# carries the largest niche, so recent compilers put it first); the order is therefore a property of the
# compiler, not of the source, and it is MEASURED per process by voting (see vote_layout).
LAYOUTS = ("cap,ptr,len", "ptr,cap,len", "ptr,len,cap", "len,ptr,cap", "cap,len,ptr", "len,cap,ptr")
_IDX = {name: tuple(name.split(",").index(f) for f in ("ptr", "cap", "len")) for name in LAYOUTS}


def validate_string_layout(read, regions: Regions, words, layout: str, max_cap: int,
                           min_printable: float = 0.9):
    """Test the 3 words at one aligned position as a String header under `layout`.
    Returns (ptr, cap, len, bytes, checks) or None. String data always lives on the heap, so ptr must
    fall in heap-like memory (not the stack). NUL bytes are valid UTF-8, so a printable-ratio floor
    (min_printable, 0 to disable) keeps zero-padded garbage out by default."""
    pi, ci, li = _IDX[layout]
    ptr, cap, ln = words[pi], words[ci], words[li]
    if not (1 <= ln <= cap <= max_cap):
        return None
    tgt = regions.lookup(ptr)
    if tgt is None or tgt[2] != HEAP or ptr + ln > tgt[1]:
        return None
    try:
        data = read(ptr, ln)
    except Exception:
        return None
    if not is_utf8(data):
        return None
    pr = printable_ratio(data)
    if pr < min_printable:
        return None
    checks = ["utf8"]
    if pr >= 0.9:
        checks.append("printable")
    if glibc_chunk_ok(read, ptr, cap):
        checks.append("chunk")
    return ptr, cap, ln, data, checks


def validate_string(read, regions: Regions, ptr: int, a: int, b: int, max_cap: int,
                    min_printable: float = 0.9):
    """Compatibility wrapper used by older tests: tries ptr-first layouts only."""
    for layout in ("ptr,cap,len", "ptr,len,cap"):
        v = validate_string_layout(read, regions, (ptr, a, b), layout, max_cap, min_printable)
        if v:
            return layout, v[1], v[2], v[3], v[4]
    return None


def vote_layout(cands):
    """cands: list of (layout, ...) candidate tuples with checks at index 5. The layout with the most
    chunk-consistent candidates wins (all candidates if no allocator agrees); ties go to LAYOUTS order."""
    votes = {l: 0 for l in LAYOUTS}
    for c in cands:
        if "chunk" in c[5]:
            votes[c[0]] += 1
    if not any(votes.values()):
        for c in cands:
            votes[c[0]] += 1
    best = max(LAYOUTS, key=lambda l: (votes[l], -LAYOUTS.index(l)))
    return best, votes


def validate_location(read, regions: Regions, ptr: int, ln: int, line: int, col: int):
    """Validate a core::panic::Location candidate. Returns (file_bytes, variant) or None.
    Layout history (library/core/src/panic/location.rs, read at the tags):
      <= 1.88  file: &str                     len excludes any NUL
      1.89     file_bytes_with_nul: &[u8]     len INCLUDES the trailing NUL      -> variant 'len-with-nul'
      >= 1.90  filename: NonNull<str>         len excludes the NUL, NUL present  -> variant 'str'
    """
    if not regions.str_target_ok(ptr) or not (1 <= ln <= STR_MAX_LEN):
        return None
    if not (1 <= line <= LOC_MAX_LINE and 1 <= col <= LOC_MAX_COL):
        return None
    tgt = regions.lookup(ptr)
    if tgt is None or ptr + ln > tgt[1]:
        return None
    try:
        data = read(ptr, ln)
    except Exception:
        return None
    variant = "str"
    if data.endswith(b".rs\x00"):
        data, variant = data[:-1], "len-with-nul"
    if not data.endswith(b".rs") or b"\x00" in data or not is_utf8(data):
        return None
    return data, variant


def validate_str(read, regions: Regions, ptr: int, ln: int, min_printable: float):
    if not regions.str_target_ok(ptr) or not (1 <= ln <= STR_MAX_LEN):
        return None
    tgt = regions.lookup(ptr)
    if tgt is None or ptr + ln > tgt[1]:
        return None
    try:
        data = read(ptr, ln)
    except Exception:
        return None
    if not is_utf8(data) or printable_ratio(data) < min_printable:
        return None
    return data


# fmt::Arguments template byte-code, rustc >= 1.93 (library/core/src/fmt/mod.rs, verified at tags 1.93.0 and
# 1.99.0; 1.89.0/1.91.0/1.92.0 still store `pieces: &[&str]`):
#   literal   : len (1..=127) + bytes            | 0x80 + u16 LE len + bytes
#   placeholder: 0b11xxxxxx, then optional fields selected by the low bits:
#                bit0 flags u32, bit1 width u16, bit2 precision u16, bit3 arg_index u16 (bits 4,5 only change meaning)
#   end       : 0x00
TEMPLATE_MAX_BYTES = 4096
TEMPLATE_MAX_PARTS = 64


def parse_template(b: bytes, start: int = 0):
    """Parse one template starting at b[start]. Returns (end_offset_exclusive, literals, n_placeholders)
    or None if the bytes are not a well-formed template. Literal pieces must be UTF-8."""
    i, n = start, len(b)
    literals, holes, parts = [], 0, 0
    while True:
        if i >= n or parts > TEMPLATE_MAX_PARTS or i - start > TEMPLATE_MAX_BYTES:
            return None
        c = b[i]
        if c == 0x00:
            return i + 1, literals, holes
        parts += 1
        if 1 <= c <= 0x7F:
            piece = b[i + 1: i + 1 + c]
            if len(piece) < c or b"\x00" in piece or not is_utf8(piece):
                return None
            literals.append(piece); i += 1 + c
        elif c == 0x80:
            if i + 3 > n:
                return None
            ln = b[i + 1] | (b[i + 2] << 8)
            piece = b[i + 3: i + 3 + ln]
            if ln == 0 or len(piece) < ln or b"\x00" in piece or not is_utf8(piece):
                return None
            literals.append(piece); i += 3 + ln
        elif c >= 0xC0:
            holes += 1; i += 1
            if c & 0x01: i += 4
            if c & 0x02: i += 2
            if c & 0x04: i += 2
            if c & 0x08: i += 2
            if i > n:
                return None
        else:                       # 0x81..0xBF never start a part
            return None


def template_text(b: bytes, start: int, end: int) -> str:
    """Re-walk a validated template and render it as a format string with {} placeholders."""
    i, out = start, []
    while i < end - 1:
        c = b[i]
        if 1 <= c <= 0x7F:
            out.append(escape(b[i + 1: i + 1 + c], 10**9)); i += 1 + c
        elif c == 0x80:
            ln = b[i + 1] | (b[i + 2] << 8); out.append(escape(b[i + 3: i + 3 + ln], 10**9)); i += 3 + ln
        else:
            out.append("{}" if c == 0xC0 else "{:...}"); i += 1
            if c & 0x01: i += 4
            if c & 0x02: i += 2
            if c & 0x04: i += 2
            if c & 0x08: i += 2
    s = "".join(out)
    return s if len(s) <= 160 else s[:160] + f"...(+{len(s) - 160})"


def scan_templates(data: bytes, base: int, min_printable: float = 0.9):
    """Yield (abs_offset, nbytes, n_placeholders, n_literal_bytes, text) for every well-formed template
    with at least one placeholder and at least one printable literal piece. Sequential: a template that
    parses is skipped over, so a start inside an accepted template is never reported."""
    i, n = 0, len(data)
    while i < n:
        c = data[i]
        if c == 0x00 or 0x81 <= c <= 0xBF:
            i += 1; continue
        r = parse_template(data, i)
        if r is None:
            i += 1; continue
        end, literals, holes = r
        lit_bytes = sum(len(l) for l in literals)
        if holes >= 1 and literals and all(printable_ratio(l) >= min_printable for l in literals) and lit_bytes >= 1:
            yield base + i, end - i, holes, lit_bytes, template_text(data, i, end)
            i = end
        else:
            i += 1


def iter_qwords(read, start: int, end: int, window: int = WINDOW_BYTES, overlap: int = WINDOW_OVERLAP):
    """Yield (addr, q0, q1, q2) for every 8-aligned addr in [start, end-24], reading in windows."""
    pos = start & ~0x7
    while pos + 24 <= end:
        size = min(window, end - pos)
        data = read(pos, size)
        last = pos + size >= end
        limit = size if last else size - overlap
        n = (len(data) - 24) // 8 + 1
        qs = struct.unpack_from(f"<{(len(data) // 8)}Q", data, 0)
        for i in range(max(n, 0)):
            off = i * 8
            if off >= limit:
                break
            yield pos + off, qs[i], qs[i + 1], qs[i + 2]
        if last:
            break
        pos += limit


TEMPLATE_MIN_RUSTC = (1, 93)     # the byte-coded fmt::Arguments template exists from this version


def rustc_minor(version: str) -> Optional[Tuple[int, int]]:
    """'1.89.0' -> (1, 89); None when the string is not a version."""
    parts = version.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return None


def templates_supported(version: Optional[str]) -> Optional[bool]:
    """True/False when the compiler version is known, None when it is not."""
    v = rustc_minor(version) if version else None
    return None if v is None else v >= TEMPLATE_MIN_RUSTC


def _detect_rustc_full(read, regions: Regions, extra_map=None, max_bytes: int = 64 << 20):
    """The compiler fingerprint plus where it was found. Returns
    (version, commit, hits, rodata_hits, text_hits): the winning commit's hit count, and how the exe's
    hits for that commit split between its RODATA segment and its own EXEC (text) pages. The split drives
    merged-text detection (D-023): a binary whose constants are linked into the text segment has
    text_hits > 0 and rodata_hits == 0. (None, None, 0, 0, 0) when nothing is found."""
    from . import provenance as _prov
    counts: Dict[str, int] = {}
    where: Dict[str, List[int]] = {}      # commit -> [rodata_hits, text_hits]
    scanned = 0
    for start, end, hk, hname in regions.exe_const_rows():
        if scanned >= max_bytes:
            break
        for off in _prov.iter_pattern_offsets(read, start, min(end, start + max_bytes - scanned), patterns=(_prov.PATTERN_CORE,)):
            m = _prov.PATTERN_CORE.match(read(off, 96))
            if m and m.group("compiler"):
                c = m.group("commit").decode()
                counts[c] = counts.get(c, 0) + 1
                w = where.setdefault(c, [0, 0])
                w[0 if hk == RODATA else 1] += 1
        scanned += min(end, start + max_bytes - scanned) - start
    if not counts:
        return None, None, 0, 0, 0
    commit = max(counts, key=counts.get)
    version = _prov.version_for(commit, extra_map or {})
    rod, text = where[commit]
    return (version if rustc_minor(version) else None), commit, counts[commit], rod, text


def detect_rustc(read, regions: Regions, extra_map=None, max_bytes: int = 64 << 20):
    """(version, commit, hits) of the compiler that built this process, from the /rustc/<commit>/ paths
    its read-only data carries (ferric.provenance's compiler tier, same pattern). The most frequent commit
    wins; version comes from provenance's table (plus --commit-map). (None, None, 0) when nothing is found."""
    v, c, h, _, _ = _detect_rustc_full(read, regions, extra_map, max_bytes)
    return v, c, h


def rust_gate(read, regions: Regions, force: bool = False) -> bool:
    """D-021 (proposed, Session 83): the structural scanners (maps, vtables, tokio) run on a process only when
    its read-only data carries the /rustc/<commit>/ compiler fingerprint, the same test ferric.strings applies
    since 0.4.0 (D-018). Every control target passes it; non-Rust processes, which on a 98-process Windows guest
    took maps and tokio past 45 minutes, are skipped. force=True (--force-scan) scans regardless."""
    if force:
        return True
    return detect_rustc(read, regions)[1] is not None


def scan_regions(read, regions: Regions, kinds_to_scan, want, max_cap: int, min_printable: float,
                 str_anywhere: bool, force_layout: Optional[str] = None, all_layouts: bool = False):
    """Generate hit tuples:
       (kind, header_addr, header_region, ptr, target_region, len, cap, layout, checks, text)
    String candidates are collected under all six layouts first; the process-wide layout is then chosen
    by vote and only its candidates are emitted (all of them, tagged, with all_layouts=True). The chosen
    layout and the vote table are emitted as a final pseudo-row of kind 'layout'."""
    loc_addrs = set()
    string_cands = []
    for start, end, hk, hname in regions.str_scan_rows(kinds_to_scan):
        # On a merged-text executable the exe's own r-x pages carry its &str and Location structs; read
        # their quadwords as header candidates too. const_here says a region may hold such headers.
        const_here = hk in (RODATA, DATA) or regions.is_exe_text(hk, hname)
        if "template" in want and hk == RODATA:
            # fmt::Arguments templates (rustc >= 1.93) are byte sequences, not pointer structures
            pos = start
            while pos < end:
                size = min(WINDOW_BYTES, end - pos)
                data = read(pos, size)
                last = pos + size >= end
                limit = size if last else size - TEMPLATE_MAX_BYTES
                for off, nbytes, holes, lit_bytes, text in scan_templates(data, pos, min_printable):
                    if off - pos < limit:
                        yield ("template", off, hk, off, RODATA, nbytes, holes, "template", ["utf8", "printable", f"lits={lit_bytes}"], text)
                if last:
                    break
                pos += limit
        for addr, q0, q1, q2 in iter_qwords(read, start, end):
            words = (q0, q1, q2)
            if "location" in want and const_here:
                line, col = q2 & 0xFFFFFFFF, q2 >> 32
                v = validate_location(read, regions, q0, q1, line, col)
                if v is not None:
                    d, variant = v
                    loc_addrs.add(addr)
                    yield ("location", addr, hk, q0, RODATA, len(d), 0, "file,line,col", ["utf8", "rs", variant],
                           f"{escape(d, 160)}:{line}:{col}")
                    continue
            if "string" in want and hk in (HEAP, STACK, DATA):
                for layout in ((force_layout,) if force_layout else LAYOUTS):
                    v = validate_string_layout(read, regions, words, layout, max_cap, min_printable)
                    if v is not None:
                        ptr, cap, ln, d, checks = v
                        string_cands.append((layout, addr, hk, ptr, ln, checks, cap, d))
            if "str" in want and (const_here or str_anywhere):
                if addr in loc_addrs:
                    continue
                d = validate_str(read, regions, q0, q1, min_printable)
                if d is not None:
                    yield ("str", addr, hk, q0, RODATA, q1, 0, "ptr,len", ["utf8", "printable"], escape(d))
                elif q1 & 1 and q1 >> 1 >= 1:
                    # fmt::Arguments literal-only representation (rustc >= 1.93): (ptr, len << 1 | 1)
                    d = validate_str(read, regions, q0, q1 >> 1, min_printable)
                    if d is not None:
                        yield ("str", addr, hk, q0, RODATA, q1 >> 1, 0, "ptr,len<<1|1", ["utf8", "printable", "fmt-literal"], escape(d))
    if string_cands:
        layout, votes = (force_layout, None) if force_layout else vote_layout(string_cands)
        for l, addr, hk, ptr, ln, checks, cap, d in string_cands:
            if l == layout or all_layouts:
                yield ("string", addr, hk, ptr, HEAP, ln, cap, l, checks, escape(d))
        if votes is not None:
            summary = " ".join(f"{l}={n}" for l, n in votes.items() if n)
            yield ("layout", 0, "-", 0, "-", 0, 0, layout, ["vote"], f"String layout chosen by vote: {summary}")


# ----------------------------------------------------------------------------- per-process policy (0.4.0)
def template_refs(read, regions: Regions, addrs, lea: Optional[Dict[int, int]] = None):
    """How each fmt template at `addrs` is reached from the process itself. Returns (refs, code_seen):
    refs maps address -> ['lea:N'] when N RIP-relative LEA instructions in executable memory compute it (the
    way rustc materialises a fmt::Arguments on the stack), plus ['ptr:M'] when M 8-byte words in read-only,
    writable or stack memory hold its address (a promoted static Arguments); empty when nothing refers to it.
    code_seen is False when no LEA decoded to any data address at all, which happens when the code pages are
    absent from the image or the process has no executable mapping; the gate cannot be judged then."""
    from .vtables import lea_targets as _lea_targets        # lazy: vtables imports this module at load
    if lea is None:
        lea = _lea_targets(read, regions)
    want = set(addrs)
    refs: Dict[int, List[str]] = {a: [] for a in want}
    for a in want:
        n = lea.get(a, 0)
        if n:
            refs[a].append(f"lea:{n}")
    if want:
        ptr_counts: Dict[int, int] = {}
        for start, end, hk, hname in regions.of_kinds({RODATA, DATA, STACK}):
            pos = start
            while pos < end:
                size = min(WINDOW_BYTES, end - pos)
                data = read(pos, size)
                nq = len(data) // 8
                for q in struct.unpack_from(f"<{nq}Q", data, 0):
                    if q in want:
                        ptr_counts[q] = ptr_counts.get(q, 0) + 1
                pos += size
        for a, m in ptr_counts.items():
            refs[a].append(f"ptr:{m}")
    return refs, bool(lea)


def scan_process(read, regions: Regions, want, max_cap: int = STRING_MAX_CAP_DEFAULT, min_printable: float = 0.9,
                 str_anywhere: bool = False, force_layout: Optional[str] = None, all_layouts: bool = False,
                 force_templates: bool = False, force_scan: bool = False, all_candidates: bool = False,
                 commit_map: Optional[Dict[str, str]] = None):
    """Per-process policy on top of scan_regions, shared by the Linux and Windows shells. Yields hit tuples
    (kind, header, header_region, ptr, target_region, len, cap, layout, checks, text); the first is always
    the 'compiler' pseudo-hit stating what was decided and why.
      1. Rust fingerprint gate (0.4.0, D-018): a process whose read-only data carries no /rustc/<commit>/
         path is not scanned at all (force_scan scans it). Measured without the gate, the String header
         heuristic alone reports thousands of rows per non-Rust process set (eval/metrics.md, Session 67).
      2. Template version gate (0.3.2, D-017): the byte-coded template exists from rustc 1.93; older
         builds are not scanned for it (force_templates scans them).
      3. Template reference gate (0.4.0): a template is reported only when the process's own code computes
         its address (RIP-relative LEA) or its static data holds a pointer to it; all_candidates lists the
         rest tagged ref=none. When no code decodes at all (pages absent) the candidates are kept and
         tagged ref=unverifiable rather than dropped."""
    want = set(want)
    version, commit, hits, rod_hits, text_hits = _detect_rustc_full(read, regions, commit_map or {})
    # D-023: the executable's constants are merged into its text segment when every compiler path sits in
    # its r-x pages and none in a separate r-- segment. Only then are its EXEC pages read for &str/Location
    # (headers and targets); an ordinary separate-rodata binary keeps merged_text False and is unchanged.
    regions.merged_text = bool(commit and regions.exe and text_hits > 0 and rod_hits == 0)
    fp = f"{commit[:12]}, {hits} hits" if commit else "none"
    if not commit and not force_scan:
        yield ("compiler", 0, "-", 0, "-", 0, 0, "-", ["provenance"],
               "no Rust compiler fingerprint in read-only data: not scanned (--force-scan to scan anyway)")
        return
    notes = []
    if "template" in want:
        ok = templates_supported(version)
        if ok is False and not force_templates:
            want.discard("template")
            notes.append("templates not scanned, format exists from 1.93 (--force-templates to scan)")
        elif ok is None:
            notes.append("templates scanned (compiler version unknown)")
        else:
            notes.append("templates scanned")
    if regions.merged_text:
        notes.append("merged-text layout: constants in the text segment, &str/Location read from exe code (D-023)")
    if version:
        head = f"rustc {version} ({fp})"
    elif commit:
        head = f"compiler unknown ({fp})"
    else:
        head = "no Rust fingerprint, scanned on --force-scan"
    yield ("compiler", 0, "-", 0, "-", 0, 0, "-", ["provenance"], head + (": " + "; ".join(notes) if notes else ""))
    pending = []
    for hit in scan_regions(read, regions, {HEAP, STACK, DATA, RODATA}, want, max_cap, min_printable,
                            str_anywhere, force_layout, all_layouts):
        if hit[0] == "template":
            pending.append(hit)
        else:
            yield hit
    if not pending:
        return
    refs, code_seen = template_refs(read, regions, [h[1] for h in pending])
    kept = lea_n = ptr_n = 0
    for h in pending:
        r = refs.get(h[1], [])
        checks = list(h[8])
        if r:
            checks += r
            kept += 1
            lea_n += any(x.startswith("lea:") for x in r)
            ptr_n += any(x.startswith("ptr:") for x in r)
        elif not code_seen:
            checks.append("ref=unverifiable")
            kept += 1
        elif all_candidates:
            checks.append("ref=none")
        else:
            continue
        yield h[:8] + (checks, h[9])
    if code_seen:
        summary = (f"fmt templates referenced from code or static data: {kept} of {len(pending)} candidates "
                   f"(lea {lea_n}, ptr {ptr_n}); unreferenced "
                   + ("listed as ref=none" if all_candidates else "dropped (--all-candidates to list)"))
    else:
        summary = (f"fmt templates: {len(pending)} candidates kept unverified; no RIP-relative LEA decoded in "
                   "executable memory (code pages absent from the image?)")
    yield ("templates", 0, "-", 0, "-", kept, len(pending), "-", ["ref"], summary)


# ----------------------------------------------------------------------------- plugin
class Strings(plugins.PluginInterface):
    """Recovers Rust String, &str and core::panic::Location objects from process memory by
    validating their headers (fat pointers) against the bytes they reference."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 4, 2)   # 0.4.2: &str/Location read from the exe's text on a merged-text layout (D-023, gated on merged_text)
                           # 0.4.1: the fingerprint gate also reads the main executable's EXEC pages (D-022)   # 0.3.1: Location 1.89 len-with-nul variant; NUL inside &str/template literals rejected
                           # 0.3.2: templates scanned only when the process's compiler is >= 1.93 (or unknown)
                           # 0.4.0: processes without a Rust compiler fingerprint are not scanned (--force-scan);
                           #        templates kept only when referenced from code or static data (--all-candidates);
                           #        policy moved into scan_process, shared with ferric.win.Strings

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid", description="Filter on specific process IDs", element_type=int, optional=True,
            ),
            requirements.ListRequirement(
                name="kinds", description="Object kinds to recover: string, str, location, template (default all)",
                element_type=str, optional=True,
            ),
            requirements.IntRequirement(
                name="max-cap", description="Maximum String capacity considered",
                default=STRING_MAX_CAP_DEFAULT, optional=True,
            ),
            requirements.IntRequirement(
                name="min-len", description="Minimum string length to report", default=1, optional=True,
            ),
            requirements.BooleanRequirement(
                name="strict-chunk", description="Report a String only when the glibc malloc chunk size "
                "agrees with its capacity", default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="str-anywhere", description="Also look for &str headers in heap/stack memory "
                "(more false positives)", default=False, optional=True,
            ),
            requirements.StringRequirement(
                name="layout", description="Force the String field order instead of voting, e.g. cap,ptr,len",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-layouts", description="Emit String candidates under every field order (tagged) "
                "instead of only the voted one", default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-utf8", description="Report any valid-UTF-8 String, including mostly "
                "non-printable content (default requires at least 90%% printable)", default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump", description="Write every row as TSV to a file per process", default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="force-templates", description="Scan for fmt templates even when the process was built "
                "by a compiler older than 1.93 (every hit is then a false parse; for measurement)",
                default=False, optional=True,
            ),
            requirements.StringRequirement(
                name="commit-map", description="CSV of rustc commit,version pairs (as ferric.provenance)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="force-scan", description="Scan a process even when its read-only data carries no "
                "/rustc/<commit>/ fingerprint (default: such processes get one 'compiler' row and no scan)",
                default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-candidates", description="List fmt templates that nothing in the process refers to "
                "(tagged ref=none) instead of dropping them", default=False, optional=True,
            ),
        ]

    def _commit_map(self) -> Dict[str, str]:
        path = self.config.get("commit-map", None)
        extra: Dict[str, str] = {}
        if not path:
            return extra
        try:
            import csv, re
            with open(path, newline="") as f:
                for row in csv.reader(f):
                    if len(row) >= 2 and re.fullmatch(r"[0-9a-f]{40}", row[0].strip()):
                        extra[row[0].strip()] = row[1].strip()
        except OSError as e:
            vollog.warning(f"commit-map not readable ({e}); using built-in table only")
        return extra

    def _regions(self, task) -> Regions:
        rows = []
        exe_vma = None
        try:
            start_code = int(task.mm.start_code)
        except exceptions.InvalidAddressException:
            start_code = 0
        vmas = []
        for vma in task.mm.get_vma_iter():
            try:
                s, e = int(vma.vm_start), int(vma.vm_end)
                prot = vma.get_protection()
                fb = int(vma.vm_file) != 0
            except exceptions.InvalidAddressException:
                continue
            name = vma.get_name(self.context, task) or ("[anon]" if not fb else "[file]")
            vmas.append((s, e, prot, fb, name))
            if fb and s <= start_code < e:
                exe_vma = name
        for s, e, prot, fb, name in vmas:
            is_exe = fb and exe_vma is not None and name == exe_vma
            kind = classify_vma(prot, fb, name, is_exe)
            rows.append((s, e, kind, name))
        regs = Regions(rows)
        regs.exe = exe_vma
        return regs

    def _generator(self, tasks: Iterable):
        want = set(self.config.get("kinds", None) or ["string", "str", "location", "template"])
        max_cap = int(self.config.get("max-cap", STRING_MAX_CAP_DEFAULT))
        min_len = int(self.config.get("min-len", 1))
        strict = bool(self.config.get("strict-chunk", False))
        anywhere = bool(self.config.get("str-anywhere", False))
        dump = bool(self.config.get("dump", False))
        min_printable = 0.0 if self.config.get("all-utf8", False) else 0.9
        force_layout = self.config.get("layout", None)
        if force_layout and force_layout not in LAYOUTS:
            vollog.error(f"--layout must be one of {LAYOUTS}"); return
        all_layouts = bool(self.config.get("all-layouts", False))
        force_templates = bool(self.config.get("force-templates", False))
        force_scan = bool(self.config.get("force-scan", False))
        all_candidates = bool(self.config.get("all-candidates", False))
        commit_map = self._commit_map()
        for task in tasks:
            try:
                if not (task.mm and task.mm.is_readable()):
                    continue
            except exceptions.InvalidAddressException:
                continue
            pid = int(task.pid)
            name = utility.array_to_string(task.comm)
            layer_name = task.add_process_layer()
            if not layer_name:
                continue
            layer = self.context.layers[layer_name]
            regions = self._regions(task)
            read = lambda off, n: layer.read(off, n, pad=True)
            lines = []
            for kind, haddr, hk, ptr, tk, ln, cap, order, checks, text in scan_process(
                    read, regions, want, max_cap, min_printable, anywhere, force_layout, all_layouts,
                    force_templates, force_scan, all_candidates, commit_map):
                if kind not in ("layout", "compiler", "templates") and ln < min_len:
                    continue
                if kind == "string" and strict and "chunk" not in checks:
                    continue
                row = (pid, name, kind, format_hints.Hex(haddr), hk, format_hints.Hex(ptr), tk,
                       ln, cap, order, ",".join(checks), text)
                if dump:
                    lines.append("\t".join(str(x) if not isinstance(x, format_hints.Hex) else f"{int(x):#x}" for x in row))
                yield (0, row)
            if dump and lines:
                fh = self.open(f"pid.{pid}.ferric-strings.tsv")
                fh.write(("\n".join(lines) + "\n").encode())
                fh.close()
                vollog.info(f"wrote {len(lines)} rows to {fh.preferred_filename}")

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            [
                ("PID", int), ("Process", str), ("Kind", str), ("Header", format_hints.Hex),
                ("HeaderIn", str), ("Ptr", format_hints.Hex), ("PtrIn", str), ("Len", int), ("Cap", int),
                ("Layout", str), ("Checks", str), ("Text", str),
            ],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=filter_func)),
        )
