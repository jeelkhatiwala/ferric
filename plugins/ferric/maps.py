# ferric.maps — Rust HashMap/HashSet (hashbrown SwissTable) recovery from process memory.
#
# Volatility 3 framework 2.28.2, Linux x86-64 (8-byte usize). Shares region classification with
# ferric.strings so "where a pointer lives" is judged the same way across the suite.
#
# What a Rust HashMap looks like in memory
#   std::collections::HashMap wraps hashbrown's HashMap, whose table is a RawTableInner. Its four fields
#   are, in source order:
#       struct RawTableInner { bucket_mask: usize, ctrl: NonNull<u8>, growth_left: usize, items: usize }
#   BUT RawTableInner is a plain repr(Rust) struct, so the compiler is free to reorder these four words in
#   memory, and it does (exactly as it reorders String's fields — see ferric.strings, which measured
#   (cap,ptr,len) on rustc 1.99 rather than the declared (ptr,cap,len)). So v0.2 does NOT assume the word
#   order. It identifies the fields by their properties instead:
#       * ctrl is the one word that points into readable heap/data/rodata memory.
#       * bucket_mask is a word equal to 2^k - 1 (capacity = bucket_mask + 1 is a power of two).
#       * items is pinned by the control bytes (see below); growth_left is the remaining word.
#   `ctrl` points to an array of one control byte per bucket, plus a replicated Group::WIDTH-byte group at
#   the end for SIMD probing. A control byte is EMPTY 0xFF, DELETED 0x80, or FULL 0x00..0x7F (top 7 bits
#   of the hash). A slot is FULL iff (byte & 0x80) == 0.
#
# The load-bearing invariant (what makes this low-false-positive, and what v0.1 got wrong)
#   hashbrown GUARANTEES at least one non-FULL bucket at all times, because a probe sequence must hit an
#   EMPTY to know a key is absent; the table resizes at 7/8 load before it would fill. Therefore a genuine
#   table always has items < capacity and at least one 0xFF control byte. v0.1 allowed items == capacity,
#   so it accepted runs of all-FULL control bytes (heap metadata, zeroed regions) as "100%-load tables" —
#   those are impossible and were false positives. v0.2 rejects any candidate whose control array has no
#   EMPTY byte.
#
# The control-byte replication signature (v0.3 — what makes it specific to hashbrown, not just plausible)
#   The control array is `buckets + Group::WIDTH` bytes long, and hashbrown maintains a replicated copy of
#   the leading group at the tail so that a SIMD probe starting near the end wraps correctly: on every
#   set_ctrl it writes both ctrl[i] and ctrl[((i - WIDTH) & bucket_mask) + WIDTH]. In practice:
#     * buckets >= WIDTH:  ctrl[buckets + i] == ctrl[i]           for i in 0..WIDTH
#     * buckets <  WIDTH:  ctrl[buckets..WIDTH] are all EMPTY(0xFF), and ctrl[WIDTH..WIDTH+buckets] == ctrl[0..buckets]
#   This byte-for-byte echo is a hard hashbrown invariant that an unrelated heap region (C/C++/Python
#   process memory) satisfies only by astronomical coincidence. v0.2's numeric checks still fired on
#   non-Rust processes (measured: systemd, systemd-udevd, python3 on a real image); requiring the
#   replication signature removes those while keeping the ground-truth map on seed01. This is the
#   distinguishing structural signal and the reason the plugin is hashbrown-specific rather than
#   SwissTable-shaped-number-specific.
#
# The recovery technique and its own cross-check
#   For a candidate (ctrl, bucket_mask) we read the capacity control bytes and count FULL/DELETED/EMPTY.
#   We accept only when:
#     * capacity = bucket_mask + 1 is a power of two in a sane range,
#     * ctrl points into readable heap/data/rodata with room for capacity + Group::WIDTH bytes,
#     * there is at least one EMPTY byte (the invariant above),
#     * 0 < full <= usable_capacity, where usable_capacity = bucket_mask (mask<8) else (bucket_mask+1)/8*7,
#     * one of the two remaining words equals `full` (the struct's `items` must agree with the control
#       bytes — the cross-check a plain byte scan cannot do),
#     * the last remaining word (growth_left) is in [0, usable_capacity].
#   growth_left == usable_capacity - items - deleted is reported as a corroborating flag (gl) when it holds
#   (it can legitimately not hold across some tombstone histories, so it is a flag, not a gate).
#   The empty-map singleton (bucket_mask=0, ctrl -> static all-0xFF group, items=0) is skipped.
#
# Entry recovery (v0.4)
#   Buckets lie BELOW ctrl: bucket i's bytes are at ctrl - (i+1)*stride, where stride = size_of::<(K,V)>().
#   A stripped binary does not say what (K,V) is, so the stride is inferred. hashbrown allocates data and
#   control bytes as ONE block: ctrl_offset = round_up(stride*buckets, 16) and the block is
#   ctrl_offset + buckets + 16 bytes (TableLayout::calculate_layout_for, identical in 0.11 through 0.17),
#   so under glibc malloc the chunk size field at block_start - 8 pins the stride exactly ("stride by chunk").
#   Without that field (musl, jemalloc, mimalloc) the stride that decodes the most typed fields across all
#   full buckets is taken and labelled "stride by content"; a tie is reported, not guessed. Each full bucket
#   is then decoded left to right: a 3-word String header (every field order tried; the order the process
#   uses is settled by majority across the table), a 2-word &str into read-only data, otherwise a raw word.
#   Validated on the controls: seed01/seed02 HashMap<String,String> and seed03 HashMap<String,f64>.
#
# What is reported
#   One 'table' row per recovered table, then one 'entry' row per full bucket: buckets (physical, = bucket_mask+1), items, tombstones (DELETED), load
#   (items/buckets, always < 100% for a real table), where ctrl lives, and the header address. Key/value
#   extraction needs the entry type (K,V) which a stripped binary does not carry; for String-keyed maps the
#   bucket region can be fed to ferric.strings. --explain surfaces structural near-misses (a readable
#   ctrl + power-of-two mask whose item word did not corroborate, or which was full) so a missing table on
#   a ground-truth image can be diagnosed rather than guessed at.

import struct
from typing import Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist
import logging
vollog = logging.getLogger(__name__)
from .strings import rust_gate as _strings_gate

from .strings import (Regions, classify_vma, HEAP, RODATA, DATA, STACK, EXEC, OTHER, LAYOUTS,
                      validate_string_layout, validate_str, glibc_chunk_expected, escape)

GROUP_WIDTH = 16                      # x86-64 SSE2 hashbrown group
CAP_MIN = 4                           # hashbrown's smallest allocated table is 4 buckets
CAP_MAX = 1 << 20                     # bounds the control-byte read; a >1M-bucket malware map is implausible
WINDOW = 8 * 1024 * 1024
OVERLAP = 64
EXPLAIN_CAP = 256                     # most near-miss rows surfaced per process in --explain
STRIDES = tuple(range(8, 257, 8))     # candidate entry sizes: (K,V) tuples holding pointers are 8-aligned
ENTRY_CAP = 4096                      # most entry rows emitted per table


def build_regions(context, task) -> Regions:
    """Same VMA classification ferric.strings uses (anon rw -> heap/stack, exe r-- -> rodata, exe rw ->
    data, anon r-- -> rodata)."""
    rows, vmas, exe = [], [], None
    try:
        start_code = int(task.mm.start_code)
    except exceptions.InvalidAddressException:
        start_code = 0
    for vma in task.mm.get_vma_iter():
        try:
            s, e = int(vma.vm_start), int(vma.vm_end)
            prot = vma.get_protection()
            fb = int(vma.vm_file) != 0
        except exceptions.InvalidAddressException:
            continue
        name = vma.get_name(context, task) or ("[anon]" if not fb else "[file]")
        vmas.append((s, e, prot, fb, name))
        if fb and s <= start_code < e:
            exe = name
    for s, e, prot, fb, name in vmas:
        rows.append((s, e, classify_vma(prot, fb, name, fb and exe is not None and name == exe), name))
    regs = Regions(rows)
    regs.exe = exe
    return regs


def popcount_full(ctrl: bytes) -> Tuple[int, int]:
    """Return (full, deleted) over control bytes. FULL = high bit clear; DELETED = exactly 0x80."""
    full = deleted = 0
    for b in ctrl:
        if b & 0x80 == 0:
            full += 1
        elif b == 0x80:
            deleted += 1
    return full, deleted


def usable_capacity(bucket_mask: int) -> int:
    """hashbrown bucket_mask_to_capacity: the number of entries the table holds before it resizes."""
    return bucket_mask if bucket_mask < 8 else ((bucket_mask + 1) // 8) * 7


def mirror_ok(cfull: bytes, buckets: int) -> bool:
    """Check hashbrown's replicated-group invariant over a control array of length buckets + GROUP_WIDTH.
    The leading group is echoed at the tail; for sub-group tables the gap is EMPTY. A non-Rust heap
    region satisfies this byte-for-byte echo only by coincidence, so it is the hashbrown-specific gate."""
    w = GROUP_WIDTH
    if len(cfull) < buckets + w:
        return False
    if buckets >= w:
        return cfull[buckets:buckets + w] == cfull[0:w]
    # sub-group table: bytes between the real slots and the group width are EMPTY, then the slots repeat
    if any(b != 0xFF for b in cfull[buckets:w]):
        return False
    return cfull[w:w + buckets] == cfull[0:buckets]


def read_ctrl(read, regions: Regions, ctrl: int, bucket_mask: int):
    """Cheap structural gates + the one control-byte read shared by every field arrangement. Reads the
    full control array (buckets + GROUP_WIDTH) and requires hashbrown's replication signature.
    Returns (capacity, usable, full, deleted, empty) or None."""
    if bucket_mask & (bucket_mask + 1) != 0:          # bucket_mask must be 2^k - 1
        return None
    capacity = bucket_mask + 1
    if not (CAP_MIN <= capacity <= CAP_MAX):
        return None
    if regions.kind(ctrl) not in (HEAP, DATA, RODATA):
        return None
    tgt = regions.lookup(ctrl)
    if tgt is None or ctrl + capacity + GROUP_WIDTH > tgt[1]:
        return None
    try:
        cfull = read(ctrl, capacity + GROUP_WIDTH)    # real slots + the replicated trailing group
    except Exception:
        return None
    if not mirror_ok(cfull, capacity):                # the hashbrown-specific structural gate (v0.3)
        return None
    full, deleted = popcount_full(cfull[:capacity])
    return capacity, usable_capacity(bucket_mask), full, deleted, capacity - full - deleted


def _accept(words, ci, mi, facts):
    """Given a window's 4 words, the ctrl index ci, the mask index mi, and the control-byte facts, test
    the two remaining words as (items, growth_left) in both arrangements. Returns
    (capacity, items, growth_left, deleted, ctrl, usable, gl_ok) or None."""
    capacity, usable, full, deleted, empty = facts
    if empty < 1 or not (0 < full <= usable):           # the invariant + a sane live count
        return None
    rest = [j for j in range(4) if j not in (ci, mi)]
    for items_j, gl_j in ((rest[0], rest[1]), (rest[1], rest[0])):
        items, growth_left = words[items_j], words[gl_j]
        if items != full:                               # struct's item count must match the control bytes
            continue
        if not (0 <= growth_left <= usable):
            continue
        gl_ok = growth_left == usable - items - deleted
        return capacity, full, growth_left, deleted, words[ci], usable, gl_ok
    return None


def scan_window(read, regions: Regions, words, explain=False):
    """Try a 4-word window as a RawTableInner under any field order. Returns (accepted, nearmisses):
    accepted is a list of result tuples (one per viable (ctrl,mask) choice), nearmisses a list of
    (ctrl, capacity, full, deleted, empty, other_words) for readable ctrl+mask pairs that failed only the
    item cross-check or the empty invariant (explain only)."""
    accepted, near = [], []
    for ci in range(4):
        if regions.kind(words[ci]) not in (HEAP, DATA, RODATA):
            continue
        for mi in range(4):
            if mi == ci:
                continue
            facts = read_ctrl(read, regions, words[ci], words[mi])
            if facts is None:
                continue
            res = _accept(words, ci, mi, facts)
            if res is not None:
                accepted.append(res)
            elif explain:
                capacity, usable, full, deleted, empty = facts
                if 0 < full <= usable:                  # a plausible-looking table that did not corroborate
                    rest = [words[j] for j in range(4) if j not in (ci, mi)]
                    near.append((words[ci], capacity, full, deleted, empty, rest))
    return accepted, near


def iter_candidates(read, start: int, end: int, window: int = WINDOW, overlap: int = OVERLAP):
    """Yield (addr, w0,w1,w2,w3) for every 8-aligned 32-byte window in [start, end)."""
    pos = start & ~0x7
    while pos + 32 <= end:
        size = min(window, end - pos)
        data = read(pos, size)
        last = pos + size >= end
        limit = size if last else size - overlap
        n = (len(data) - 32) // 8 + 1
        if len(data) >= 8:
            qs = struct.unpack_from(f"<{len(data)//8}Q", data, 0)
            for i in range(max(n, 0)):
                off = i * 8
                if off >= limit:
                    break
                yield pos + off, qs[i], qs[i + 1], qs[i + 2], qs[i + 3]
        if last:
            break
        pos += limit


def validate_table(read, regions: Regions, words: Tuple[int, int, int, int]):
    """Source-order validator kept for unit tests: words = (bucket_mask, ctrl, growth_left, items).
    Applies the v0.2 invariant (>=1 empty bucket, items == full control-byte count). Returns
    (capacity, items, growth_left, deleted, ctrl) or None."""
    bucket_mask, ctrl, growth_left, items = words
    facts = read_ctrl(read, regions, ctrl, bucket_mask)
    if facts is None:
        return None
    capacity, usable, full, deleted, empty = facts
    if empty < 1 or not (0 < full <= usable):
        return None
    if items != full or not (0 <= growth_left <= usable):
        return None
    return capacity, items, growth_left, deleted, ctrl


class Maps(plugins.PluginInterface):
    """Recovers Rust HashMap/HashSet (hashbrown) tables from process memory by validating RawTable
    control blocks against their control bytes, independent of in-memory field order, and decodes
    the entries of each table (v0.4)."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 5, 3)   # 0.5.3: Rust fingerprint gate (D-021, --force-scan); 0.5.2: process-wide String order off glibc, --debug-ctrl stride trace; 0.5.1: signature agreement in the content stride, Vec<u8> without a glibc chunk off-glibc; 0.5.0: content stride by mean typed fraction (Windows NT heap); 0.4.0: entry recovery (stride by chunk/content, typed fields); header chosen by gl
                           # 0.4.1: a nested table's RawTableInner is recognised before the String reading of the same words

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 0, 0)),
            requirements.ListRequirement(
                name="pid", description="Filter on specific process IDs", element_type=int, optional=True
            ),
            requirements.IntRequirement(
                name="min-items", description="Only report tables with at least this many live items",
                default=1, optional=True,
            ),
            requirements.BooleanRequirement(
                name="explain", description="Also report structural near-misses (readable ctrl + "
                "power-of-two mask whose item count did not corroborate), to diagnose missing tables",
                default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="no-entries", description="Report tables only; skip entry decoding",
                default=False, optional=True,
            ),
            requirements.IntRequirement(
                name="max-entries", description="Most entry rows emitted per table", default=ENTRY_CAP,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="force-scan", description="Scan a process even when its read-only data carries no "
                "/rustc/<commit>/ compiler fingerprint (default: such processes are skipped)",
                default=False, optional=True,
            ),
        ]

    def _scan_task(self, task, min_items: int, explain: bool, entries: bool, max_entries: int):
        pid = int(task.pid)
        name = utility.array_to_string(task.comm)
        layer_name = task.add_process_layer()
        if not layer_name:
            return
        layer = self.context.layers[layer_name]
        regions = build_regions(self.context, task)
        read = lambda off, n: layer.read(off, n, pad=True)
        if not _strings_gate(read, regions, bool(self.config.get("force-scan", False))):
            vollog.info(f"pid {pid} ({name}): no Rust compiler fingerprint, not scanned (--force-scan)")
            return
        yield from scan_process(read, regions, pid, name, min_items, explain, entries, max_entries)

    def _generator(self, tasks: Iterable):
        min_items = int(self.config.get("min-items", 1))
        explain = bool(self.config.get("explain", False))
        entries = not bool(self.config.get("no-entries", False))
        max_entries = int(self.config.get("max-entries", ENTRY_CAP))
        for task in tasks:
            try:
                if not (task.mm and task.mm.is_readable()):
                    continue
            except exceptions.InvalidAddressException:
                continue
            yield from self._scan_task(task, min_items, explain, entries, max_entries)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(COLUMNS, self._generator(
            pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=filter_func)))


COLUMNS = [
    ("PID", int), ("Process", str), ("Kind", str), ("Header", format_hints.Hex), ("HeaderIn", str),
    ("Ctrl", format_hints.Hex), ("Buckets", int), ("Items", int), ("Deleted", int), ("Load", str),
    ("Stride", int), ("Bucket", int), ("Tag", int), ("Fields", str), ("Note", str),
]


# ----------------------------------------------------------------------------- v0.4 entry recovery
def scan_process(read, regions: Regions, pid: int, name: str, min_items: int = 1, explain: bool = False,
                 entries: bool = True, max_entries: int = ENTRY_CAP, debug_ctrl: Optional[int] = None):
    """All of the per-process work, as a generator of TreeGrid rows (COLUMNS). Pure: takes a read
    function and a Regions table, so a live process (/proc) and a Volatility layer are scanned by
    exactly the same code."""
    na = renderers.NotAvailableValue()
    # ctrl -> best (addr, kind, capacity, items, growth_left, deleted, usable, gl_ok); a window whose
    # growth_left corroborates (gl) beats an earlier, shifted window on the same ctrl (v0.4)
    best: Dict[int, tuple] = {}
    near_rows = []
    explained = 0
    for s, e, kind, nm in regions.rows:
        if kind not in (HEAP, STACK, DATA):
            continue
        for addr, w0, w1, w2, w3 in iter_candidates(read, s, e):
            accepted, near = scan_window(read, regions, (w0, w1, w2, w3), explain)
            for capacity, items, growth_left, deleted, ctrl, usable, gl_ok in accepted:
                if items < min_items:
                    continue
                cur = best.get(ctrl)
                if cur is None or (gl_ok and not cur[7]):
                    best[ctrl] = (addr, kind, capacity, items, growth_left, deleted, usable, gl_ok)
            if explain:
                for ctrl, capacity, full, deleted, empty, rest in near:
                    if explained >= EXPLAIN_CAP:
                        break
                    explained += 1
                    near_rows.append((addr, kind, ctrl, capacity, full, deleted, empty, rest))
    xref_all = {c: best[c][3] for c in best}      # every table found, for the nested cross reference
    # pass 1: stride and a first decode of every table; pass 2 re-decodes under one String field order.
    # Off glibc (0.5.2) the order is voted over ALL tables of the process: without a chunk check a
    # (u64, String) entry also reads as a String whose capacity is the u64 key under another field order,
    # and a table made only of such entries outvotes itself (seed05 'ids' on Windows: 0/20 under 0.5.1).
    # On glibc the per-table vote is kept unchanged, so the Linux tables cannot move.
    staged = []
    for ctrl in sorted(best, key=lambda c: best[c][0]):
        addr, kind, capacity, items, growth_left, deleted, usable, gl_ok = best[ctrl]
        trace = [] if (debug_ctrl is not None and ctrl == debug_ctrl) else None
        stride, how = (None, "skipped") if not entries else infer_stride(read, regions, ctrl, capacity, tables=xref_all, trace=trace)
        decoded = []
        if entries and stride is not None:
            for i, h2, data, eaddr in read_entries(read, regions, ctrl, capacity, stride, max_entries):
                decoded.append((i, h2, eaddr, decode_entry(read, regions, data, eaddr, tables=xref_all)))
        staged.append((ctrl, stride, how, decoded, trace))
    proc_hint = None
    if getattr(regions, "allocator", "glibc") != "glibc":
        proc_hint = table_layout_vote([d[3] for _c, _s, _h, dec, _t in staged for d in dec])
    for ctrl, stride, how, decoded, trace in staged:
        addr, kind, capacity, items, growth_left, deleted, usable, gl_ok = best[ctrl]
        load = f"{100.0 * items / capacity:.0f}%"
        note = f"cap={usable}" + (" gl" if gl_ok else "") + f" stride={stride if stride else '?'}:{how}"
        yield (0, (pid, name, "table", format_hints.Hex(addr), kind, format_hints.Hex(ctrl),
                   capacity, items, deleted, load, stride if stride else na, na, na, "", note))
        for st, n, mean, agree, score in (trace or []):
            yield (0, (pid, name, "stride", format_hints.Hex(addr), kind, format_hints.Hex(ctrl),
                       capacity, items, deleted, load, st, na, na, "",
                       f"buckets={n} typed={mean:.3f} agree={agree:.3f} score={score:.3f}"))
        if not entries or stride is None:
            continue
        hint = proc_hint or table_layout_vote([d[3] for d in decoded])
        if hint:                          # re-decode under the majority String order
            decoded = [(i, h2, eaddr, decode_entry(read, regions, read(eaddr, stride), eaddr, layout_hint=hint, tables=xref_all))
                       for i, h2, eaddr, _f in decoded]
        for i, h2, eaddr, fields in decoded:
            yield (0, (pid, name, "entry", format_hints.Hex(eaddr), kind, format_hints.Hex(ctrl),
                       capacity, items, deleted, load, stride, i, h2, render_fields(fields),
                       f"layout={hint}" if hint else ""))
    for addr, kind, ctrl, capacity, full, deleted, empty, rest in near_rows:
        if ctrl in best:
            continue                      # a shifted window of a recovered table is not a near-miss
        reason = "no-empty" if empty < 1 else "items!=full"
        load = f"{100.0 * full / capacity:.0f}%"
        note = f"NEAR {reason} full={full} empty={empty} others=" + ",".join(f"{w:#x}" for w in rest)
        yield (0, (pid, name, "near", format_hints.Hex(addr), kind, format_hints.Hex(ctrl),
                   capacity, full, deleted, load, na, na, na, "", note))


def block_len(stride: int, buckets: int) -> Tuple[int, int]:
    """(ctrl_offset, total_len) of hashbrown's single allocation for `buckets` entries of `stride` bytes:
    data first, control bytes at ctrl_offset = round_up(stride*buckets, 16), then buckets+16 control bytes."""
    ctrl_offset = (stride * buckets + 15) & ~15
    return ctrl_offset, ctrl_offset + buckets + GROUP_WIDTH


def stride_by_chunk(read, regions: Regions, ctrl: int, buckets: int) -> Optional[int]:
    """The stride whose allocation block agrees with the glibc chunk size field in front of it, or None."""
    hits = []
    for s in STRIDES:
        ctrl_offset, total = block_len(s, buckets)
        start = ctrl - ctrl_offset
        tgt = regions.lookup(start - 8)
        if tgt is None or tgt[2] not in (HEAP, DATA) or tgt != regions.lookup(ctrl):
            continue
        try:
            (size,) = struct.unpack("<Q", read(start - 8, 8))
        except Exception:
            continue
        if (size & ~0x7) == glibc_chunk_expected(total):
            hits.append(s)
    return hits[0] if len(hits) == 1 else None


def validate_vec_layout(read, regions: Regions, words, layout: str, max_cap: int):
    """A Vec<u8>-like header: same three words as a String but the bytes need not be text. Returns
    (ptr, cap, len, data, checks) or None. Requires the glibc chunk to agree, since the text check that
    anchors String candidates is absent here."""
    pi, ci, li = (layout.split(",").index(f) for f in ("ptr", "cap", "len"))
    ptr, cap, ln = words[pi], words[ci], words[li]
    if not (1 <= ln <= cap <= max_cap):
        return None
    tgt = regions.lookup(ptr)
    if tgt is None or tgt[2] != HEAP or ptr + ln > tgt[1]:
        return None
    try:
        (size,) = struct.unpack("<Q", read(ptr - 8, 8))
        d = read(ptr, min(ln, 64))
    except Exception:
        return None
    if getattr(regions, "allocator", "glibc") != "glibc":
        # NT heap (Windows), musl, jemalloc: no size field to agree with. Accepted only for a plausible
        # buffer (capacity under 64 KiB, data not all zero), and only ever inside a validated hashbrown
        # bucket, which is the only caller (0.5.1; the first Windows matrix lost every Vec<u8> value)
        if cap > (1 << 16) or not d.strip(b"\0"):
            return None
        return ptr, cap, ln, d, ["heap"]
    if (size & ~0x7) != glibc_chunk_expected(cap):
        return None
    return ptr, cap, ln, d, ["chunk"]


def decode_entry(read, regions: Regions, data: bytes, base: int, max_cap: int = 1 << 20, layout_hint=None,
                 tables=None):
    """Decode one bucket's bytes into typed fields, left to right. Returns a list of
    (kind, offset, text, layout, len, cap, checks) with kind in
    {'String', 'Vec<u8>', '&str', 'HashMap', 'ptr', 'u64'}. `tables` (ctrl -> items) lets a nested
    table be labelled by cross-reference instead of being shown as a bare pointer."""
    fields = []
    n = len(data) // 8
    words = struct.unpack(f"<{n}Q", data[: n * 8])

    def string_at(j):
        """Best String reading of words[j:j+3]: a chunk-consistent one wins over a merely valid one."""
        got = None
        for layout in ((layout_hint,) if layout_hint else LAYOUTS):
            v = validate_string_layout(read, regions, words[j:j + 3], layout, max_cap)
            if v is not None and (got is None or "chunk" in v[4]):
                got = (layout, v)
                if "chunk" in v[4]:
                    break
        return got

    def nested_at(i):
        """A RawTableInner of a table this scan already found: one word equals a known ctrl pointer and
        another is a bucket mask (2^k - 1, k >= 2). Tested BEFORE the String reading (0.4.1): the 1.71
        field order (ctrl, bucket_mask, growth_left, items) reads as a String (ptr, cap, len) whenever the
        first `growth_left` control bytes happen to be printable (seed05 'west' on s5sweep-01: "L`")."""
        if not tables or i + 4 > n:
            return None
        w4 = words[i:i + 4]
        # RawTableInner is (bucket_mask, ctrl, growth_left, items) as declared or (ctrl, bucket_mask, ...) as
        # rustc lays it out: ctrl and mask are the first two words, in either order. Requiring that keeps a
        # String (ptr, cap, len) followed by a nested table's ctrl word from being swallowed as a table when
        # its cap or len happens to be 2^k - 1.
        for ci in (0, 1):
            ctrl, mask = w4[ci], w4[1 - ci]
            if ctrl in tables and (mask & (mask + 1)) == 0 and mask >= 3:
                return ctrl
        return None

    i = 0
    while i < n:
        ctrl_hit = nested_at(i)
        if ctrl_hit is not None:
            fields.append(("HashMap", i * 8, f"table ctrl={ctrl_hit:#x} items={tables[ctrl_hit]}", "", 0, 0, []))
            i += 4
            continue
        if i + 3 <= n:
            got = string_at(i)
            # a reading without allocator corroboration yields to a corroborated one that overlaps it
            # (words[i:i+3] can be the tail of a previous field plus the head of a real String)
            if got is not None and "chunk" not in got[1][4]:
                for k in (1, 2):
                    if i + k + 3 <= n:
                        alt = string_at(i + k)
                        if alt is not None and "chunk" in alt[1][4]:
                            got = None
                            break
            if got is not None:
                layout, (ptr, cap, ln, d, checks) = got
                fields.append(("String", i * 8, escape(d), layout, ln, cap, checks))
                i += 3
                continue
            got = None
            for layout in ((layout_hint,) if layout_hint else LAYOUTS):
                v = validate_vec_layout(read, regions, words[i:i + 3], layout, max_cap)
                if v is not None:
                    got = (layout, v)
                    break
            if got is not None:
                layout, (ptr, cap, ln, d, checks) = got
                hexs = d.hex() + ("..." if ln > len(d) else "")
                fields.append(("Vec<u8>", i * 8, hexs, layout, ln, cap, checks))
                i += 3
                continue
        if i + 2 <= n:
            d = validate_str(read, regions, words[i], words[i + 1], 0.9)
            if d is not None:
                fields.append(("&str", i * 8, escape(d), "ptr,len", words[i + 1], 0, ["utf8"]))
                i += 2
                continue
        w = words[i]
        k = regions.kind(w)
        if w and k != OTHER:
            fields.append(("ptr", i * 8, f"{w:#x}->{k}", "", 0, 0, []))
        else:
            text = str(w) if w < 1 << 32 else f"{w:#x}"
            f = struct.unpack("<d", struct.pack("<Q", w))[0]
            if w >= 1 << 32 and f == f and abs(f) != float("inf") and (f == 0.0 or 1e-9 <= abs(f) <= 1e15):
                text += f" (f64 {f:.6g})"          # a word that reads as a sane double is shown both ways
            fields.append(("u64", i * 8, text, "", 0, 0, []))
        i += 1
    return fields


def read_entries(read, regions: Regions, ctrl: int, buckets: int, stride: int, max_entries: int = ENTRY_CAP):
    """Yield (bucket_index, h2_tag, entry_bytes, entry_addr) for every FULL bucket."""
    try:
        cb = read(ctrl, buckets)
    except Exception:
        return
    n = 0
    for i, b in enumerate(cb):
        if b & 0x80:
            continue
        addr = ctrl - (i + 1) * stride
        if regions.lookup(addr) is None:
            continue
        try:
            yield i, b, read(addr, stride), addr
        except Exception:
            continue
        n += 1
        if n >= max_entries:
            return


# bytes of an entry explained by a typed field; a bare pointer or integer word explains nothing by itself
STRUCT_BYTES = {"String": 24, "Vec<u8>": 24, "&str": 16, "HashMap": 32}


def _typed_fraction(read, regions, data, addr, tables, sig=None):
    if not data:
        return 0.0
    fields = decode_entry(read, regions, data, addr, tables=tables)
    if sig is not None:
        sig.append(tuple((f[0], f[1]) for f in fields if f[0] in STRUCT_BYTES))
    return min(1.0, sum(STRUCT_BYTES.get(f[0], 0) for f in fields) / len(data))


def infer_stride(read, regions: Regions, ctrl: int, buckets: int, tables=None, trace=None):
    """Return (stride, how) with how in {'chunk', 'content', 'none'}.
    chunk: the glibc size field in front of the hashbrown block pins the stride exactly (Linux).
    content (0.5.0): where no allocator header exists (NT heap on Windows, musl, jemalloc) the candidate
    strides are compared by the MEAN FRACTION of each full bucket's bytes that typed fields explain. 0.4.x
    summed the typed fields found inside the window instead, which made a window several entries wide
    score higher than the entry itself (the first Windows matrix read 240 for a 48-byte entry and 256 for
    a 32-byte one: 274 of 706 pairs lost, Session 77). A multiple of the true stride can only tie it, and
    only when every entry it spans is full; a divisor ties it only when its windows all land inside full
    entries, which happens in a table with one full bucket. Ties are broken by the EMPTY buckets: the
    stride whose never-used buckets hold fewer typed bytes wins (a divisor of the true stride turns the
    other half of the real entry into an "empty" bucket full of valid Strings), then the smaller stride.
    `tables` (ctrl -> items of the tables already found) lets a nested table count as a typed field, as
    in decode_entry; without it a (String, HashMap) entry would be out-scored by its own key."""
    s = stride_by_chunk(read, regions, ctrl, buckets)
    if s is not None:
        return s, "chunk"
    try:
        cb = read(ctrl, buckets)
    except Exception:
        return None, "none"
    best, best_key = None, None
    tgt = regions.lookup(ctrl)
    for st in STRIDES:
        ctrl_offset, _ = block_len(st, buckets)
        if tgt is None or ctrl - ctrl_offset < tgt[0]:
            break
        total, n, sigs = 0.0, 0, []
        for _i, _h2, data, addr in read_entries(read, regions, ctrl, buckets, st, 64):
            total += _typed_fraction(read, regions, data, addr, tables, sigs)
            n += 1
        if n == 0:
            continue
        # every full bucket of a real table has the same key and value types at the same offsets: the share
        # of buckets agreeing with the commonest typed-field signature scales the score (0.5.1). A divisor of
        # the true stride reads key halves and value halves as alternating signatures and loses here even
        # when both halves are typed, which mean fraction alone cannot see (String, Vec<u8>) at 24 vs 48.
        modal = max(sorted(set(sigs)), key=sigs.count) if sigs else ()
        agree = (sigs.count(modal) / len(sigs)) if (sigs and modal) else 0.0
        score = (total / n) * agree
        if trace is not None:
            trace.append((st, n, total / n, agree, score))
        if best_key is not None and score < best_key[0] - 1e-9:
            continue
        # tie-breaker, computed only when needed: typed bytes inside EMPTY (never used) buckets
        etotal, en = 0.0, 0
        for i, b in enumerate(cb):
            if b != 0xFF:
                continue
            addr = ctrl - (i + 1) * st
            if regions.lookup(addr) is None:
                continue
            try:
                etotal += _typed_fraction(read, regions, read(addr, st), addr, tables)
            except Exception:
                continue
            en += 1
            if en >= 64:
                break
        empty_typed = etotal / en if en else 0.0
        key = (score, -empty_typed)
        if best_key is None or key[0] > best_key[0] + 1e-9 or (abs(key[0] - best_key[0]) <= 1e-9 and key[1] > best_key[1] + 1e-9):
            best, best_key = st, key           # an exact tie on both keeps the smaller (earlier) stride
    if best is None or best_key[0] <= 0.0:
        return None, "none"
    return best, "content"


def table_layout_vote(entries_fields) -> Optional[str]:
    """Majority String field order across a table's decoded entries (chunk-consistent ones count double)."""
    votes: Dict[str, int] = {}
    for fields in entries_fields:
        for f in fields:
            if f[0] == "String":
                votes[f[3]] = votes.get(f[3], 0) + (2 if "chunk" in f[6] else 1)
    return max(votes, key=lambda k: (votes[k], -LAYOUTS.index(k))) if votes else None


def render_fields(fields) -> str:
    out = []
    for f in fields:
        kind, off, text = f[0], f[1], f[2]
        if kind == "String":
            out.append(f'String "{text}"' + ("" if f[4] == f[5] else f"(cap {f[5]})"))
        elif kind == "Vec<u8>":
            out.append(f"Vec<u8>[{f[4]}] {text}")
        elif kind == "HashMap":
            out.append(f"HashMap {text}")
        elif kind == "&str":
            out.append(f'&str "{text}"')
        elif kind == "ptr":
            out.append(f"ptr {text}")
        else:
            out.append(f"u64 {text}")
    return " | ".join(out)
