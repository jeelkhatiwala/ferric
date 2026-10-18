# ferric.tokio — tokio async-runtime tasks recovered from process memory: task vtables, live task cells,
# their lifecycle state, task ids, and String locals held inside the parked futures.
#
# Volatility 3 framework 2.28.2, Linux x86-64 (8-byte usize). Shares region classification and the window
# reader with the rest of the ferric suite.
#
# What tokio leaves in memory (all read from the crate sources and measured on live builds of the seed02
# control against tokio 1.0.3, 1.8.4, 1.14.1, 1.20.6, 1.28.2, 1.35.1, 1.40.0, 1.47.1 and 1.53.2)
#
#   Task Vtable   `tokio::runtime::task::raw::Vtable`, one static per (future type, scheduler) pair, in
#                 read-only data: a run of function pointers. The run's length is the tokio era:
#                     5  poll dealloc try_read_output drop_join_handle_slow shutdown            (1.0)
#                     6  + remote_abort                                                          (1.1 .. 1.19)
#                     8  + try_set_join_waker, drop_abort_handle                                 (1.20 .. 1.2x)
#                     7  poll schedule dealloc try_read_output drop_join_handle_slow drop_abort_handle shutdown
#                        followed by three usize fields: trailer_offset, scheduler_offset, id_offset
#                                                                                                 (1.28 .. 1.53+)
#                 From 1.28 the vtable therefore DESCRIBES the task cell: where the scheduler, the task id and
#                 the trailer sit relative to the Header. Nothing version-specific has to be hard-coded.
#
#   Task cell     `Cell<T,S> { header: Header, core: Core<T,S>, trailer: Trailer }`, all #[repr(C)], one heap
#                 allocation per task. Header begins with `state: AtomicUsize`; the vtable pointer sits at a
#                 fixed offset inside the Header that moved twice: +40 (1.0, `owned` pointers and
#                 `stack_next` before it), +32 (1.1 .. 1.2x, `owned` before it), +16 (1.28+). The Header is
#                 found from a heap word equal to a vtable address by testing each of those offsets:
#                 the right one yields a plausible state word and a queue_next that is null or a heap pointer.
#
#   State word    bit 0 RUNNING, bit 1 COMPLETE, bit 2 NOTIFIED, bit 3 JOIN_INTEREST, bit 4 JOIN_WAKER,
#                 bit 5 CANCELLED, bits 6.. reference count (runtime/task/state.rs; unchanged across the
#                 versions above). A task that is parked on a timer with a live JoinHandle reads 0xC8
#                 (refs 3 + JOIN_INTEREST); a runtime worker's blocking task reads 0x81 (refs 2 + RUNNING).
#
#   Future locals The future itself (the compiler-generated async state machine) occupies the bytes between
#                 the task id and the trailer: [header + id_offset + 8, header + trailer_offset). Locals that
#                 are alive across an .await are stored there; String headers among them are recovered with
#                 the same validation ferric.strings uses and reported per task.
#
# What is reported
#   kind=vtable   one row per task vtable: fns in the run, how many live tasks reference it, era
#   kind=task     one row per live task cell: header, state flags, ref count, task id, scheduler pointer,
#                 the future's location and size, and any String locals
#   kind=stale    a vtable reference in stack memory (a cell is built on the stack before it is boxed, and
#                 the slot keeps its contents): evidence that a task of that type was spawned, not a live task
#   kind=remnant  a heap reference whose header no longer validates (a freed task cell)
#
# Why it reads VMAs directly instead of layer.scan(): same page-gap defect documented in ferric.provenance.

import struct
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
import logging
vollog = logging.getLogger(__name__)
from .strings import rust_gate as _strings_gate
from volatility3.plugins.linux import pslist

from .strings import (Regions, classify_vma, HEAP, RODATA, DATA, STACK, EXEC, OTHER, LAYOUTS,
                      validate_string_layout, escape)
from .vtables import iter_windows, build_regions, is_power_of_two

MIN_FNS = 5
MAX_FNS = 8
TRAIT_HEADERS = 3
VTABLE_OFFSETS = (16, 32, 40)         # header + offset == address of the vtable pointer, by tokio era
MAX_REFS = 4096                       # measured: 3 on 36 live cells (seed02, 6 images); the Go runtime's structures
                                      # that passed the 0.2.1 checks read 74,893 to 89,516 (Session 71 negative control)
MAX_OWNER = 1 << 20                   # owner_id is a small per-runtime counter (measured: 0 or 1)
FUTURE_MAX = 1 << 20                  # a future larger than this is not scanned for locals

RUNNING, COMPLETE, NOTIFIED, JOIN_INTEREST, JOIN_WAKER, CANCELLED = 1, 2, 4, 8, 16, 32
FLAG_NAMES = ((RUNNING, "running"), (COMPLETE, "complete"), (NOTIFIED, "notified"),
              (JOIN_INTEREST, "join-interest"), (JOIN_WAKER, "join-waker"), (CANCELLED, "cancelled"))

# TreeGrid columns. "TableIn" rather than "In": Volatility lowercases column names to build a namedtuple,
# and "in" is a Python keyword, which crashes construction (matches ferric.strings' "HeaderIn"/"PtrIn").
COLUMNS = [
    ("PID", int), ("Process", str), ("Kind", str), ("Table", format_hints.Hex), ("TableIn", str),
    ("Fns", int), ("Header", format_hints.Hex), ("State", format_hints.Hex), ("Flags", str), ("Refs", int),
    ("TaskId", int), ("Scheduler", format_hints.Hex), ("FutureAt", format_hints.Hex), ("FutureBytes", int),
    ("Locals", str), ("Note", str),
]


def looks_like_trait_vtable(regions: Regions, qs, i: int, n: int) -> bool:
    """A trait-object vtable has [code_ptr, size, align, code_ptr...]: words [1],[2] are NOT code pointers
    but a power-of-two align and a size that is a multiple of it. A pure code-pointer run is not this."""
    if i + TRAIT_HEADERS > n:
        return False
    _drop, size, align = qs[i], qs[i + 1], qs[i + 2]
    return (regions.kind(qs[i]) == EXEC and regions.kind(align) != EXEC
            and is_power_of_two(align) and align <= 4096 and size % align == 0
            and regions.kind(size) != EXEC)


def describe_offsets(qs, i: int, runlen: int, n: int):
    """For a 7-pointer run, read the three usize fields tokio >= 1.28 stores after the function pointers.
    Returns (trailer_offset, scheduler_offset, id_offset) when they are consistent, else None:
    scheduler_offset is the Header size (16 + the owner_id word = 32 bytes), id_offset follows the
    scheduler (and equals it when the scheduler is zero-sized), trailer_offset follows the future."""
    if runlen != 7 or i + runlen + 3 > n:
        return None
    t, s, d = qs[i + 7], qs[i + 8], qs[i + 9]
    if s != 32 or d < s or t <= d or d % 8 or t % 8 or t > FUTURE_MAX:
        return None
    return t, s, d


def find_fn_tables(read, regions: Regions, min_fns: int = MIN_FNS, max_fns: int = MAX_FNS) -> Dict[int, int]:
    """addr -> number of consecutive code pointers, for each maximal run in read-only data whose length is
    in [min_fns, max_fns] and which is not a trait-object vtable. Kept for the v0.1 tests."""
    return {a: v[0] for a, v in find_task_tables(read, regions, min_fns, max_fns).items()}


def find_task_tables(read, regions: Regions, min_fns: int = MIN_FNS, max_fns: int = MAX_FNS):
    """addr -> (runlen, offsets_or_None) for every candidate task vtable in read-only data."""
    tables = {}
    for s, e, kind, nm in regions.rows:
        if kind != RODATA:
            continue
        first = True
        for base, qs, usable in iter_windows(read, s, e, (max_fns + 4) * 8):
            n = len(qs)
            for i in range(usable):
                if regions.kind(qs[i]) != EXEC:
                    continue
                if i == 0 and not first:
                    continue                         # a boundary run was already seen in the prior window
                if i > 0 and regions.kind(qs[i - 1]) == EXEC:
                    continue                         # not a run start
                j = i
                while j < n and j - i <= max_fns and regions.kind(qs[j]) == EXEC:
                    j += 1
                runlen = j - i
                if min_fns <= runlen <= max_fns and not looks_like_trait_vtable(regions, qs, i, n):
                    tables[base + i * 8] = (runlen, describe_offsets(qs, i, runlen, n))
            first = False
    return tables


def count_refs(read, regions: Regions, tset) -> Dict[int, int]:
    """addr -> number of writable-memory words equal to it (the v0.1 live-task proxy; kept for tests)."""
    refs = {a: 0 for a in tset}
    for s, e, kind, nm in regions.rows:
        if kind not in (HEAP, STACK, DATA):
            continue
        for base, qs, usable in iter_windows(read, s, e, 8):
            for i in range(min(usable, len(qs))):
                w = qs[i]
                if w in refs:
                    refs[w] += 1
    return refs


def find_task_tables_by_refs(read, regions: Regions, min_fns: int = MIN_FNS, max_fns: int = MAX_FNS):
    """Reference-driven discovery (v0.2): every writable word that points into read-only data is a candidate
    vtable address; one that begins a run of min_fns..max_fns code pointers and is not a trait vtable is a
    task vtable. Finding tables through their references instead of as maximal runs matters because rustc
    emits vtables back to back: two adjacent 5-pointer tokio vtables read as one 10-pointer run (measured on
    tokio 1.0.3 and 1.8.4), which a run-length rule cannot split. Returns ({addr: (runlen, offsets)},
    {addr: [(ref_addr, region_kind)]})."""
    refs: Dict[int, List[Tuple[int, str]]] = {}
    for s, e, kind, nm in regions.rows:
        if kind not in (HEAP, STACK, DATA):
            continue
        for base, qs, usable in iter_windows(read, s, e, 8):
            for i in range(min(usable, len(qs))):
                w = qs[i]
                if w & 7 == 0 and regions.kind(w) == RODATA:
                    refs.setdefault(w, []).append((base + i * 8, kind))
    tables = {}
    for addr, rl in refs.items():
        if not any(k != STACK for _a, k in rl):
            continue
        try:
            qs = struct.unpack(f"<{max_fns + 4}Q", read(addr, (max_fns + 4) * 8))
        except Exception:
            continue
        runlen = 0
        while runlen < len(qs) and regions.kind(qs[runlen]) == EXEC:
            runlen += 1
        if runlen > max_fns:
            runlen = max_fns if runlen >= max_fns + 1 and describe_offsets(qs, 0, 7, len(qs)) is None else runlen
        if not (min_fns <= runlen <= max_fns) or looks_like_trait_vtable(regions, qs, 0, len(qs)):
            continue
        offs = describe_offsets(qs, 0, 7, len(qs)) if runlen >= 7 else None
        if offs is not None:
            runlen = 7
        tables[addr] = (runlen, offs)
    return tables, {a: refs[a] for a in tables}


def find_refs(read, regions: Regions, tset):
    """Every (address, region kind) of a writable word equal to a candidate vtable address."""
    out = {a: [] for a in tset}
    for s, e, kind, nm in regions.rows:
        if kind not in (HEAP, STACK, DATA):
            continue
        for base, qs, usable in iter_windows(read, s, e, 8):
            for i in range(min(usable, len(qs))):
                w = qs[i]
                if w in out:
                    out[w].append((base + i * 8, kind))
    return out


def decode_state(state: int) -> Tuple[int, List[str]]:
    refs = state >> 6
    flags = [name for bit, name in FLAG_NAMES if state & bit]
    return refs, flags


def validate_header(read, regions: Regions, vt_addr: int, off: int, offs=None):
    """Validate a task Header whose vtable word is at vt_addr with the vtable `off` bytes into the Header.
    Returns ((header, state, queue_next, owner_id, links), None) or (None, reason).
    Checks (0.3.0; every one measured against the seed02 cells and the Go runtime's look-alikes):
      state     refs in 1..MAX_REFS; RUNNING and COMPLETE never together (transition_to_complete clears
                RUNNING in the same CAS); the word is not an address inside a mapped region (the Go cells
                carried data-segment pointers where tokio keeps its state bits)
      word +8   null or a heap/data pointer (queue_next from 1.28, the owned.prev list pointer before)
      after     the word after the vtable pointer: owner_id (small) at +16; at +32 either owner_id (1.8+) or
                the scheduler Arc of 1.1 .. 1.7 (a heap pointer); at +40 the 1.0 scheduler (heap or null)
      links     the OwnedTasks doubly linked list: Pointers<Header>{prev, next} at header+8 for the +32/+40
                eras, inside the trailer (trailer_offset) for 1.28+. A non-null link must point back at this
                header (next.prev == header, prev.next == header): 'linked'; both null: 'lone'; else reject."""
    h = vt_addr - off
    if regions.kind(h) not in (HEAP, STACK, DATA):
        return None, "header outside heap/stack/data"
    try:
        state, w1, w2 = struct.unpack("<QQQ", read(h, 24))
        (after,) = struct.unpack("<Q", read(vt_addr + 8, 8))
    except Exception:
        return None, "unreadable"
    refs = state >> 6
    if regions.kind(state) != OTHER:
        return None, "state is a mapped address"
    if refs < 1 or refs > MAX_REFS:
        return None, f"refs={refs}"
    if state & RUNNING and state & COMPLETE:
        return None, "running+complete"
    if w1 != 0 and regions.kind(w1) not in (HEAP, DATA):
        return None, "word+8 not null/heap"
    if off == 16:
        if after > MAX_OWNER:
            return None, f"owner_id={after:#x}"
    elif off == 32:
        if after > MAX_OWNER and regions.kind(after) != HEAP:
            return None, f"owner/scheduler word={after:#x}"
    else:
        if after != 0 and regions.kind(after) not in (HEAP, DATA):
            return None, f"scheduler word={after:#x}"
    # owned-list back-links
    prev = nxt = None
    link_at = None
    if off in (32, 40):
        prev, nxt, link_at = w1, w2, 8
    elif offs is not None:
        try:
            prev, nxt = struct.unpack("<QQ", read(h + offs[0], 16))
            link_at = offs[0]
        except Exception:
            prev = nxt = None
    links = "n/a"
    if link_at is not None:
        links = "lone"
        for other, back_word, label in ((nxt, 0, "next"), (prev, 8, "prev")):
            if other == 0:
                continue
            if regions.kind(other) not in (HEAP, DATA):
                return None, f"{label} link outside heap"
            try:
                (back,) = struct.unpack("<Q", read(other + link_at + back_word, 8))
            except Exception:
                return None, f"{label} link unreadable"
            if back != h:
                return None, f"{label} link does not point back"
            links = "linked"
    owner_id = after if off in (16, 32) and after <= MAX_OWNER else 0
    return (h, state, w1, owner_id, links), None


def header_at(read, regions: Regions, vt_addr: int, off: int, check_owner: bool = True, offs=None):
    """Compatibility wrapper (tests, 0.2.x callers): the validated header tuple without the link status."""
    r, _why = validate_header(read, regions, vt_addr, off, offs)
    return None if r is None else r[:4]


def locals_in(read, regions: Regions, start: int, size: int, max_items: int = 16) -> List[str]:
    """String headers inside a future's bytes, validated as ferric.strings does (any field order, allocator
    corroboration preferred). Returns their texts."""
    if size <= 0 or size > FUTURE_MAX:
        return []
    try:
        data = read(start, size)
    except Exception:
        return []
    n = len(data) // 8
    words = struct.unpack(f"<{n}Q", data[: n * 8])
    out, i = [], 0
    while i + 3 <= n and len(out) < max_items:
        best = None
        for layout in LAYOUTS:
            v = validate_string_layout(read, regions, words[i:i + 3], layout, 1 << 20)
            if v is not None and (best is None or "chunk" in v[4]):
                best = v
                if "chunk" in v[4]:
                    break
        if best is not None:
            out.append(escape(best[3], 48))
            i += 3
        else:
            i += 1
    return out


def scan_process(read, regions: Regions, pid: int, name: str, min_refs: int = 1, want_locals: bool = True,
                 candidates: bool = False):
    """All of the per-process work, as a generator of TreeGrid rows (COLUMNS). Pure, so a live process and a
    Volatility layer are scanned by the same code."""
    na = renderers.NotAvailableValue()
    tables, refs = find_task_tables_by_refs(read, regions)
    for addr in sorted(tables, key=lambda a: (-len(refs[a]), a)):
        runlen, offs = tables[addr]
        rlist = refs[addr]
        if len(rlist) < min_refs:
            continue
        # pick the header offset: self-described (scheduler_offset == header size) or the one that
        # validates for the most heap references
        live, stale, remnant, why = [], [], [], {}
        cands = VTABLE_OFFSETS
        if offs is not None:
            cands = (offs[1] - 16,) + tuple(o for o in VTABLE_OFFSETS if o != offs[1] - 16)
        best_off, best_n = None, -1
        for off in cands:
            n_ok = sum(1 for a, k in rlist if k != STACK and validate_header(read, regions, a, off, offs)[0] is not None)
            if n_ok > best_n:
                best_off, best_n = off, n_ok
        for a, k in rlist:
            hv, reason = validate_header(read, regions, a, best_off, offs)
            if k == STACK:
                stale.append((a, hv))
            elif hv is None:
                remnant.append(a)
                why[reason] = why.get(reason, 0) + 1
            else:
                live.append(hv)
        era = {40: "tokio 1.0 layout", 32: "tokio 1.1-1.2x layout", 16: "tokio 1.28+ layout"}.get(best_off, "?")
        # a legacy-era table (no self-described offsets) needs list evidence: at least one live cell whose
        # OwnedTasks links point back at it. Go's itab method tables, referenced from heap interface values,
        # passed every per-cell check of 0.2.1 at these offsets (15 "tasks" on neg_go); none of them is in a
        # consistent doubly linked list. A lone legacy cell is shown with --candidates, not as a task.
        linked = any(hv[4] == "linked" for hv in live)
        if live and offs is None and not linked:
            if candidates:
                yield (0, (pid, name, "candidate", format_hints.Hex(addr), regions.kind(addr), runlen, na, na,
                           f"refs={len(rlist)} live-shaped={len(live)} but no owned-list link", len(live), na, na, na, na, "",
                           f"{era} shape without list evidence (--candidates); rejected headers: "
                           + ", ".join(f"{k} x{v}" for k, v in sorted(why.items())) if why else f"{era} shape without list evidence (--candidates)"))
            continue
        if not live:
            # a code-pointer table that heap words reference but that never fronts a task header (a
            # RawWakerVTable, a C ops table): a diagnostic, shown only with --candidates. Measured on the
            # 5 negative-control images: 3 such tables per image, all in C/Python processes (udisksd,
            # unattended-upgrades), none a task.
            if candidates:
                yield (0, (pid, name, "candidate", format_hints.Hex(addr), regions.kind(addr), runlen, na, na,
                           f"refs={len(rlist)} none validates as a task header", 0, na, na, na, na, "",
                           "not a task vtable (or every cell is freed); rejected headers: "
                           + ", ".join(f"{k} x{v}" for k, v in sorted(why.items())) if why else "not a task vtable (or every cell is freed)"))
            continue
        note = f"{era}; vtable at header+{best_off}"
        if offs:
            note += f"; trailer_offset={offs[0]:#x} scheduler_offset={offs[1]:#x} id_offset={offs[2]:#x}"
        yield (0, (pid, name, "vtable", format_hints.Hex(addr), regions.kind(addr), runlen, na, na,
                   f"live={len(live)} stale={len(stale)} remnant={len(remnant)}", len(live), na, na, na, na, "", note))
        for h, state, queue_next, owner_id, links in sorted(live):
            rc, flags = decode_state(state)
            tid, sched, fut_at, fut_n, locs = na, na, na, na, ""
            if offs is not None:
                trailer, sched_off, id_off = offs
                try:
                    (tid_v,) = struct.unpack("<Q", read(h + id_off, 8))
                    (sched_v,) = struct.unpack("<Q", read(h + sched_off, 8))
                except Exception:
                    tid_v, sched_v = 0, 0
                tid = tid_v if 0 < tid_v < 1 << 48 else na
                sched = format_hints.Hex(sched_v)
                fut_start, fut_len = h + id_off + 8, trailer - (id_off + 8)
                fut_at, fut_n = format_hints.Hex(fut_start), fut_len
                if want_locals:
                    locs = " | ".join(f'"{t}"' for t in locals_in(read, regions, fut_start, fut_len))
            yield (0, (pid, name, "task", format_hints.Hex(addr), regions.kind(addr), runlen, format_hints.Hex(h),
                       format_hints.Hex(state), ",".join(flags) or "idle", rc, tid, sched, fut_at, fut_n, locs,
                       f"owner_id={owner_id} list={links}"))
        for a, hv in stale:
            st = format_hints.Hex(hv[1]) if hv else na
            fl = ",".join(decode_state(hv[1])[1]) if hv else "-"
            yield (0, (pid, name, "stale", format_hints.Hex(addr), regions.kind(addr), runlen,
                       format_hints.Hex(a - best_off), st, fl, hv[1] >> 6 if hv else 0, na, na, na, na, "",
                       "vtable reference on a stack: a cell built there before boxing"))
        for a in remnant:
            yield (0, (pid, name, "remnant", format_hints.Hex(addr), regions.kind(addr), runlen,
                       format_hints.Hex(a - best_off), na, "-", 0, na, na, na, na, "",
                       "heap reference whose header no longer validates (freed cell)"))


class Tokio(plugins.PluginInterface):
    """Recovers tokio task vtables and live task cells (state, reference count, task id, scheduler, and
    String locals held in the parked future) from process memory, using the offsets the vtable carries."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 3, 1)   # 0.3.1: Rust fingerprint gate (D-021, --force-scan); 0.2.0: header parsing via self-described offsets; state decode; ids; locals
                           # 0.2.1: candidate (non-task) tables only with --candidates
                           # 0.3.0: header checks measured against the Go runtime's look-alikes (refs bound, state not an
                           #        address, owner/scheduler word, OwnedTasks back-links); legacy-era tables need list evidence

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
                name="min-refs", description="Only report vtables with at least this many references "
                "(0 shows every candidate table)", default=1, optional=True,
            ),
            requirements.BooleanRequirement(
                name="no-locals", description="Skip the String-local scan inside each task's future",
                default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="candidates", description="Also report referenced code-pointer tables that front no "
                "task header (diagnostic; C ops tables and waker vtables show up here)", default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="force-scan", description="Scan a process even when its read-only data carries no "
                "/rustc/<commit>/ compiler fingerprint (default: such processes are skipped)",
                default=False, optional=True,
            ),
        ]

    def _scan_task(self, task, min_refs: int, want_locals: bool, candidates: bool):
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
        yield from scan_process(read, regions, pid, name, min_refs, want_locals, candidates)

    def _generator(self, tasks: Iterable):
        min_refs = int(self.config.get("min-refs", 1))
        want_locals = not bool(self.config.get("no-locals", False))
        candidates = bool(self.config.get("candidates", False))
        for task in tasks:
            try:
                if not (task.mm and task.mm.is_readable()):
                    continue
            except exceptions.InvalidAddressException:
                continue
            yield from self._scan_task(task, min_refs, want_locals, candidates)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            COLUMNS,
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=filter_func)),
        )
