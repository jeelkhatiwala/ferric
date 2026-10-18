# ferric.vtables — Rust trait-object vtables (Box<dyn Trait> / &dyn Trait) recovered from process memory.
#
# Volatility 3 framework 2.28.2, Linux x86-64 (8-byte usize). Shares region classification with
# ferric.strings so "where a pointer lives" is judged the same way across the suite.
#
# What a Rust trait object looks like in memory
#   A `dyn Trait` value is a fat pointer: (data_ptr, vtable_ptr). The vtable is a static structure emitted
#   once per (concrete type, trait) pair into read-only data. Its layout is fixed by the compiler:
#       [0]  drop_in_place: fn(*mut ())      a pointer into .text, OR NULL (see below)
#       [1]  size:  usize                    size_of the concrete type
#       [2]  align: usize                    align_of the concrete type (a power of two)
#       [3..] one fn pointer per trait method, each into .text
#   A plain array of function pointers (a jump table) has no size/align pair in the middle, so it does not
#   match.
#
# The drop slot is nullable (v0.2.0; what v0.1.0 got wrong)
#   Newer compilers store NULL in slot [0] when the concrete type has no drop glue (rust-lang/rust PR
#   122662, "Omit non-needs_drop drop_in_place in vtables"). v0.1.0 required a code pointer there and
#   therefore missed every vtable of a plain-data type. Measured against DWARF ground truth on rustc 1.97
#   (controls built with debug info; `<T as Trait>::{vtable}` variables): seed01 0 of 2 recovered, seed03
#   3 of 4, seed02 11 of 26, and every miss had a null drop slot. v0.2.0 accepts either form and reports
#   which one it saw (the `Drop` column: fn or null). On which compiler versions the null form appears is
#   a measurement to take on the version-sweep images, not an assumption made here.
#
# Adjacent vtables (v0.2.0; the second v0.1.0 defect)
#   rustc emits vtables back to back. v0.1.0 counted methods as "the run of code pointers after align",
#   which runs on into the NEXT vtable's drop pointer and reports one method too many. Measured on seed03:
#   `<Circle as Shape>` has 2 methods and was reported with 3. v0.2.0 ends a method run where another
#   vtable header begins.
#
# Corroboration (because a null drop slot removes the code-pointer anchor)
#   CodeRefs  how many RIP-relative LEA instructions in executable memory target the vtable address. A
#             vtable that is ever turned into a trait object by code is materialised that way in
#             position-independent code, so CodeRefs >= 1 is strong, symbol-free evidence that the
#             candidate is a real, used table. Candidates with a null drop slot are reported only when
#             CodeRefs >= 1 or Refs >= 1 (--all-candidates lifts this).
#   Refs      with --objects: live fat pointers (data_ptr, vtable_ptr) in heap/data memory. StackRefs
#             counts the same on stacks, kept apart because stack words outlive the frames that wrote them.
#
# What it reports
#   One row per vtable: where it lives, the drop form and target, the concrete type's size and alignment,
#   the number of trait methods, the corroboration counts, and the backing module with its load base
#   (VTable - Base is the file address, which is how eval/make_table_vtables.py checks a row against the
#   unstripped twin's symbols). Naming the trait needs type information a stripped image does not carry
#   and is out of scope.
#
# Why it reads VMAs directly instead of layer.scan(): same page-gap defect documented in ferric.provenance;
# each region is read as a contiguous virtual range in windows with a header+methods lookahead overlap.

import re
import struct
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist
import logging
vollog = logging.getLogger(__name__)
from .strings import rust_gate as _strings_gate

from .strings import Regions, classify_vma, HEAP, RODATA, DATA, STACK, EXEC, OTHER

HEADER_WORDS = 3                      # drop, size, align
MAX_METHODS = 64                      # a trait with more than this many methods is implausible
SIZE_MAX = 1 << 24                    # 16 MiB: a single concrete type larger than this is implausible
ALIGN_MAX = 4096
WINDOW = 8 * 1024 * 1024
LOOKAHEAD = (HEADER_WORDS + MAX_METHODS + HEADER_WORDS + 1) * 8   # a vtable plus the next header

# TreeGrid columns. Note: a column name that Volatility lowercases to a Python keyword (e.g. "In" -> "in")
# crashes namedtuple construction, so the region column is "VTableIn", matching ferric.strings' "HeaderIn".
COLUMNS = [
    ("PID", int), ("Process", str), ("VTable", format_hints.Hex), ("VTableIn", str),
    ("Drop", str), ("DropIn", format_hints.Hex), ("Size", int), ("Align", int), ("Methods", int),
    ("CodeRefs", int), ("Refs", int), ("StackRefs", int),
    ("Module", str), ("Base", format_hints.Hex),
]


def build_regions(context, task, with_exe: bool = False):
    """Regions for a task; with_exe=True also returns the backing name of the main executable."""
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
    return (regs, exe) if with_exe else regs


def module_base(regions: Regions, addr: int) -> Tuple[str, int]:
    """(basename of the file backing addr's VMA, lowest start of any VMA with that same backing file).
    For a position-independent binary the second value is its load base, so VTable - Base is the address
    in the file (what an unstripped twin's symbols and DWARF are keyed by). ('', 0) for unbacked memory."""
    r = regions.lookup(addr)
    if r is None or not r[3] or r[3].startswith("["):
        return "", 0
    name = r[3]
    base = min(s for s, e, k, n in regions.rows if n == name)
    return name.rsplit("/", 1)[-1], base


def is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def header_ok(regions: Regions, qs, i: int, n: int) -> bool:
    """True when qs[i..i+3] is a vtable header followed by at least one method: drop is a code pointer or
    NULL, align is a power of two, size is a multiple of align, and the next word is a code pointer."""
    if i + HEADER_WORDS + 1 > n:
        return False
    drop, size, align = qs[i], qs[i + 1], qs[i + 2]
    if not is_power_of_two(align) or align > ALIGN_MAX:
        return False
    if size > SIZE_MAX or size % align != 0:            # size is always a multiple of align in Rust
        return False
    if drop != 0 and regions.kind(drop) != EXEC:        # drop glue lives in executable memory, or is NULL
        return False
    return regions.kind(qs[i + HEADER_WORDS]) == EXEC   # an object-safe dyn trait has at least one method


def classify_vtable(regions: Regions, qs, i: int, n: int, base: int = 0, boundaries=None):
    """Test qs[i..] as a vtable header + method run. Returns (size, align, methods, drop) or None.
    drop == 0 means the null form. The method run ends at the first word that is not a code pointer,
    where another vtable header begins (vtables are emitted back to back), or (v0.2.4) at an address
    that code references as an object of its own (`boundaries`: the RIP-relative LEA targets; `base` is
    the address of qs[0]). Measured need: on rustc 1.89 the <Triangle as Shape> vtable is followed by a
    lone function pointer that no header check can separate from the method run (reported with 3 methods
    instead of 2); the code that uses that pointer addresses it directly, which is the boundary."""
    if not header_ok(regions, qs, i, n):
        return None
    drop, size, align = qs[i], qs[i + 1], qs[i + 2]
    methods, j = 0, i + HEADER_WORDS
    while j < n and methods < MAX_METHODS and regions.kind(qs[j]) == EXEC:
        if methods >= 1 and header_ok(regions, qs, j, n):
            break                                       # qs[j] is the next vtable's drop pointer
        if methods >= 1 and boundaries and (base + j * 8) in boundaries:
            break                                       # qs[j] starts an object that code references
        methods += 1
        j += 1
    if methods < 1:
        return None
    return size, align, methods, drop


def iter_windows(read, start: int, end: int, lookahead: int, window: int = WINDOW):
    """Yield (base, qs, usable) for each window of [start, end): qs is every 8-aligned word in the window,
    usable is how many starting positions in this window own a full lookahead (so a structure straddling a
    window edge is parsed once, from the earlier window)."""
    pos = start & ~0x7
    while pos + 8 <= end:
        size = min(window, end - pos)
        data = read(pos, size)
        if len(data) < 8:
            break
        last = pos + size >= end
        qs = struct.unpack_from(f"<{len(data)//8}Q", data, 0)
        limit_bytes = size if last else size - lookahead
        usable = max(0, (limit_bytes + 7) // 8)
        yield pos, qs, min(usable, len(qs))
        if last:
            break
        pos += max(8, size - lookahead)


def find_vtables(read, regions: Regions, exe: Optional[str] = None, boundaries=None) -> Dict[int, Tuple[int, int, int, int]]:
    """addr -> (size, align, methods, drop) for every vtable candidate in read-only data, plus (v0.2.2) in
    the main executable's writable file-backed data when `exe` names it. Vtables live in .data.rel.ro,
    which is read-only only after the loader applies RELRO; a static-pie musl binary relocates itself and
    never protects that range, so its vtables sit in a writable mapping of the binary (measured on
    musl-01: v0.2.1 found 0 of 45 vtables there). Libraries' writable data is not scanned."""
    found = {}
    for s, e, kind, nm in regions.rows:
        if not (kind == RODATA or (kind == DATA and exe is not None and nm == exe)):
            continue
        for base, qs, usable in iter_windows(read, s, e, LOOKAHEAD):
            n = len(qs)
            for i in range(usable):
                v = classify_vtable(regions, qs, i, n, base, boundaries)
                if v is not None:
                    found[base + i * 8] = v
    return found


# lea r64, [rip + disp32]:  REX.W (48 or 4C), 8D, ModRM with mod=00 and r/m=101
_LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.DOTALL)


def lea_targets(read, regions: Regions) -> Dict[int, int]:
    """target address -> number of RIP-relative LEA instructions in executable memory that compute it,
    kept for targets inside read-only or writable data of this process (where vtables and other constants
    live). One pass over executable memory; feeds both CodeRefs and the object boundaries of v0.2.4.
    Byte patterns inside other instructions can decode as an LEA; an accidental decode landing exactly on
    a candidate address is improbable, and the count is reported, not thresholded."""
    out: Dict[int, int] = {}
    keep = (RODATA, DATA)
    for s, e, kind, nm in regions.rows:
        if kind != EXEC:
            continue
        pos = s
        while pos < e:
            size = min(WINDOW, e - pos)
            data = read(pos, size)
            last = pos + size >= e
            limit = size if last else size - 16
            for m in _LEA_RIP.finditer(data):
                o = m.start()
                if o >= limit or o + 7 > len(data):
                    continue
                (disp,) = struct.unpack_from("<i", data, o + 3)
                t = pos + o + 7 + disp
                if regions.kind(t) in keep:
                    out[t] = out.get(t, 0) + 1
            if last:
                break
            pos += limit
    return out


def count_code_refs(read, regions: Regions, targets) -> Dict[int, int]:
    """addr -> number of RIP-relative LEA instructions in executable memory whose target is addr (kept
    for callers that want the counts of a known set; scan_process uses lea_targets once instead)."""
    refs = {a: 0 for a in targets}
    if not refs:
        return refs
    for s, e, kind, nm in regions.rows:
        if kind != EXEC:
            continue
        pos = s
        while pos < e:
            size = min(WINDOW, e - pos)
            data = read(pos, size)
            last = pos + size >= e
            limit = size if last else size - 16
            for m in _LEA_RIP.finditer(data):
                o = m.start()
                if o >= limit or o + 7 > len(data):
                    continue
                (disp,) = struct.unpack_from("<i", data, o + 3)
                t = pos + o + 7 + disp
                if t in refs:
                    refs[t] += 1
            if last:
                break
            pos += limit
    return refs


def count_objects(read, regions: Regions, vtset) -> Dict[int, int]:
    """Count fat pointers (data_ptr, vtable_ptr) in heap/data memory whose vtable_ptr is a known vtable
    and whose data_ptr points somewhere readable. Kept for callers that want one number."""
    heap, _stack = count_objects_split(read, regions, vtset)
    return heap


def count_objects_split(read, regions: Regions, vtset):
    """(heap_and_data_refs, stack_refs): fat pointers per vtable, with stack words counted separately
    because a stack slot keeps its last value after the frame that wrote it has returned."""
    heap = {a: 0 for a in vtset}
    stack = {a: 0 for a in vtset}
    for s, e, kind, nm in regions.rows:
        if kind not in (HEAP, STACK, DATA):
            continue
        dest = stack if kind == STACK else heap
        for base, qs, usable in iter_windows(read, s, e, 16):
            n = len(qs)
            for i in range(min(usable, n - 1)):
                vt = qs[i + 1]
                if vt in dest and regions.kind(qs[i]) in (HEAP, STACK, DATA, RODATA):
                    dest[vt] += 1
    return heap, stack


def scan_process(read, regions: Regions, pid: int, name: str, objects: bool = False, min_methods: int = 1,
                 all_candidates: bool = False, exe: Optional[str] = None):
    """Everything the plugin does for one process, on any (read, regions) pair: find candidates in
    read-only data, corroborate with code references (and live objects when `objects`), apply the
    reporting gates, and yield TreeGrid rows in COLUMNS order. Pure, so tests and the live-process
    harness run exactly the code the plugin runs."""
    leas = lea_targets(read, regions)
    vts = find_vtables(read, regions, exe, boundaries=leas)
    code = {a: leas.get(a, 0) for a in vts}
    heap, stack = count_objects_split(read, regions, set(vts)) if objects else ({}, {})
    for addr in sorted(vts):
        size, align, methods, drop = vts[addr]
        if methods < min_methods:
            continue
        crefs, hrefs, srefs = code.get(addr, 0), heap.get(addr, 0), stack.get(addr, 0)
        if drop == 0 and not all_candidates and crefs == 0 and hrefs == 0:
            continue
        # a candidate in WRITABLE module data has no read-only guarantee behind it: C function-pointer
        # tables live there too (measured: rsyslogd, 8 rows of [fn, 0, 2, fn x15] per image under v0.2.2).
        # Such a row is reported only when something references it (code, a live object, or a stack word).
        # Cost measured on musl-01: 1 of 45 real vtables, one no code or object ever uses.
        if regions.kind(addr) == DATA and not all_candidates and crefs == 0 and hrefs == 0 and srefs == 0:
            continue
        na = renderers.NotAvailableValue()
        module, base = module_base(regions, addr)
        yield (0, (pid, name, format_hints.Hex(addr), regions.kind(addr), "null" if drop == 0 else "fn",
                   format_hints.Hex(drop), size, align, methods, crefs,
                   hrefs if objects else na, srefs if objects else na,
                   module, format_hints.Hex(base)))


class VTables(plugins.PluginInterface):
    """Recovers Rust trait-object vtables (Box<dyn Trait> / &dyn Trait) from read-only memory by their
    fixed [drop-or-null, size, align, methods...] layout, with code and live-object reference counts."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 2, 5)   # 0.2.5: Rust fingerprint gate (D-021, --force-scan); 0.2.x: nullable drop slot; method run stops at the next header; CodeRefs/StackRefs;
                           # 0.2.1 Module/Base columns; 0.2.2 also scans the executable's writable data (musl static-pie);
                           # 0.2.3 a candidate in writable data is reported only when referenced
                           # 0.2.4 a method run also ends at an address that code references (object boundary)

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
            requirements.BooleanRequirement(
                name="objects", description="Also scan writable memory for fat pointers and report Refs = "
                "live trait objects in heap/data and StackRefs = the same on stacks", default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="min-methods", description="Only report vtables with at least this many trait methods",
                default=1, optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-candidates", description="Also report null-drop candidates that no code or live "
                "object references (more false positives)", default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="force-scan", description="Scan a process even when its read-only data carries no "
                "/rustc/<commit>/ compiler fingerprint (default: such processes are skipped)",
                default=False, optional=True,
            ),
        ]

    def _scan_task(self, task, objects: bool, min_methods: int, all_candidates: bool):
        pid = int(task.pid)
        name = utility.array_to_string(task.comm)
        layer_name = task.add_process_layer()
        if not layer_name:
            return
        layer = self.context.layers[layer_name]
        regions, exe = build_regions(self.context, task, with_exe=True)
        read = lambda off, n: layer.read(off, n, pad=True)
        if not _strings_gate(read, regions, bool(self.config.get("force-scan", False))):
            vollog.info(f"pid {pid} ({name}): no Rust compiler fingerprint, not scanned (--force-scan)")
            return
        yield from scan_process(read, regions, pid, name, objects, min_methods, all_candidates, exe)

    def _generator(self, tasks: Iterable):
        objects = bool(self.config.get("objects", False))
        min_methods = int(self.config.get("min-methods", 1))
        all_candidates = bool(self.config.get("all-candidates", False))
        for task in tasks:
            try:
                if not (task.mm and task.mm.is_readable()):
                    continue
            except exceptions.InvalidAddressException:
                continue
            yield from self._scan_task(task, objects, min_methods, all_candidates)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            COLUMNS,
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=filter_func)),
        )
