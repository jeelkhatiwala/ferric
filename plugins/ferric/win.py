# ferric.win: Windows entry points for the ferric suite: the same five recoverers over a Windows
# process, with the region table built from the VAD tree instead of Linux VMAs.
#
# STATUS: first run on win-img01 2026-10-11 (Session 75): every pre-registered prediction held; the
# CommitCharge rule below came out of that run's timings. Every scanning function is
# the shared, unit-tested code used by the Linux plugins (vtables.scan_process, maps.scan_process,
# tokio.scan_process, strings.scan_regions, provenance.iter_pattern_offsets/classify); only the two
# things below are Windows-specific, and they are what the first Windows image must prove:
#
#   1. Regions from VADs. A VAD carries one protection for its whole range, and an image (EXE/DLL)
#      is ONE VAD with PAGE_EXECUTE_WRITECOPY, so the VAD alone cannot separate .text from .rdata from
#      .data. For image mappings the PE section table is read from memory (DOS header -> NT headers ->
#      sections) and the VAD is split into section-level regions with the section characteristics as
#      protection. Private memory is classified by the VAD protection; the ranges between each
#      thread's TEB StackLimit and StackBase are named "[stack]" so classify_vma tells stacks from
#      heaps the way it does on Linux.
#   2. The executable. PEB.ImageBaseAddress names the main image; when the PEB is not readable, the
#      image VAD whose file name starts with the process name is used.
#
# What is deliberately the same: classify_vma (strings.py) and therefore every "where does this
# pointer live" decision in the suite; the output columns; the pure scanners.
# Known Windows-specific measurement to make on win-img01: std paths inside Windows-built binaries
# are written with the host separator after the remapped prefix (/rustc/<hash>\library\core\src\<file>),
# so the compiler and std-dep alternatives in provenance.PATTERN_CORE accept either separator from
# 0.3.1 on. The String data pointer must land in HEAP memory: NT heap segments are private committed
# VADs and classify as HEAP; the stride inference in maps falls back to content (no glibc chunk).

import struct
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

from . import maps as _maps, provenance as _prov, strings as _strings, tokio as _tokio, vtables as _vt
from .strings import Regions, classify_vma, HEAP, STACK, DATA, RODATA

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


# ----------------------------------------------------------------------------- pure helpers (unit-tested)
def prot_rwx(vad_protection: str) -> str:
    """'PAGE_EXECUTE_WRITECOPY|PAGE_GUARD' -> 'rwx' with '-' for absent bits (classify_vma's input)."""
    names = set((vad_protection or "").split("|"))
    if "PAGE_NOACCESS" in names or not names or names == {""}:
        return "---"
    x = any(n.startswith("PAGE_EXECUTE") for n in names)
    w = bool(names & {"PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"})
    return "r" + ("w" if w else "-") + ("x" if x else "-")


def scan_vad(file_backed: bool, commit_charge: int) -> bool:
    """Whether a VAD is handed to the scanners. A private VAD with no committed page is reserved
    address space (win-img01: one 4 GB PAGE_READWRITE reservation, CommitCharge 0, in a 300 KB seed);
    read with pad=True it is 4 GB of zeros, and the word-by-word scanners spent 433 s (maps) and 349 s
    (strings) on it. File-backed VADs keep CommitCharge 0 for shared pages and are always scanned."""
    return file_backed or commit_charge > 0


def section_rwx(characteristics: int) -> str:
    return ("r" if characteristics & IMAGE_SCN_MEM_READ else "-") + \
           ("w" if characteristics & IMAGE_SCN_MEM_WRITE else "-") + \
           ("x" if characteristics & IMAGE_SCN_MEM_EXECUTE else "-")


def pe_sections(read, base: int, vad_end: int) -> Optional[List[Tuple[int, int, str, str]]]:
    """Split a mapped PE image at `base` into [(start, end, rwx, section_name)] from its in-memory
    section table. Returns None when no valid PE header is readable. The headers themselves are a
    read-only region named '[pe-headers]'; sections are page-aligned to SectionAlignment."""
    try:
        dos = read(base, 0x40)
        if dos[:2] != b"MZ":
            return None
        (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
        if not 0x40 <= e_lfanew <= 0x1000:
            return None
        nt = read(base + e_lfanew, 24 + 0x100)
        if nt[:4] != b"PE\0\0":
            return None
        nsec, opt_size = struct.unpack_from("<H", nt, 6)[0], struct.unpack_from("<H", nt, 20)[0]
        if not 1 <= nsec <= 96:
            return None
        opt = read(base + e_lfanew + 24, opt_size)
        magic = struct.unpack_from("<H", opt, 0)[0]
        if magic not in (0x10B, 0x20B):
            return None
        sec_align = struct.unpack_from("<I", opt, 32)[0] or 0x1000
        size_hdrs = struct.unpack_from("<I", opt, 60)[0] or 0x1000
        table = read(base + e_lfanew + 24 + opt_size, 40 * nsec)
    except Exception:
        return None
    out = [(base, base + ((size_hdrs + 0xFFF) & ~0xFFF), "r--", "[pe-headers]")]
    for i in range(nsec):
        name = table[i * 40:i * 40 + 8].rstrip(b"\0").decode("ascii", errors="replace") or f"sec{i}"
        vsize, va, rawsize = struct.unpack_from("<III", table, i * 40 + 8)
        chars = struct.unpack_from("<I", table, i * 40 + 36)[0]
        size = max(vsize, rawsize)
        if size == 0 or va == 0:
            continue
        start = base + va
        end = min(base + ((va + size + sec_align - 1) // sec_align) * sec_align, vad_end)
        if end <= start:
            continue
        out.append((start, end, section_rwx(chars), name))
    out.sort()
    return out


def pe_import_dlls(read, base: int) -> Optional[List[str]]:
    """Names of the DLLs a mapped PE image at `base` imports, read from its in-memory import directory
    (data directory 1, IMAGE_IMPORT_DESCRIPTOR.Name). None when no valid PE header or import directory
    is readable; [] when the directory is present but empty."""
    try:
        dos = read(base, 0x40)
        if dos[:2] != b"MZ":
            return None
        (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
        if not 0x40 <= e_lfanew <= 0x1000:
            return None
        nt = read(base + e_lfanew, 24 + 0xF0)
        if nt[:4] != b"PE\0\0":
            return None
        magic = struct.unpack_from("<H", nt, 24)[0]
        dd = {0x20B: 24 + 112, 0x10B: 24 + 96}.get(magic)
        if dd is None:
            return None
        imp_rva, imp_size = struct.unpack_from("<II", nt, dd + 8)
        if not imp_rva:
            return None
        names: List[str] = []
        for i in range(256):
            desc = read(base + imp_rva + 20 * i, 20)
            if len(desc) < 20 or desc == b"\0" * 20:
                break
            name_rva = struct.unpack_from("<I", desc, 12)[0]
            if not name_rva:
                break
            raw = read(base + name_rva, 256).split(b"\0", 1)[0]
            if raw and all(32 < c < 127 for c in raw):
                names.append(raw.decode("ascii"))
        return names
    except Exception:
        return None


def infer_windows_target(dlls: Optional[List[str]], std_deps: Iterable[str]) -> Tuple[str, str, int]:
    """(triple, evidence, agreeing_signals) for an x86-64 Windows Rust process, from two independent
    signals measured on every MSVC and gnu seed build of rustc 1.71 to 1.99 (Session 81):
      imports  MSVC links VCRUNTIME140.dll and the api-ms-win-crt-* UCRT set; gnu links msvcrt.dll and
               neither of those.
      std-dep  the gnu std vendors its DWARF backtrace stack (gimli, addr2line); the MSVC std uses
               dbghelp and carries only hashbrown and rustc-demangle.
    The std-dep signal is used only when std-dep rows exist at all (absence of gimli in a process whose
    std pages were not resident is not evidence). Disagreeing signals are reported as a conflict."""
    imp = None
    if dlls:
        low = [d.lower() for d in dlls]
        if any(d.startswith("vcruntime") or d.startswith("api-ms-win-crt-") for d in low):
            imp = "msvc"
        elif "msvcrt.dll" in low:
            imp = "gnu"
    crates = {d.rsplit("-", 1)[0] for d in std_deps}
    std = None
    if crates:
        std = "gnu" if crates & {"gimli", "addr2line"} else "msvc"
    parts = []
    if imp:
        parts.append("imports " + ("VCRUNTIME/UCRT" if imp == "msvc" else "msvcrt.dll without VCRUNTIME"))
    if std:
        parts.append("std-deps " + ("with gimli/addr2line" if std == "gnu" else "without gimli/addr2line"))
    if imp and std and imp != std:
        return "conflict", f"imports say {imp}, std-deps say {std}", 0
    abi = imp or std
    if not abi:
        return "unknown", "no import or std-dep evidence", 0
    return f"x86_64-pc-windows-{abi}", "; ".join(parts), (1 if imp else 0) + (1 if std else 0)


def regions_from_table(vads, stacks, exe_name: Optional[str]) -> Regions:
    """vads: [(start, end, rwx, file_backed, name, sections_or_None)]; stacks: [(limit, base)].
    Builds the Regions table the shared scanners expect."""
    rows = []
    for s, e, rwx, fb, name, sections in vads:
        if sections:
            is_exe = fb and exe_name is not None and name == exe_name
            for ss, se, srwx, sname in sections:
                rows.append((ss, se, classify_vma(srwx, True, name, is_exe), name))
            continue
        nm = name
        for lo, hi in stacks:
            if s <= lo < e or s < hi <= e:
                nm = "[stack]"
                break
        rows.append((s, e, classify_vma(rwx, fb, nm, False), nm))
    return Regions(rows)


# ----------------------------------------------------------------------------- Volatility glue
def build_regions(context, kernel, proc, layer_name: str) -> Tuple[Regions, Optional[str]]:
    layer = context.layers[layer_name]
    read = lambda off, n: layer.read(off, n, pad=True)
    protect_values = vadinfo.VadInfo.protect_values(context, kernel.layer_name, kernel.symbol_table_name)
    proc_name = _proc_name(proc)
    vads = []
    for vad in proc.get_vad_root().traverse():
        try:
            s, e = int(vad.get_start()), int(vad.get_end())
            rwx = prot_rwx(vad.get_protection(protect_values, vadinfo.winnt_protections))
        except exceptions.InvalidAddressException:
            continue
        fname = None
        try:
            fn = vad.get_file_name()
            if isinstance(fn, str) and fn:
                fname = fn
        except exceptions.InvalidAddressException:
            fname = None
        try:
            commit = int(vad.get_commit_charge())
        except (exceptions.InvalidAddressException, AttributeError, TypeError):
            commit = 1          # unknown: scan rather than skip
        if not scan_vad(fname is not None, commit):
            continue
        name = fname or "[anon]"
        sections = pe_sections(read, s, e) if fname else None
        vads.append((s, e, rwx, fname is not None, name, sections))
    # the executable: PEB.ImageBaseAddress, else the image whose file name starts with the process name
    exe_name = None
    try:
        base = int(proc.get_peb().ImageBaseAddress)
        for s, e, rwx, fb, name, sections in vads:
            if fb and s <= base < e:
                exe_name = name
                break
    except exceptions.InvalidAddressException:
        pass
    if exe_name is None:
        for s, e, rwx, fb, name, sections in vads:
            if fb and sections and name.rsplit("\\", 1)[-1].lower().startswith(proc_name.lower()[:14]):
                exe_name = name
                break
    # user stacks from each thread's TEB
    stacks = []
    teb_type = kernel.symbol_table_name + constants.BANG + "_TEB"
    try:
        for thread in proc.ThreadListHead.to_list(kernel.symbol_table_name + constants.BANG + "_ETHREAD", "ThreadListEntry"):
            try:
                teb_ptr = int(thread.Tcb.Teb)
                if not teb_ptr:
                    continue
                teb = context.object(teb_type, offset=teb_ptr, layer_name=layer_name)
                lo, hi = int(teb.NtTib.StackLimit), int(teb.NtTib.StackBase)
                if 0 < lo < hi:
                    stacks.append((lo, hi))
            except exceptions.InvalidAddressException:
                continue
    except exceptions.InvalidAddressException:
        pass
    regs = regions_from_table(vads, stacks, exe_name)
    regs.allocator = "nt"          # no glibc chunk header anywhere: maps validates Vec<u8> and strides by content
    return regs, exe_name


def _proc_name(proc) -> str:
    try:
        return proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
    except exceptions.InvalidAddressException:
        return "?"


def iter_procs(context, kernel_module_name: str, pid_list):
    """Yield (proc, pid, name, layer_name) for every readable process."""
    kernel = context.modules[kernel_module_name]
    filter_func = pslist.PsList.create_pid_filter(pid_list)
    for proc in pslist.PsList.list_processes(context, kernel_module_name, filter_func=filter_func):
        try:
            pid = int(proc.UniqueProcessId)
            layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException:
            continue
        if not layer_name:
            continue
        yield kernel, proc, pid, _proc_name(proc), layer_name


def _common_requirements(extra):
    return [
        requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel64"]),
        requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
        requirements.VersionRequirement(name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)),
        requirements.ListRequirement(name="pid", description="Filter on specific process IDs", element_type=int, optional=True),
    ] + extra


class VTables(plugins.PluginInterface):
    """Rust trait-object vtables in a Windows process (ferric.vtables over VAD/PE-section regions)."""
    _required_framework_version = (2, 4, 0)
    _version = (0, 1, 5)   # 0.1.5: Rust fingerprint gate (D-021, --force-scan); 0.1.3: Maps --debug-ctrl; 0.1.2: regions tagged allocator=nt; 0.1.1: reserved-only private VADs (CommitCharge 0) are not scanned (scan_vad)

    @classmethod
    def get_requirements(cls):
        return _common_requirements([
            requirements.BooleanRequirement(name="objects", description="Also count live trait objects (Refs/StackRefs)", default=False, optional=True),
            requirements.IntRequirement(name="min-methods", description="Only report vtables with at least this many methods", default=1, optional=True),
            requirements.BooleanRequirement(name="all-candidates", description="Also report unreferenced null-drop candidates", default=False, optional=True),
            requirements.BooleanRequirement(name="force-scan", description="Scan a process even when it carries no /rustc/<commit>/ fingerprint (default: skipped)", default=False, optional=True),
        ])

    def _generator(self):
        for kernel, proc, pid, name, layer_name in iter_procs(self.context, self.config["kernel"], self.config.get("pid", None)):
            layer = self.context.layers[layer_name]
            regions, exe = build_regions(self.context, kernel, proc, layer_name)
            read = lambda off, n: layer.read(off, n, pad=True)
            if not _strings.rust_gate(read, regions, bool(self.config.get("force-scan", False))):
                continue
            yield from _vt.scan_process(read, regions, pid, name, bool(self.config.get("objects", False)),
                                        int(self.config.get("min-methods", 1)), bool(self.config.get("all-candidates", False)), exe)

    def run(self):
        return renderers.TreeGrid(_vt.COLUMNS, self._generator())


class Maps(plugins.PluginInterface):
    """Rust hashbrown tables and their entries in a Windows process (ferric.maps over VAD regions)."""
    _required_framework_version = (2, 4, 0)
    _version = (0, 1, 5)   # 0.1.5: Rust fingerprint gate (D-021, --force-scan); 0.1.3: Maps --debug-ctrl; 0.1.2: regions tagged allocator=nt; 0.1.1: reserved-only private VADs (CommitCharge 0) are not scanned (scan_vad)

    @classmethod
    def get_requirements(cls):
        return _common_requirements([
            requirements.IntRequirement(name="min-items", description="Only report tables with at least this many live items", default=1, optional=True),
            requirements.BooleanRequirement(name="explain", description="Also report structural near-misses", default=False, optional=True),
            requirements.BooleanRequirement(name="no-entries", description="Report tables only; skip entry decoding", default=False, optional=True),
            requirements.IntRequirement(name="max-entries", description="Most entry rows emitted per table", default=_maps.ENTRY_CAP, optional=True),
            requirements.StringRequirement(name="debug-ctrl", description="Print the stride candidates' scores for the table with this ctrl address (hex)", optional=True),
            requirements.BooleanRequirement(name="force-scan", description="Scan a process even when it carries no /rustc/<commit>/ fingerprint (default: skipped)", default=False, optional=True),
        ])

    def _generator(self):
        for kernel, proc, pid, name, layer_name in iter_procs(self.context, self.config["kernel"], self.config.get("pid", None)):
            layer = self.context.layers[layer_name]
            regions, _exe = build_regions(self.context, kernel, proc, layer_name)
            read = lambda off, n: layer.read(off, n, pad=True)
            if not _strings.rust_gate(read, regions, bool(self.config.get("force-scan", False))):
                continue
            dbg = self.config.get("debug-ctrl", None)
            yield from _maps.scan_process(read, regions, pid, name, int(self.config.get("min-items", 1)),
                                          bool(self.config.get("explain", False)), not bool(self.config.get("no-entries", False)),
                                          int(self.config.get("max-entries", _maps.ENTRY_CAP)),
                                          int(dbg, 0) if dbg else None)

    def run(self):
        return renderers.TreeGrid(_maps.COLUMNS, self._generator())


class Tokio(plugins.PluginInterface):
    """tokio task vtables, headers, states and locals in a Windows process (ferric.tokio over VAD regions)."""
    _required_framework_version = (2, 4, 0)
    _version = (0, 1, 5)   # 0.1.5: Rust fingerprint gate (D-021, --force-scan); 0.1.3: Maps --debug-ctrl; 0.1.2: regions tagged allocator=nt; 0.1.1: reserved-only private VADs (CommitCharge 0) are not scanned (scan_vad)

    @classmethod
    def get_requirements(cls):
        return _common_requirements([
            requirements.IntRequirement(name="min-refs", description="Only report vtables with at least this many references", default=1, optional=True),
            requirements.BooleanRequirement(name="no-locals", description="Skip the String-local scan inside each task's future", default=False, optional=True),
            requirements.BooleanRequirement(name="candidates", description="Also report referenced code tables that front no task header", default=False, optional=True),
            requirements.BooleanRequirement(name="force-scan", description="Scan a process even when it carries no /rustc/<commit>/ fingerprint (default: skipped)", default=False, optional=True),
        ])

    def _generator(self):
        for kernel, proc, pid, name, layer_name in iter_procs(self.context, self.config["kernel"], self.config.get("pid", None)):
            layer = self.context.layers[layer_name]
            regions, _exe = build_regions(self.context, kernel, proc, layer_name)
            read = lambda off, n: layer.read(off, n, pad=True)
            if not _strings.rust_gate(read, regions, bool(self.config.get("force-scan", False))):
                continue
            yield from _tokio.scan_process(read, regions, pid, name, int(self.config.get("min-refs", 1)),
                                           not bool(self.config.get("no-locals", False)), bool(self.config.get("candidates", False)))

    def run(self):
        return renderers.TreeGrid(_tokio.COLUMNS, self._generator())


class Strings(plugins.PluginInterface):
    """Rust String, &str, panic Location and fmt template objects in a Windows process (ferric.strings)."""
    _required_framework_version = (2, 4, 0)
    _version = (0, 2, 1)   # 0.2.0: policy shared with ferric.strings 0.4.0 (fingerprint gate, template reference gate)
                           # 0.2.1: reserved-only private VADs (CommitCharge 0) are not scanned (scan_vad)

    @classmethod
    def get_requirements(cls):
        return _common_requirements([
            requirements.ListRequirement(name="kinds", description="Object kinds: string, str, location, template", element_type=str, optional=True),
            requirements.IntRequirement(name="max-cap", description="Maximum String capacity considered", default=_strings.STRING_MAX_CAP_DEFAULT, optional=True),
            requirements.IntRequirement(name="min-len", description="Minimum string length to report", default=1, optional=True),
            requirements.BooleanRequirement(name="str-anywhere", description="Also look for &str headers in heap/stack memory", default=False, optional=True),
            requirements.BooleanRequirement(name="all-utf8", description="Report any valid-UTF-8 String", default=False, optional=True),
            requirements.BooleanRequirement(name="dump", description="Write every row as TSV to a file per process", default=False, optional=True),
            requirements.BooleanRequirement(name="force-templates", description="Scan for fmt templates even on a compiler older than 1.93", default=False, optional=True),
            requirements.BooleanRequirement(name="force-scan", description="Scan a process even when it carries no /rustc/<commit>/ fingerprint", default=False, optional=True),
            requirements.BooleanRequirement(name="all-candidates", description="List fmt templates nothing refers to (tagged ref=none) instead of dropping them", default=False, optional=True),
        ])

    def _generator(self):
        want = set(self.config.get("kinds", None) or ["string", "str", "location", "template"])
        force_templates = bool(self.config.get("force-templates", False))
        force_scan = bool(self.config.get("force-scan", False))
        all_candidates = bool(self.config.get("all-candidates", False))
        max_cap = int(self.config.get("max-cap", _strings.STRING_MAX_CAP_DEFAULT))
        min_len = int(self.config.get("min-len", 1))
        anywhere = bool(self.config.get("str-anywhere", False))
        min_printable = 0.0 if self.config.get("all-utf8", False) else 0.9
        dump = bool(self.config.get("dump", False))
        for kernel, proc, pid, name, layer_name in iter_procs(self.context, self.config["kernel"], self.config.get("pid", None)):
            layer = self.context.layers[layer_name]
            regions, _exe = build_regions(self.context, kernel, proc, layer_name)
            read = lambda off, n: layer.read(off, n, pad=True)
            lines = []
            # the per-process policy (fingerprint gate, template version gate, template reference gate) is
            # _strings.scan_process, the same function the Linux shell runs; nothing is decided here
            for kind, haddr, hk, ptr, tk, ln, cap, order, checks, text in _strings.scan_process(
                    read, regions, want, max_cap, min_printable, anywhere, None, False,
                    force_templates, force_scan, all_candidates, None):
                if kind not in ("layout", "compiler", "templates") and ln < min_len:
                    continue
                row = (pid, name, kind, format_hints.Hex(haddr), hk, format_hints.Hex(ptr), tk, ln, cap, order, ",".join(checks), text)
                if dump:
                    lines.append("\t".join(f"{int(x):#x}" if isinstance(x, format_hints.Hex) else str(x) for x in row))
                yield (0, row)
            if dump and lines:
                fh = self.open(f"pid.{pid}.ferric-strings.tsv")
                fh.write(("\n".join(lines) + "\n").encode())
                fh.close()

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Kind", str), ("Header", format_hints.Hex), ("HeaderIn", str),
             ("Ptr", format_hints.Hex), ("PtrIn", str), ("Len", int), ("Cap", int), ("Layout", str), ("Checks", str), ("Text", str)],
            self._generator())


class Provenance(plugins.PluginInterface):
    """Rust toolchain provenance (compiler commit, std deps, toolchain, crates, author paths) in a Windows process."""
    _required_framework_version = (2, 4, 0)
    _version = (0, 1, 4)   # 0.1.4: 'target' row (MSVC vs gnu from imports and std-deps); 0.1.3: Maps --debug-ctrl; 0.1.2: regions tagged allocator=nt; 0.1.1: reserved-only private VADs (CommitCharge 0) are not scanned (scan_vad)

    @classmethod
    def get_requirements(cls):
        return _common_requirements([
            requirements.StringRequirement(name="commit-map", description="CSV of rustc commit,version pairs", optional=True),
            requirements.BooleanRequirement(name="dump-hits", description="Write every hit to a file per process", default=False, optional=True),
            requirements.BooleanRequirement(name="all-authors", description="Also report author paths lacking a Rust marker", default=False, optional=True),
            requirements.IntRequirement(name="maxsize", description="Skip VADs larger than this many bytes", default=_prov.MAXSIZE_DEFAULT, optional=True),
        ])

    def _generator(self):
        extra_map: Dict[str, str] = {}
        cm = self.config.get("commit-map", None)
        if cm:
            try:
                import csv
                import re as _re
                with open(cm, newline="") as fh:
                    for r in csv.reader(fh):
                        if len(r) >= 2 and _re.fullmatch(r"[0-9a-f]{40}", r[0].strip()):
                            extra_map[r[0].strip()] = r[1].strip()
            except OSError:
                pass
        dump = bool(self.config.get("dump-hits", False))
        all_authors = bool(self.config.get("all-authors", False))
        maxsize = int(self.config.get("maxsize", _prov.MAXSIZE_DEFAULT))
        for kernel, proc, pid, name, layer_name in iter_procs(self.context, self.config["kernel"], self.config.get("pid", None)):
            layer = self.context.layers[layer_name]
            regions, _exe = build_regions(self.context, kernel, proc, layer_name)
            read = lambda off, n: layer.read(off, n, pad=True)
            agg: Dict[Tuple[str, str], list] = {}
            dump_lines: List[str] = []
            for s, e, kind, backing in regions.rows:          # every region, as the Linux plugin scans every VMA
                if e <= s or e - s > maxsize:
                    continue
                for offset in _prov.iter_pattern_offsets(read, s, e):
                    data = read(offset, _prov.CONTEXT_BYTES)
                    lb = max(offset - _prov.LOOKBEHIND_BYTES, s)
                    prefix = read(lb, offset - lb) if offset > lb else b""
                    records = _prov.classify(data, prefix)
                    if all_authors and not records:
                        m = _prov.PATTERN_AUTHOR.match(data)
                        if m:
                            records = [("author*", m.group("user").decode(errors="replace"), m.group(0))]
                    is_file = not backing.startswith("[")
                    for tier, evidence, matched in records:
                        a = agg.setdefault((tier, evidence), [0, set(), 0, 0, offset])
                        a[0] += 1
                        a[1].add(s)
                        a[2 if is_file else 3] += 1
                        if dump:
                            txt = matched.split(b"\x00")[0].decode("utf-8", errors="replace")
                            dump_lines.append(f"{offset:#018x}\t{tier}\t{evidence}\t{backing}\t{txt}")
            if dump and dump_lines:
                fh = self.open(f"pid.{pid}.ferric-provenance.txt")
                fh.write("\n".join(dump_lines).encode() + b"\n")
                fh.close()
            # target row (0.1.4): only for a process called Rust-built, i.e. with file-backed compiler hits
            if any(t == "compiler" and v[2] > 0 for (t, _), v in agg.items()):
                exe_base = min((s for s, e, k, b in regions.rows if b == _exe), default=None) if _exe else None
                dlls = pe_import_dlls(read, exe_base) if exe_base is not None else None
                std_deps = [ev for (t, ev) in agg if t == "std-dep"]
                triple, why, n = infer_windows_target(dlls, std_deps)
                agg[("target", f"{triple} ({why})")] = [n, {exe_base or 0}, 1 if dlls else 0, 0, exe_base or 0]
            order = {"compiler": 0, "target": 1, "std-dep": 2, "toolchain": 3, "dependency": 4, "author": 5, "author*": 6}
            for (tier, evidence), (hits, vmas, fh_, ah_, first) in sorted(agg.items(), key=lambda kv: (order.get(kv[0][0], 9), -kv[1][0], kv[0][1])):
                shown = f"rustc {evidence[:12]} = {_prov.version_for(evidence, extra_map)}" if tier == "compiler" else evidence
                yield (0, (pid, name, tier, shown, hits, len(vmas), fh_, ah_, format_hints.Hex(first)))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Tier", str), ("Evidence", str), ("Hits", int), ("VMAs", int),
             ("FileHits", int), ("AnonHits", int), ("FirstOffset", format_hints.Hex)],
            self._generator())
