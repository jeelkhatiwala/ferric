# ferric.provenance — Rust toolchain provenance recovered from a live process's memory.
#
# Written against Volatility 3 framework 2.28.2 (pslist 4.1.1), following the structure of the
# upstream linux.vmaregexscan plugin so it can be reviewed in the same style. It differs from that
# plugin in one deliberate way: VMAs are read contiguously instead of through layer.scan(), because
# the framework scan splits a VMA at every physical page discontinuity without overlap and misses
# patterns that straddle page boundaries (see the note above iter_pattern_offsets).
#
# What it does
#   For each selected task it builds the process layer, reads every VMA once, matches a single
#   compiled pattern, and classifies each hit into one of five provenance tiers:
#     compiler    /rustc/<40-hex commit>/library/...   -> rustc git commit (and version, if known)
#     std-dep     /rust/deps/<crate>-<semver>/... (or /cargo/registry/src/<idx>/<crate>-<semver>/
#                 on older toolchains)                   -> std's vendored dependency versions
#     toolchain   .rustup/toolchains/<name>/...         -> toolchain name (carries the version)
#     dependency  .cargo/registry/src/<index>/<crate>-<semver>/ -> crate and exact version
#     author      /home/<u>/..., /Users/<u>/..., X:\Users\<u>\... (Rust-specific suffix required)
#   Hits are aggregated per (task, tier, evidence) with a count, the number of distinct VMAs
#   involved, and how many hits sit in file-backed vs anonymous memory. A compiler fingerprint
#   that is present only in anonymous memory, with none in the mapped executable, is the
#   signature of a binary whose on-disk image does not carry the strings (e.g. packed).
#
# Why these strings exist
#   core::panic::Location records are emitted for panicking operations (unwrap, expect, index,
#   arithmetic overflow checks, ...). Their file paths come from where the code was compiled.
#   The standard library is prebuilt by the Rust project with --remap-path-prefix to
#   /rustc/<commit>/, so every program linked against the shipped std carries that commit.
#   An author's own --remap-path-prefix does not touch it (measured: zero effect).
#
# Known limits (stated, not hidden)
#   * Version lookup for the compiler tier uses a small table of commits verified in our lab
#     plus an optional --commit-map CSV (commit,version). Unknown commits are reported as such;
#     nothing is guessed.
#   * Counts are occurrences of the pattern in mapped, readable pages at capture time. Pages
#     that are unmapped, swapped, or unreadable are not counted and not estimated.
#   * The author tier is the weakest signal (it dies under $HOME remapping) and is labelled so.

import bisect
import csv
import logging
import re
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

# rustc commits verified in the lab by building with each toolchain and reading the hash back
# from the resulting binaries and from live process memory (NOTEBOOK sessions 18-37).
# Extend with --commit-map; obtain a commit with `rustc +<ver> -vV` (commit-hash line).
KNOWN_COMMITS: Dict[str, str] = {
    "8ede3aae28fe6e4d52b38157d7bfe0d3bceef225": "1.71.0",
    "aedd173a2c086e558c2b66d3743b344f977621a7": "1.77.0",
    "90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf": "1.83.0",
    "29483883eed69d5fb4db01964cdf2af4d86e9cb2": "1.89.0",
    "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4": "1.99.0",
}

# Two patterns, matched INDEPENDENTLY over the same bytes (see iter_pattern_offsets):
#   PATTERN_CORE   short, bounded alternatives that cannot contain one another
#   PATTERN_AUTHOR the one greedy alternative (a home-directory path)
# Why two: Rust string literals are packed in .rodata with no terminators, so one regex with a greedy
# alternative can swallow the literal that follows it (a registry path immediately followed by a
# /rustc/<hash>/library/ path). With one combined finditer the compiler hit was lost: measured 4 misses
# across 3 tokio images (NOTEBOOK session 42). Independent passes cannot hide hits from each other.
_SEMVER = rb"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]{1,32})?"
PATTERN_CORE = re.compile(
    # the remapped prefix is always /rustc/<hash>; what follows uses the separator of the host that built
    # std, so Windows-built binaries carry /rustc/<hash>\library\core\src\... (0.3.1; measure on win-img01)
    rb"(?P<compiler>/rustc/(?P<commit>[0-9a-f]{40})[\\/]library[\\/])"
    # 0.3.3: Windows-built std writes /rust/deps\<crate>-<ver>\ (host separator after the remapped
    # prefix); 0.3.1 accepted either separator only after the version, so every Windows std-dep was lost.
    rb"|(?P<stddep>/rust/deps[\\/](?P<dcrate>[A-Za-z0-9_\-]{1,64}?)-(?P<dver>" + _SEMVER + rb")[\\/])"
    # std's vendored deps on older toolchains: the Rust CI cargo home (/cargo, no user) un-remapped.
    # Hypothesis for rustc <= 1.71 where no /rust/deps/ strings were observed; confirm on images.
    rb"|(?P<stddep2>/cargo/registry/src/[^/\x00]{1,96}/(?P<dcrate2>[A-Za-z0-9_\-]{1,64}?)-(?P<dver2>" + _SEMVER + rb")/)"
    rb"|(?P<toolchain>\.rustup[\\/]toolchains[\\/](?P<tcname>[0-9A-Za-z._\-]{1,96})[\\/])"
    rb"|(?P<dependency>\.cargo[\\/]registry[\\/]src[\\/][^\\/\x00]{1,96}[\\/]"
    rb"(?P<crate>[A-Za-z0-9_\-]{1,64}?)-(?P<ver>" + _SEMVER + rb")[\\/])",
    re.DOTALL,
)
PATTERN_AUTHOR = re.compile(
    rb"(?P<author>(?:/home/|/Users/|[A-Za-z]:\\Users\\)(?P<user>[^\\/\x00]{1,64})[\\/]"
    rb"(?P<apath>(?:[^\x00\\/]{1,96}[\\/]){0,16}[^\x00\\/]{0,128}))",
    re.DOTALL,
)
PATTERNS = (PATTERN_CORE, PATTERN_AUTHOR)
PATTERN = PATTERN_CORE   # backwards-compatible name used by tests
# the author alternative is only accepted when the path is unmistakably Rust-related. 0.3.2: the cargo and
# rustup markers name the directories that hold SOURCES (registry, git checkouts, toolchains), not the
# tool directory: a PATH that contains ~/.cargo/bin sits in the environment block of EVERY process started
# from that shell, and the C++ and Go negative controls showed it as an "author" record (Session 65).
_AUTHOR_RUST_MARKERS = (b"/.cargo/registry/", b"\\.cargo\\registry\\", b"/.cargo/git/", b"\\.cargo\\git\\",
                        b"/.rustup/toolchains/", b"\\.rustup\\toolchains\\",
                        b"/target/", b"\\target\\", b".rs")
# a path followed by ':' and another absolute path is an element of a PATH-like list, not a source path
_PATH_LIST = re.compile(rb"^[^\x00:]*:(?:/|[A-Za-z]:\\)")
_HOME_PREFIX = re.compile(rb"(?:/home/|/Users/|[A-Za-z]:\\Users\\)([^\\/\x00]{1,64})[\\/]")

# std's own vendored crates (library/Cargo.lock of the shipped toolchains). Used for one purpose only:
# recognising std's dependencies when the Rust project's Windows CI left its cargo home un-remapped.
STD_VENDORED = frozenset({
    "addr2line", "adler", "adler2", "cfg-if", "compiler_builtins", "dlmalloc", "fortanix-sgx-abi", "getopts",
    "gimli", "hashbrown", "hermit-abi", "libc", "memchr", "miniz_oxide", "object", "r-efi", "r-efi-alloc",
    "rustc-demangle", "std_detect", "unicode-width", "unwinding", "wasi",
})
# 0.3.3: Windows std of rustc <= 1.71 was built on GitHub-hosted Windows runners (account runneradmin)
# without remapping the cargo home, so its vendored deps read
#   C:\Users\runneradmin\.cargo\registry\src\<index>\<crate>-<ver>\...
# (measured: hashbrown-0.13.1, rustc-demangle-0.1.21 in every 1.71 MSVC and gnu seed build). Such a path
# is std-dep, not dependency, and its home directory is the Rust project's CI, not an author.
# Limit: a malware author who also builds on a GitHub-hosted Windows runner and depends on one of the
# STD_VENDORED crates would have that dependency reported as std-dep.
_CI_HOME_TAIL = re.compile(rb"[A-Za-z]:\\Users\\runneradmin\\$")
_CI_STD_PATH = re.compile(rb"^[A-Za-z]:\\Users\\runneradmin\\\.cargo\\registry\\src\\[^\\\x00]{1,96}\\"
                          rb"(?P<crate>[A-Za-z0-9_\-]{1,64}?)-" + _SEMVER + rb"\\")

CONTEXT_BYTES = 512      # read at each hit for re-matching and extraction
LOOKBEHIND_BYTES = 192   # read before a dependency hit to recover a home-dir prefix (author tier)

# Why this plugin does NOT use layer.scan():
#   TranslationLayerInterface._scan_iterator ships every physically-contiguous run of pages as its
#   own chunk with no overlap between runs (verified against 2.28.2, tests/test_framework_scan_pagegap.py).
#   A VMA whose pages are scattered in RAM is therefore scanned page by page and any pattern that
#   straddles a 4 KiB boundary is never matched. Measured loss on real images: 1/97 and 2/45.
#   Reading each VMA as one contiguous virtual range (what linux.proc.Maps --dump does) avoids it.
WINDOW_BYTES = 16 * 1024 * 1024   # read VMAs in windows of this size ...
WINDOW_OVERLAP = 8192             # ... overlapping by this much; must exceed the longest possible match
MAXSIZE_DEFAULT = 1024 * 1024 * 1024  # VMAs larger than this are skipped and reported (same default as Maps)


def iter_pattern_offsets(read, start: int, end: int, pattern=None, patterns=None,
                         window: int = WINDOW_BYTES, overlap: int = WINDOW_OVERLAP):
    """Yield absolute offsets of every match of each pattern in [start, end), reading through
    `read(offset, size)` (which must zero-pad unreadable bytes) in overlapping windows. Patterns are
    matched independently over the same bytes, so a greedy match of one cannot hide a match of another.
    Each match is reported once: a window owns matches starting in its first (size - overlap) bytes,
    except the last window which owns everything. Requires overlap >= longest match."""
    pats = patterns if patterns is not None else ((pattern,) if pattern is not None else PATTERNS)
    pos = start
    while pos < end:
        size = min(window, end - pos)
        data = read(pos, size)
        last = pos + size >= end
        limit = size if last else size - overlap
        found = set()
        for pat in pats:
            for m in pat.finditer(data):
                if m.start() < limit:
                    found.add(pos + m.start())
        yield from sorted(found)
        if last:
            break
        pos += limit


def classify(data: bytes, prefix: bytes = b"") -> List[Tuple[str, str, bytes]]:
    """Classify a hit found at data[0]. Returns a list of (tier, evidence, matched): one record per
    hit (a registry path under /home/<u>/ produces a dependency record at its .cargo offset and an
    author record at its /home/ offset, each found by its own pass). Pure function, unit-tested
    without the framework. `prefix` (bytes preceding the hit) is kept for API stability; unused.
    """
    out: List[Tuple[str, str, bytes]] = []
    m = PATTERN_CORE.match(data)
    if m:
        if m.group("compiler"):
            out.append(("compiler", m.group("commit").decode(), m.group(0)))
        elif m.group("stddep"):
            out.append(("std-dep",
                        f"{m.group('dcrate').decode(errors='replace')}-{m.group('dver').decode(errors='replace')}",
                        m.group(0)))
        elif m.group("stddep2"):
            out.append(("std-dep",
                        f"{m.group('dcrate2').decode(errors='replace')}-{m.group('dver2').decode(errors='replace')}",
                        m.group(0)))
        elif m.group("toolchain"):
            out.append(("toolchain", m.group("tcname").decode(errors="replace"), m.group(0)))
        elif m.group("dependency"):
            crate = m.group("crate").decode(errors="replace")
            ver = m.group("ver").decode(errors="replace")
            ci_std = crate in STD_VENDORED and bool(_CI_HOME_TAIL.search(prefix))
            out.append(("std-dep" if ci_std else "dependency", f"{crate}-{ver}", m.group(0)))
            # a home-directory prefix before this registry path is reported by the independent
            # author pass (PATTERN_AUTHOR), so it is not emitted here: one string, one author record
        return out
    m = PATTERN_AUTHOR.match(data)
    if m:
        full = m.group(0)
        ci = _CI_STD_PATH.match(full)
        if ci and ci.group("crate").decode(errors="replace") in STD_VENDORED:
            return out          # the Rust project's Windows CI building std (see _CI_HOME_TAIL), not an author
        if any(mk in full for mk in _AUTHOR_RUST_MARKERS) and not _PATH_LIST.match(full):
            out.append(("author", m.group("user").decode(errors="replace"), full))
    return out


def version_for(commit: str, extra: Dict[str, str]) -> str:
    v = extra.get(commit) or KNOWN_COMMITS.get(commit)
    return v if v else "unknown (add to --commit-map)"


class Provenance(plugins.PluginInterface):
    """Recovers Rust toolchain provenance (compiler commit, toolchain, dependency crates,
    author paths) from the memory of running processes, with file-backed vs anonymous
    placement of the evidence."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 3, 3)   # 0.2.0 contiguous VMA reads; 0.3.0 independent core/author passes, /cargo/registry std-dep form
                           # 0.3.1 compiler/std-dep alternatives accept either path separator (Windows-built std)
                           # 0.3.2 author tier: source-directory markers only; PATH-list elements rejected
                           # 0.3.3 /rust/deps\ (Windows std-dep); Windows CI cargo home of std <= 1.71 is std-dep

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid", description="Filter on specific process IDs",
                element_type=int, optional=True,
            ),
            requirements.StringRequirement(
                name="commit-map",
                description="CSV of rustc commit,version pairs to extend the built-in table",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump-hits",
                description="Write every individual hit (offset, tier, string, backing) to a "
                "file per process for the evidence archive",
                default=False, optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-authors",
                description="Also report author-tier paths that lack a Rust marker "
                "(noisier; off by default)",
                default=False, optional=True,
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Skip (and log) VMAs larger than this many bytes",
                default=MAXSIZE_DEFAULT, optional=True,
            ),
        ]

    # ------------------------------------------------------------------ helpers
    def _load_commit_map(self) -> Dict[str, str]:
        path = self.config.get("commit-map", None)
        extra: Dict[str, str] = {}
        if not path:
            return extra
        try:
            with open(path, newline="") as f:
                for row in csv.reader(f):
                    if len(row) >= 2 and re.fullmatch(r"[0-9a-f]{40}", row[0].strip()):
                        extra[row[0].strip()] = row[1].strip()
        except OSError as e:
            vollog.warning(f"commit-map not readable ({e}); using built-in table only")
        return extra

    def _vma_table(self, task) -> Tuple[List[int], List[Tuple[int, int, str]]]:
        """Sorted VMA table: starts list for bisect, and (start, end, backing-name) rows.
        backing-name is the mapped file's path for file-backed VMAs; anonymous VMAs are
        '[heap]', '[stack]', '[vdso]' or '[anon]' (upstream's naming, bracketed)."""
        rows: List[Tuple[int, int, str]] = []
        for vma in task.mm.get_vma_iter():
            try:
                start, end = int(vma.vm_start), int(vma.vm_end)
            except exceptions.InvalidAddressException:
                continue
            try:
                file_backed = int(vma.vm_file) != 0
            except exceptions.InvalidAddressException:
                file_backed = False
            name = vma.get_name(self.context, task)
            if file_backed:
                backing = name or "[file]"
            else:
                backing = "[anon]" if (not name or name == "Anonymous Mapping") else name
            rows.append((start, end, backing))
        rows.sort()
        return [r[0] for r in rows], rows

    @staticmethod
    def _backing_for(offset: int, starts: List[int], rows: List[Tuple[int, int, str]]) -> Tuple[int, str]:
        i = bisect.bisect_right(starts, offset) - 1
        if i >= 0 and rows[i][0] <= offset < rows[i][1]:
            return rows[i][0], rows[i][2]
        return -1, "[unmapped?]"

    # ------------------------------------------------------------------ core
    def _scan_task(self, task, extra_map: Dict[str, str], dump: bool, all_authors: bool):
        pid = int(task.pid)
        name = utility.array_to_string(task.comm)
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            return
        layer = self.context.layers[proc_layer_name]
        starts, rows = self._vma_table(task)
        if not rows:
            return
        maxsize = int(self.config.get("maxsize", MAXSIZE_DEFAULT))

        # key -> [hits, set(vma starts), file_hits, anon_hits, first_offset]
        agg: Dict[Tuple[str, str], list] = {}
        dump_lines: List[str] = []

        def read(off: int, size: int) -> bytes:
            return layer.read(off, size, pad=True)

        def offsets():
            for s, e, backing in rows:
                if e <= s:
                    continue
                if e - s > maxsize:
                    vollog.warning(f"pid {pid}: skipping VMA {s:#x}-{e:#x} ({e - s} bytes > maxsize) [{backing}]")
                    continue
                yield from iter_pattern_offsets(read, s, e)

        for offset in offsets():
            data = layer.read(offset, CONTEXT_BYTES, pad=True)
            vstart, backing = self._backing_for(offset, starts, rows)
            lb = max(offset - LOOKBEHIND_BYTES, vstart if vstart >= 0 else offset)
            prefix = layer.read(lb, offset - lb, pad=True) if offset > lb else b""
            records = classify(data, prefix)
            if all_authors and not records:
                m = PATTERN_AUTHOR.match(data)
                if m:
                    records = [("author*", m.group("user").decode(errors="replace"), m.group(0))]
            is_file = not backing.startswith("[")      # [anon]/[heap]/[stack]/[vdso]/[unmapped?]
            for tier, evidence, matched in records:
                a = agg.setdefault((tier, evidence), [0, set(), 0, 0, offset])
                a[0] += 1
                a[1].add(vstart)
                if is_file:
                    a[2] += 1
                else:
                    a[3] += 1
                if dump:
                    s = matched.split(b"\x00")[0].decode("utf-8", errors="replace")
                    dump_lines.append(f"{offset:#018x}\t{tier}\t{evidence}\t{backing}\t{s}")

        if dump and dump_lines:
            fh = self.open(f"pid.{pid}.ferric-provenance.txt")
            fh.write("\n".join(dump_lines).encode() + b"\n")
            fh.close()
            vollog.info(f"wrote {len(dump_lines)} hits to {fh.preferred_filename}")

        order = {"compiler": 0, "std-dep": 1, "toolchain": 2, "dependency": 3, "author": 4, "author*": 5}
        for (tier, evidence), (hits, vmas, fh_, ah_, first) in sorted(
            agg.items(), key=lambda kv: (order.get(kv[0][0], 9), -kv[1][0], kv[0][1])
        ):
            shown = evidence
            if tier == "compiler":
                shown = f"rustc {evidence[:12]} = {version_for(evidence, extra_map)}"
            yield (0, (pid, name, tier, shown, hits, len(vmas), fh_, ah_, format_hints.Hex(first)))

    def _generator(self, tasks: Iterable):
        extra_map = self._load_commit_map()
        dump = bool(self.config.get("dump-hits", False))
        all_authors = bool(self.config.get("all-authors", False))
        for task in tasks:
            try:
                if not (task.mm and task.mm.is_readable()):
                    continue
            except exceptions.InvalidAddressException:
                continue
            yield from self._scan_task(task, extra_map, dump, all_authors)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Tier", str),
                ("Evidence", str),
                ("Hits", int),
                ("VMAs", int),
                ("FileHits", int),
                ("AnonHits", int),
                ("FirstOffset", format_hints.Hex),
            ],
            self._generator(
                pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=filter_func)
            ),
        )
