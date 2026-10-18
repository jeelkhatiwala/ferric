#!/usr/bin/env python3
"""Score ferric.vtables outputs against the control binaries' symbol tables (precision) and the seeds'
known trait objects (recall). Pre-registered in eval/METRICS.md.

How a row is checked (needs pyelftools: `pip install pyelftools` in the analysis venv)
  The plugin reports every vtable with the module that backs it and that module's load base, so
  file address = VTable - Base for a position-independent binary (VTable itself for ET_EXEC). The words
  at that file address are read from the UNSTRIPPED TWIN of the captured binary (the strip-none build of
  the same matrix cell, or the binary itself when it carries .symtab) with R_X86_64_RELATIVE / RELR
  relocations applied. A row is CONFIRMED when its drop slot is null or the start of a function whose
  symbol names drop_in_place, and every method slot the plugin counted is the start of a function.
  Anything else is a FALSE POSITIVE. precision = confirmed / scored rows.
  The twin is trusted only when every PT_LOAD segment of the captured binary and the twin hold identical
  bytes (a stripped link differs from its unstripped twin only in non-allocated sections); a mismatch is
  reported and that image is not scored.
Recall
  seed01: Box<dyn Display> holding a usize -> one vtable: size 8, align 8, 1 method, whose method symbol
          carries the identifiers Display and fmt (usize is a single-letter primitive in v0 mangling, so
          it cannot be required by name).
  seed03: Box<dyn Shape> for Circle (size 32), Rect (40), Triangle (40): align 8, 2 methods, method
          symbols carrying the type name, Shape, name and area.
  seed02: tokio internals carry many vtables that the source does not enumerate; precision only.
  A known vtable is RECOVERED when a confirmed row matches its shape and its identifiers.
Drop form
  The fraction of confirmed rows with a null drop slot, by rustc version: the measurement behind the
  v0.1 -> v0.2 fix (rust-lang/rust PR 122662).
Negative control
  ferric_vtables_allprocs.txt: rows outside the target pid, by process and module. No binaries are held
  for those processes, so they are counted and listed, not symbol-checked.

Inputs : MANIFEST/images.csv (target_binary_id, pid); MANIFEST/binaries.csv (path); control-corpus/build/...;
         analysis/<img>.vol/ferric_vtables.txt [ferric_vtables_allprocs.txt]
Usage  : python3 eval/make_table_vtables.py [--repo .] [--tsv out.tsv] [--show-fp N]
"""
import argparse
import bisect
import hashlib
import os
import re
import struct
import sys
from collections import Counter
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import image_class, parse_grid, images, binaries, find_output  # noqa: E402

try:
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError
except ImportError:
    sys.exit("pyelftools is required: pip install pyelftools   (inside the analysis venv)")

# family -> [(label, size, align, methods, required identifiers in the method symbols)]
EXPECT = {
    "seed01_collections": [("<usize as Display>", 8, 8, 1, {"Display", "fmt"})],
    "seed03_graph": [("<Circle as Shape>", 32, 8, 2, {"Circle", "Shape", "name", "area"}),
                     ("<Rect as Shape>", 40, 8, 2, {"Rect", "Shape", "name", "area"}),
                     ("<Triangle as Shape>", 40, 8, 2, {"Triangle", "Shape", "name", "area"})],
}


class Elf:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.pie = self.elf["e_type"] == "ET_DYN"
        self.segs = [(s["p_vaddr"], s["p_vaddr"] + s["p_filesz"], s["p_offset"], s["p_filesz"])
                     for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.exec_ranges = [(s["p_vaddr"], s["p_vaddr"] + s["p_memsz"]) for s in self.elf.iter_segments()
                            if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1]
        self.funcs = []
        symtab = self.elf.get_section_by_name(".symtab")
        self.has_symtab = symtab is not None and symtab.num_symbols() > 0
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
                    self.funcs.append((sym["st_value"], sym["st_size"], sym.name))
        self.funcs.sort()
        self.starts = [x[0] for x in self.funcs]
        self.relocs = {}
        for sec in self.elf.iter_sections():
            if sec["sh_type"] == "SHT_RELA":
                for r in sec.iter_relocations():
                    if r["r_info_type"] == 8:              # R_X86_64_RELATIVE: *where = base + addend
                        self.relocs[r["r_offset"]] = r["r_addend"]
            elif sec["sh_type"] == "SHT_RELR":
                data = sec.data()
                where = 0
                for (entry,) in struct.iter_unpack("<Q", data):
                    if entry & 1 == 0:
                        self.relocs[entry] = None      # addend is the word stored in the file
                        where = entry + 8
                    else:
                        bits = entry >> 1
                        i = 0
                        while bits:
                            if bits & 1:
                                self.relocs[where + i * 8] = None
                            bits >>= 1
                            i += 1
                        where += 63 * 8

    def read(self, vaddr, n):
        for lo, hi, off, _sz in self.segs:
            if lo <= vaddr and vaddr + n <= hi:
                self.f.seek(off + (vaddr - lo))
                return self.f.read(n)
        return None

    def masked_ranges(self):
        """Loaded byte ranges that legitimately differ between a stripped link and its unstripped twin:
        the ELF header (section-table fields) and the build-id note, whose hash covers the symbol table.
        Measured on twin builds (rustc 1.97, lld): these two ranges are the only loaded differences."""
        out = [(0, 64)]
        for sec in self.elf.iter_sections():
            if sec.name == ".note.gnu.build-id" and sec["sh_flags"] & 2:
                out.append((sec["sh_addr"], sec["sh_size"]))
        return out

    def loaded(self):
        """[(vaddr, bytes)] per PT_LOAD segment, masked ranges zeroed."""
        out = []
        masks = self.masked_ranges()
        for lo, hi, off, sz in sorted(self.segs):
            self.f.seek(off)
            data = bytearray(self.f.read(sz))
            for mlo, msz in masks:
                a, b = max(mlo, lo), min(mlo + msz, lo + sz)
                if a < b:
                    data[a - lo:b - lo] = b"\0" * (b - a)
            out.append((lo, bytes(data)))
        return out

    def segment_digest(self):
        """sha256 over every PT_LOAD segment's (vaddr, filesz, masked bytes)."""
        h = hashlib.sha256()
        for lo, data in self.loaded():
            h.update(struct.pack("<QQ", lo, len(data)))
            h.update(data)
        return h.hexdigest()

    def section_of(self, vaddr):
        for sec in self.elf.iter_sections():
            if sec["sh_flags"] & 2 and sec["sh_addr"] <= vaddr < sec["sh_addr"] + sec["sh_size"]:
                return sec.name
        return "?"


    def words(self, vaddr, n):
        raw = self.read(vaddr, n * 8)
        if raw is None:
            return None
        qs = list(struct.unpack(f"<{n}Q", raw))
        for i in range(n):
            a = vaddr + i * 8
            if a in self.relocs and self.relocs[a] is not None:
                qs[i] = self.relocs[a]
        return qs

    def symbolize(self, addr):
        """(name, at_start) for a code address, from .symtab."""
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            a, sz, nm = self.funcs[i]
            if addr == a:
                return nm, True
            if a < addr < a + max(sz, 1):
                return nm, False
        return None, False


_LEN_IDENT = re.compile(r"(\d+)")


def explain_mismatch(target: "Elf", twin: "Elf") -> str:
    """Where the loaded bytes differ, by section of the twin, so a MISMATCH is diagnosable from the table."""
    ta, tb = target.loaded(), twin.loaded()
    if [lo for lo, _ in ta] != [lo for lo, _ in tb] or any(len(a[1]) != len(b[1]) for a, b in zip(ta, tb)):
        return "segment layout differs"
    where = Counter()
    for (lo, da), (_lo, db) in zip(ta, tb):
        if da == db:
            continue
        for i in range(0, len(da), 64):
            if da[i:i + 64] != db[i:i + 64]:
                where[twin.section_of(lo + i)] += 1
    return "differs in " + ", ".join(f"{s}({n}x64B)" for s, n in where.most_common(4))


def identifiers(mangled: str):
    """Identifiers inside a legacy (_ZN) or v0 (_R) mangled Rust symbol. Both encode identifiers as
    <len><chars>; a length that does not fit a run of identifier characters is skipped. Legacy identifiers
    are further split on their $..$ escapes and '..' path separators."""
    out = set()
    for m in _LEN_IDENT.finditer(mangled):
        n = int(m.group(1))
        s = m.end()
        if n == 0 or s + n > len(mangled):
            continue
        ident = mangled[s:s + n]
        if not re.fullmatch(r"[A-Za-z_$.][A-Za-z0-9_$.]*", ident):
            continue
        for part in re.split(r"\$[^$]*\$|\.\.|\.", ident):
            if part:
                out.add(part)
    return out


PROLOGUE_BYTES = 32   # bytes compared at each function start when a twin is verified locally


def check_row(twin: Elf, vaddr: int, methods: int, target: Optional[Elf] = None):
    """Confirm a reported vtable at file address vaddr with `methods` method slots. Returns
    (verdict, reason, method_symbols) with verdict True (confirmed), False (false row) or None
    (unverifiable: the twin's bytes differ from the captured binary's at this row, so no verdict).
    With `target` (the captured binary) given, the twin is verified LOCALLY for this row: the vtable's own
    words and the first PROLOGUE_BYTES of every function it points to must be identical in both files.
    That is what makes the twin's symbol trustworthy for this row when the two links are not identical
    everywhere (measured: seed01 twins on the GNU-ld toolchains differ in a few .text chunks)."""
    qs = twin.words(vaddr, 3 + methods)
    if qs is None:
        return False, "unreadable in twin", []
    if target is not None:
        if target.words(vaddr, 3 + methods) != qs:
            return None, "unverified: vtable bytes differ between the captured binary and the twin", []
        for w in [qs[0]] + list(qs[3:]):
            if w and target.read(w, PROLOGUE_BYTES) != twin.read(w, PROLOGUE_BYTES):
                return None, f"unverified: function bytes at {w:#x} differ between the captured binary and the twin", []
    drop = qs[0]
    if drop != 0:
        nm, at = twin.symbolize(drop)
        if not at:
            return False, f"drop slot {drop:#x} is not a function start ({nm})", []
        if "drop_in_place" not in nm and "drop_glue" not in nm:
            return False, f"drop slot is not drop_in_place: {nm[:60]}", []
    syms = []
    for w in qs[3:]:
        nm, at = twin.symbolize(w)
        if not at:
            return False, f"method slot {w:#x} is not a function start ({nm})", syms
        syms.append(nm)
    return True, "", syms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    ap.add_argument("--show-fp", type=int, default=5, help="print up to N false positives per image")
    a = ap.parse_args()
    imgs = images(a.repo)
    bins = binaries(a.repo)
    tsv = open(a.tsv, "w") if a.tsv else None
    if tsv:
        tsv.write("image_id\trustc\tfamily\ttwin\tscored\tconfirmed\tfalse\tother_module\tnull_drop\tfn_drop\texpected\trecovered\n")
    tot = Counter()
    by_ver = {}
    by_ver_all = {}
    elf_cache = {}
    print(f"{'image_id':66s} rustc   twin      rows  scored conf  FP   null/fn   recall      other-module")
    for im in imgs:
        pid = int(im["pid"] or 0)
        if pid == 0 or image_class(im) in ("negative", "benign", "wild"):
            continue          # non-Rust and benign-Rust programs are scored by make_table_negatives.py
        fam = im["family_or_label"]
        f = find_output(a.repo, im["image_id"], "ferric_vtables.txt")
        rows = parse_grid(f) if f else None
        if rows is None:
            tot["noout"] += 1
            print(f"{im['image_id']:66s} {im['rustc_version']:7s} NO OUTPUT")
            continue
        mine = [r for r in rows if r["PID"] == pid]
        # the captured binary and its unstripped twin
        bid = im["target_binary_id"]
        status, twin, target = "no-binary", None, None
        unrecorded = ""
        local_verify = False

        def locate(binary_id):
            """Path of a control binary: from binaries.csv, else the build convention
            control-corpus/build/<binary_id> (used, but flagged, when the manifest row is missing)."""
            nonlocal unrecorded
            row = bins.get(binary_id)
            if row:
                return os.path.join(a.repo, row["path"]), False
            conv = os.path.join(a.repo, "control-corpus", "build", binary_id)
            if os.path.exists(conv):
                unrecorded = "*"
                return conv, True
            return None, False

        tpath, _unrec = locate(bid)
        if im.get("os") == "windows":
            # Windows twins are PE .exe files, not ELF; symbol confirmation needs a PE/PDB scorer that does
            # not exist yet, so Windows vtables are scored by shape only (RESULTS-windows.md). Do not open
            # the .exe as ELF (it raises ELFError). The shape rows are still counted via `mine` below.
            status = "pe-shape-only"
            tpath = None
        if tpath is not None and os.path.exists(tpath):
            try:
                target = elf_cache.get(tpath) or Elf(tpath)
            except ELFError:
                target, status = None, "not-elf"
                tpath = None
            else:
                elf_cache[tpath] = target
            if target is None:
                pass                       # not an ELF (e.g. a Windows PE): shape-only, status already set
            elif target.has_symtab:
                twin, status = target, "self"
            else:
                tid = bid.replace("strip-symbols", "strip-none")
                tp, _unrec = locate(tid) if tid != bid else (None, False)
                if tp is not None and os.path.exists(tp):
                    twin = elf_cache.get(tp) or Elf(tp)
                    elf_cache[tp] = twin
                    if not twin.has_symtab:
                        status, twin = "twin-no-symtab", None
                    elif twin.segment_digest() != target.segment_digest():
                        # not identical everywhere: keep the twin, verify every row locally (check_row with target)
                        status = "local:" + explain_mismatch(target, twin)
                        local_verify = True
                    else:
                        status = "ok"
                else:
                    status = "no-twin"
        elif tpath is not None:
            status = "binary-missing"
        if unrecorded:
            status += "*"
            tot["unrecorded_binaries"] += 1
        # which module is the target binary: the file name when known, else the module whose name begins
        # with the process comm (a 15-character truncation of the executable's name)
        exe_name = os.path.basename(tpath) if tpath else ""
        if not exe_name or not any(r["Module"] == exe_name for r in mine):
            comm = mine[0]["Process"] if mine else ""
            # Windows modules are image paths (\\corpus-build\\<id>.exe): compare the path's last component
            leaf = lambda m: str(m).replace("\\", "/").rsplit("/", 1)[-1]
            cands = Counter(r["Module"] for r in mine if comm and leaf(r["Module"]).startswith(comm))
            if cands:
                exe_name = cands.most_common(1)[0][0]
            elif mine and all(str(r["Module"]).startswith("Anonymous") for r in mine):
                # a packed binary (UPX) unpacks into anonymous memory: its vtables carry no module name
                exe_name = mine[0]["Module"]
                status += "(anon)"
        scored = [r for r in mine if r["Module"] == exe_name]
        other = Counter(r["Module"] for r in mine if r["Module"] != exe_name)
        conf = fp = unver = 0
        null_c = fn_c = 0
        fps = []
        confirmed_rows = []
        if twin is not None:
            for r in scored:
                vaddr = r["VTable"] - r["Base"] if target.pie else r["VTable"]
                ok, why, syms = check_row(twin, vaddr, r["Methods"], target if local_verify else None)
                if ok:
                    conf += 1
                    confirmed_rows.append((r, syms))
                    if r["Drop"] == "null":
                        null_c += 1
                    else:
                        fn_c += 1
                elif ok is None:
                    unver += 1
                    fps.append((r, why))
                else:
                    fp += 1
                    fps.append((r, why))
        stale = False
        if twin is not None and scored and fp > len(scored) // 2:
            # the recorded binary is not the one that ran (manifest target_binary_id), or the twin is wrong:
            # a real plugin false-positive rate above 50% would contradict every other image. Reported
            # apart from precision, never silently dropped.
            stale = True
            status = "STALE-BINARY?"
        # recall against the seed's known trait objects
        expect = EXPECT.get(fam, [])
        recovered = []
        over = []
        for label, size, align, nmeth, idents in expect:
            hit = False
            over_hit = None
            for r, syms in confirmed_rows:
                if r["Size"] == size and r["Align"] == align and r["Methods"] >= nmeth:
                    have = set()
                    for s in syms:
                        have |= identifiers(s)
                    if idents <= have:
                        if r["Methods"] == nmeth:
                            hit = True
                            break
                        over_hit = r["Methods"] - nmeth
            recovered.append((label, hit))
            if not hit and over_hit:
                over.append((label, over_hit))
        tot["recovered_over"] += len(over)
        rec_txt = f"{sum(h for _, h in recovered)}/{len(expect)}" if expect else "n/a"
        missed = [l for l, h in recovered if not h]
        miss_detail = [f"      {l}: found with {k} extra method slot(s) (counted as a miss; method run over-counted)" for l, k in over]
        for label, size, align, nmeth, idents in expect:
            if label in missed and twin is not None and not stale:
                # the type's own identifier is the first word of the label: "<Triangle as Shape>" -> Triangle
                type_ident = label.strip("<").split()[0]
                for r, syms in confirmed_rows:
                    have = set()
                    for s in syms:
                        have |= identifiers(s)
                    shape = r["Size"] == size and r["Align"] == align and r["Methods"] == nmeth
                    if shape or type_ident in have:
                        miss_detail.append(f"      {label}: {'shape match' if shape else 'name match'} at {r['VTable']:#x} "
                                           f"size={r['Size']} align={r['Align']} methods={r['Methods']} drop={r['Drop']}: "
                                           + " ; ".join(s[:60] for s in syms))
        if twin is None and expect:
            # no symbols to confirm against: report shape-only matches, kept apart from the real recall
            pool = scored if exe_name else mine
            shape_hits = sum(1 for _l, size, align, nmeth, _i in expect
                             if any(r["Size"] == size and r["Align"] == align and r["Methods"] == nmeth for r in pool))
            rec_txt = f"shape {shape_hits}/{len(expect)}"
            missed = []
            tot["shape_expected"] += len(expect); tot["shape_recovered"] += shape_hits
        v_all = by_ver_all.setdefault(im["rustc_version"], Counter())
        v_all["null"] += sum(1 for r in scored if r["Drop"] == "null")
        v_all["fn"] += sum(1 for r in scored if r["Drop"] == "fn")
        v_all["images"] += 1
        if twin is not None and stale:
            tot["images_stale"] += 1
            tot["stale_rows"] += len(scored); tot["stale_false"] += fp
            tot["expected_stale"] += len(expect)
        elif twin is not None:
            tot["images_scored"] += 1
            tot["scored"] += len(scored) - unver; tot["confirmed"] += conf; tot["fp"] += fp; tot["unverified"] += unver
            tot["null"] += null_c; tot["fn"] += fn_c
            tot["expected"] += len(expect); tot["recovered"] += sum(h for _, h in recovered)
            v = by_ver.setdefault(im["rustc_version"], Counter())
            v["scored"] += len(scored) - unver; v["confirmed"] += conf; v["fp"] += fp; v["null"] += null_c; v["fn"] += fn_c
            v["expected"] += len(expect); v["recovered"] += sum(h for _, h in recovered)
        elif twin is None:
            tot["images_unscored"] += 1
        tot["other_module"] += sum(other.values())
        print(f"{im['image_id']:66s} {im['rustc_version']:7s} {status[:9]:9s} {len(mine):<5d} {len(scored):<6d} {conf:<5d} {fp:<4d} "
              + (f"({unver} unverified) " if unver else "")
              + f"{null_c}/{fn_c:<6d} {rec_txt:10s}  {dict(other) if other else ''}"
              + (f"  MISSED {missed}" if missed else "") + (f"  [{status}]" if status.startswith(("MISMATCH", "local", "STALE")) else ""))
        for line in miss_detail:
            print(line)
        for r, why in fps[:a.show_fp]:
            print(f"      FP {r['VTable']:#x} size={r['Size']} align={r['Align']} methods={r['Methods']} drop={r['Drop']} "
                  f"coderefs={r['CodeRefs']} refs={r['Refs']}: {why}")
        if tsv:
            tsv.write("\t".join(str(x) for x in (im["image_id"], im["rustc_version"], fam, status, len(scored), conf, fp,
                                                  sum(other.values()), null_c, fn_c, len(expect), sum(h for _, h in recovered))) + "\n")
    print("\nSUMMARY")
    print(f"  images scored (twin available) : {tot['images_scored']}   unscored: {tot['images_unscored']}   no output: {tot['noout']}"
          + (f"   STALE-BINARY?: {tot['images_stale']} (rows {tot['stale_rows']}, {tot['stale_false']} failed; excluded from precision; fix target_binary_id)" if tot["images_stale"] else ""))
    n = tot["scored"]
    print(f"  rows in the target binary      : {n}   confirmed: {tot['confirmed']}   false: {tot['fp']}   "
          f"precision: {tot['confirmed'] / n:.3f}" if n else "  rows in the target binary      : 0")
    if tot["unverified"]:
        print(f"  rows unverifiable (twin differs locally): {tot['unverified']}   (not counted either way)")
    print(f"  rows in other modules (unscored): {tot['other_module']}")
    if tot["unrecorded_binaries"]:
        print(f"  images whose binary is on disk but NOT in binaries.csv (status marked *): {tot['unrecorded_binaries']}  -> manifest fix needed")
    print(f"  known trait objects recovered  : {tot['recovered']}/{tot['expected']}  (symbol-confirmed, scored images)"
          + (f"; {tot['recovered_over']} more found with an over-counted method run (not credited)" if tot["recovered_over"] else ""))
    if tot["shape_expected"]:
        print(f"  shape-only matches, unscored   : {tot['shape_recovered']}/{tot['shape_expected']}  (no twin binary; not a recall figure)")
    print(f"  drop form among confirmed      : null={tot['null']} fn={tot['fn']}")
    print("  drop form, ALL target-module rows (no twin needed; prediction: null only on rustc >= 1.79):")
    for ver, c in sorted(by_ver_all.items()):
        print(f"    {ver:8s} images={c['images']:<3d} null={c['null']:<4d} fn={c['fn']:<4d}")
    print("  by rustc version (symbol-scored):")
    for ver, c in sorted(by_ver.items()):
        p = f"{c['confirmed'] / c['scored']:.3f}" if c["scored"] else "n/a"
        print(f"    {ver:8s} scored={c['scored']:<4d} confirmed={c['confirmed']:<4d} false={c['fp']:<3d} precision={p:6s} "
              f"null-drop={c['null']:<4d} fn-drop={c['fn']:<4d} recall={c['recovered']}/{c['expected']}")
    print("  negative control (all processes; rows outside the target pid, by process):")
    for im in imgs:
        f = find_output(a.repo, im["image_id"], "ferric_vtables_allprocs.txt")
        if not f:
            continue
        rows = parse_grid(f)
        if rows is None:
            print(f"    {im['image_id']}: NO OUTPUT")
            continue
        pid = int(im["pid"] or 0)
        other = [r for r in rows if r["PID"] != pid]
        procs = Counter(f"{r['Process']}:{r['Module']}" for r in other)
        print(f"    {im['image_id']}: processes with rows={len({r['PID'] for r in rows})} rows outside target={len(other)} {dict(procs)}")
    if tsv:
        tsv.close()


if __name__ == "__main__":
    main()
