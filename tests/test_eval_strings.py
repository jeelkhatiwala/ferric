#!/usr/bin/env python3
"""Unit tests for eval/make_table_strings.py on a synthetic repo tree (one image, one seed truth, one
gated and one ungated all-process output). Pure; no volatility needed. Run: python3 tests/test_eval_strings.py
"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
from make_table_strings import score_target, negative_control, produced_by_current  # noqa: E402
from ferric_out import images  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

repo = tempfile.mkdtemp()
os.makedirs(os.path.join(repo, "MANIFEST")); os.makedirs(os.path.join(repo, "control-corpus", "seeds", "seedX"))
os.makedirs(os.path.join(repo, "analysis", "vsweep-05-x.elf.vol")); os.makedirs(os.path.join(repo, "plugins", "ferric"))
open(os.path.join(repo, "plugins", "ferric", "strings.py"), "w").write("# current plugin\n")
import hashlib
CUR = hashlib.sha256(b"# current plugin\n").hexdigest()
open(os.path.join(repo, "MANIFEST", "images.csv"), "w").write(
    "image_id,family_or_label,rustc_version,pid,image_path\nvsweep-05-x,seedX,1.99.0,42,/nowhere/vsweep-05-x.elf\n")
open(os.path.join(repo, "control-corpus", "seeds", "seedX", "TRUTH.strings.tsv"), "w").write(
    "# kind\ttext\tcap\tlen\tlineno\tapplies\tnote\n"
    "string\tmode\t4\t4\t-\t-\t\nstring\titem-0\t10\t6\t-\t-\t\n"
    "location\tsrc/main.rs\t-\t-\t12\t-\t\n"
    "template\titem-{}\t-\t-\t-\trustc>=1.93\t\ntemplate\t{} {} {}\\n\t-\t-\t-\trustc>=1.93\t\n"
    "str\titem-\t-\t-\t-\trustc<=1.92\t\n")
HDR = "Volatility 3 Framework 2.28.2\n\nPID\tProcess\tKind\tHeader\tHeaderIn\tPtr\tPtrIn\tLen\tCap\tLayout\tChecks\tText\n\n"
def row(pid, proc, kind, ln, cap, checks, text, layout="-"):
    return f"{pid}\t{proc}\t{kind}\t0x1000\theap\t0x2000\theap\t{ln}\t{cap}\t{layout}\t{checks}\t{text}\n"
target = (HDR + row(42, "seed", "compiler", 0, 0, "provenance", "rustc 1.99.0 (b940084d7eb6, 45 hits): templates scanned")
          + row(42, "seed", "string", 4, 4, "utf8,printable,chunk", "mode", "cap,ptr,len")
          + row(42, "seed", "string", 6, 10, "utf8,printable,chunk", "item-0", "cap,ptr,len")
          + row(42, "seed", "string", 5, 8, "utf8,printable", "extra", "cap,ptr,len")
          + row(42, "seed", "location", 11, 0, "utf8,rs,str", "src/main.rs:12:29")
          + row(42, "seed", "template", 7, 1, "utf8,printable,lits=5,lea:1", "item-{}")
          + row(42, "seed", "template", 9, 3, "utf8,printable,lits=3,lea:2,ptr:1", "{} {} {}\\n")
          + row(42, "seed", "template", 3, 1, "utf8,printable,lits=1,ref=unverifiable", ":{}")
          + row(42, "seed", "templates", 3, 9, "ref", "fmt templates referenced from code or static data: 3 of 9 candidates (lea 2, ptr 1); unreferenced dropped"))
d = os.path.join(repo, "analysis", "vsweep-05-x.elf.vol")
open(os.path.join(d, "ferric_strings.txt"), "w").write(target)
open(os.path.join(d, "ferric_strings.txt.meta"), "w").write(f"plugin_sha256={CUR}  strings.py\n")
im = images(repo)[0]
r = score_target(repo, im, CUR)
check("String truth 2/2, one extra row, 2 chunk-consistent", r["string_truth"] == "2/2" and r["string_extra"] == 1 and r["string_chunk"] == 2)
check("location truth 1/1; &str truth not applicable on 1.99", r["location_truth"] == "1/1" and r["str_truth"] == "-")
check("template truth 2/2 with the reference evidence of each truth template", r["template_truth"] == "2/2" and r["template_truth_refs"] == "lea:1;lea:2,ptr:1")
check("templates pseudo-row read: 9 candidates -> 3 kept; one kept row has a single literal byte", r["template_cand"] == 9 and r["template_kept"] == 3 and r["template_lits1"] == 1)
check("output marked as produced by the current strings.py", r["version"] == "current")
open(os.path.join(d, "ferric_strings.txt.meta"), "w").write("plugin_sha256=" + "0" * 64 + "  strings.py\n")
check("another hash in the sidecar -> older; no sidecar -> ?", produced_by_current(os.path.join(d, "ferric_strings.txt"), CUR) == "older"
      and produced_by_current(os.path.join(d, "nope.txt"), CUR) == "?")

gated = (HDR + row(42, "seed", "compiler", 0, 0, "provenance", "rustc 1.99.0 (b940084d7eb6, 45 hits): templates scanned")
         + row(42, "seed", "string", 4, 4, "utf8,printable,chunk", "mode", "cap,ptr,len")
         + row(1, "systemd", "compiler", 0, 0, "provenance", "no Rust compiler fingerprint in read-only data: not scanned (--force-scan to scan anyway)")
         + row(7, "bash", "compiler", 0, 0, "provenance", "no Rust compiler fingerprint in read-only data: not scanned (--force-scan to scan anyway)")
         + row(9, "weird", "compiler", 0, 0, "provenance", "compiler unknown (0123456789ab, 2 hits): templates scanned (compiler version unknown)")
         + row(9, "weird", "str", 2, 0, "utf8,printable", "lo", "ptr,len"))
open(os.path.join(d, "ferric_strings_allprocs.txt"), "w").write(gated)
ungated = (HDR + row(42, "seed", "compiler", 0, 0, "provenance", "rustc 1.99.0 (b940084d7eb6, 45 hits): templates scanned")
           + row(1, "systemd", "compiler", 0, 0, "provenance", "no Rust fingerprint, scanned on --force-scan: templates scanned (compiler version unknown)")
           + row(1, "systemd", "string", 1, 8, "utf8,printable", "p", "cap,ptr,len")
           + row(1, "systemd", "string", 1, 8, "utf8,printable,chunk", "q", "cap,ptr,len")
           + row(1, "systemd", "str", 1, 0, "utf8,printable", "l", "ptr,len")
           + row(1, "systemd", "template", 3, 1, "utf8,printable,lits=1,ref=none", "({:...}")
           + row(1, "systemd", "template", 5, 1, "utf8,printable,lits=3,lea:1", "abc{}")
           + row(1, "systemd", "templates", 1, 2, "ref", "fmt templates referenced from code or static data: 1 of 2 candidates (lea 1, ptr 0); unreferenced listed as ref=none")
           + row(7, "bash", "compiler", 0, 0, "provenance", "no Rust fingerprint, scanned on --force-scan: templates scanned (compiler version unknown)")
           + row(7, "bash", "string", 2, 2, "utf8,printable", "ab", "cap,ptr,len"))
open(os.path.join(d, "ferric_strings_allprocs_ungated.txt"), "w").write(ungated)
nc = negative_control(repo, images(repo))
check("negative control finds the image by prefix", len(nc) == 1 and nc[0]["image"] == "vsweep-05-x")
n = nc[0]
check("gated: 3 non-target processes, 1 scanned (fingerprint without version), 1 row beyond compiler in 1 process", n["gated_procs"] == 3 and n["gated_procs_scanned"] == 1 and n["gated_rows_beyond_compiler"] == 1 and n["gated_procs_with_rows"] == 1 and n["gated_kinds"] == {"str": 1})
check("ungated: String 3 (chunk 1), &str 1, template candidates 2, referenced 1, lits=1: 1", n["ungated_string"] == 3 and n["ungated_string_chunk"] == 1 and n["ungated_str"] == 1 and n["ungated_template_cand"] == 2 and n["ungated_template_referenced"] == 1 and n["ungated_template_lits1"] == 1)
check("ungated: referenced template in a non-Rust process is listed as gate residue", n["ungated_referenced_examples"] == [("systemd", "abc{}")])
check("ungated: top String processes counted", n["ungated_top_string_procs"][0] == ("systemd", 2))

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)
