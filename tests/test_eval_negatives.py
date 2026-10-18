#!/usr/bin/env python3
"""Unit tests for eval/ferric_out.image_class and eval/make_table_negatives.py on a synthetic repo tree.
Pure; no volatility needed. Run: python3 tests/test_eval_negatives.py
"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
from ferric_out import image_class, images  # noqa: E402
from make_table_negatives import cell  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

mk = lambda **kw: dict({"pid": "0", "target_binary_id": "", "family_or_label": ""}, **kw)
check("baseline: pid 0", image_class(mk(pid="0", target_binary_id="x", family_or_label="seed01_collections")) == "baseline")
check("baseline: no target binary", image_class(mk(pid="5", target_binary_id="none", family_or_label="seed01_collections")) == "baseline")
check("rust seed", image_class(mk(pid="5", target_binary_id="seed01__1.99.0_o2_unwind_strip-symbols", family_or_label="seed01_collections")) == "rust")
check("negative program", image_class(mk(pid="5", target_binary_id="neg_cpp__none_o2_none_strip-symbols", family_or_label="neg_cpp")) == "negative")
check("benign Rust program", image_class(mk(pid="5", target_binary_id="neg_rust_benign__1.99.0_o3_unwind_strip-symbols", family_or_label="neg_rust_benign")) == "benign")

repo = tempfile.mkdtemp()
os.makedirs(os.path.join(repo, "MANIFEST")); d = os.path.join(repo, "analysis", "neg-01-neg_cpp__none.elf.vol"); os.makedirs(d)
open(os.path.join(repo, "MANIFEST", "images.csv"), "w").write(
    "image_id,family_or_label,rustc_version,pid,target_binary_id,image_path\n"
    "neg-01-neg_cpp__none,neg_cpp,none,77,neg_cpp__none_o2_none_strip-symbols,/nowhere/neg-01.elf\n")
im = images(repo)[0]
check("manifest row classified negative", image_class(im) == "negative")
B = "Volatility 3 Framework 2.28.2\n\n"
open(os.path.join(d, "ferric_provenance.txt"), "w").write(B + "PID\tProcess\tTier\tEvidence\tHits\tVMAs\tFileHits\tAnonHits\tFirstOffset\n\n")
n, t = cell(repo, im, "provenance")
check("provenance: header only -> 0 rows", n == 0 and t == "0 rows")
open(os.path.join(d, "ferric_provenance.txt"), "w").write(B + "PID\tProcess\tTier\tEvidence\tHits\tVMAs\tFileHits\tAnonHits\tFirstOffset\n\n"
                                                           "77\tneg_cpp\tauthor\tclaude\t1\t1\t0\t1\t0x1000\n99\tother\tcompiler\trustc x\t3\t1\t3\t0\t0x2000\n")
n, t = cell(repo, im, "provenance")
check("provenance: only the target pid's rows count (1 author row)", n == 1 and t == "1 rows author=1")
SH = "PID\tProcess\tKind\tHeader\tHeaderIn\tPtr\tPtrIn\tLen\tCap\tLayout\tChecks\tText\n\n"
open(os.path.join(d, "ferric_strings.txt"), "w").write(B + SH + "77\tneg_cpp\tcompiler\t0x0\t-\t0x0\t-\t0\t0\t-\tprovenance\tno Rust compiler fingerprint in read-only data: not scanned (--force-scan to scan anyway)\n")
n, t = cell(repo, im, "strings")
check("strings 0.4.0 on a negative: not scanned, 0 rows", n == 0 and t == "not scanned (no fingerprint); 0 rows")
open(os.path.join(d, "ferric_strings.txt"), "w").write(B + SH + "77\tneg_cpp\tcompiler\t0x0\t-\t0x0\t-\t0\t0\t-\tprovenance\tcompiler unknown: templates scanned\n"
                                                        "77\tneg_cpp\tstring\t0x10\theap\t0x20\theap\t3\t8\tcap,ptr,len\tutf8\tabc\n77\tneg_cpp\tlayout\t0x0\t-\t0x0\t-\t0\t0\tcap,ptr,len\tvote\tString layout chosen by vote: x\n"
                                                        "77\tneg_cpp\tstr\t0x30\trodata\t0x40\trodata\t2\t0\tptr,len\tutf8\tlo\n")
n, t = cell(repo, im, "strings")
check("strings 0.3.2-style output: rows beyond compiler/layout counted by kind", n == 2 and t == "compiler unknown: templates scanned; 2 rows str=1 string=1")
open(os.path.join(d, "ferric_maps.txt"), "w").write(B + "PID\tProcess\tKind\tHeader\tItems\tStride\tFields\tNote\n\n77\tneg_cpp\ttable\t0x1\t2\t48\t\tstride=48:chunk\n77\tneg_cpp\tentry\t0x2\t2\t48\tString \"a\"\t\n77\tneg_cpp\tnear\t0x3\t2\t-\t\tNEAR\n")
n, t = cell(repo, im, "maps")
check("maps: 1 table, 1 entry (near rows not counted)", n == 1 and t == "1 tables, 1 entries")
open(os.path.join(d, "ferric_vtables.txt"), "w").write(B + "PID\tProcess\tVTable\tVTableIn\tSize\tAlign\tMethods\n\n77\tneg_cpp\t0x5\trodata\t32\t8\t2\n77\tneg_cpp\t0x6\tdata\t40\t8\t2\n")
n, t = cell(repo, im, "vtables")
check("vtables: 2 rows with their regions", n == 2 and t == "2 rows in data=1/rodata=1")
n, t = cell(repo, im, "tokio")
check("tokio: no output -> None", n is None and t == "no output")
open(os.path.join(d, "ferric_tokio.txt"), "w").write(B + "PID\tProcess\tKind\tAddr\n\n")
n, t = cell(repo, im, "tokio")
check("tokio: header only -> 0 rows", n == 0 and t == "0 rows")

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)
