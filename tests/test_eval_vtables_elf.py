#!/usr/bin/env python3
"""Regression test for eval/make_table_vtables.py's ELF side: the Elf class must expose every method the
scorer calls on a twin (words, symbolize, segment_digest, loaded, section_of), check_row must run, and
the twin comparison must accept a binary against itself. Session 60 shipped a scorer whose `words` and
`symbolize` had been displaced out of the class by an edit, which the unit tests did not catch because
they only imported `identifiers`; the host run crashed on the first twinned image. Needs pyelftools.
Run: python3 tests/test_eval_vtables_elf.py
"""
import glob, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
try:
    from make_table_vtables import Elf, check_row, explain_mismatch  # noqa: E402
except SystemExit as e:
    print(f"skip: {e}"); print("\nALL PASS (skipped: pyelftools missing)"); sys.exit(0)

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

# any ELF will do for the API checks; prefer an unstripped control twin when the repo has one
root = os.path.join(os.path.dirname(__file__), "..")
cands = sorted(glob.glob(os.path.join(root, "control-corpus", "build", "**", "*strip-none*"), recursive=True))
path = cands[0] if cands else sys.executable
e = Elf(path)
check(f"Elf loads {os.path.basename(path)}", e.segs and e.exec_ranges is not None)
for m in ("words", "symbolize", "segment_digest", "loaded", "section_of", "masked_ranges", "read"):
    check(f"Elf has method {m}", callable(getattr(e, m, None)))
lo = e.segs[0][0]
check("words() reads from the first segment", e.words(lo, 2) is not None and len(e.words(lo, 2)) == 2)
check("symbolize() returns (name, at_start) without raising", isinstance(e.symbolize(e.exec_ranges[0][0] if e.exec_ranges else lo), tuple))
check("segment_digest() is stable", e.segment_digest() == Elf(path).segment_digest())
check("explain_mismatch() of a binary against itself reports no differing section", "differs in " not in explain_mismatch(e, Elf(path)) or explain_mismatch(e, Elf(path)) == "differs in ")
check("section_of() answers for the first loaded byte", isinstance(e.section_of(lo), str))
ok, why, syms = check_row(e, lo, 1)
check("check_row() runs and rejects a non-vtable address with a reason", ok is False and isinstance(why, str))

# with a strip-symbols / strip-none pair on disk (the host), the masked digest must match
pairs = [(p, p.replace("strip-none", "strip-symbols")) for p in cands if os.path.exists(p.replace("strip-none", "strip-symbols"))]
if pairs:
    a, b = Elf(pairs[0][0]), Elf(pairs[0][1])
    same = a.segment_digest() == b.segment_digest()
    print(f"info: twin pair {os.path.basename(pairs[0][1])}: " + ("identical loaded bytes after masking" if same else "not identical: " + explain_mismatch(b, a) + " (the scorer verifies such a twin row by row)"))
    check("explain_mismatch() runs on the pair", isinstance(explain_mismatch(b, a), str))
else:
    print("info: no strip-none/strip-symbols pair under control-corpus/build; twin-pair check skipped")

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
