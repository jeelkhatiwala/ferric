#!/usr/bin/env python3
"""Guard against the column-name crash (Session 57): a TreeGrid column whose name Volatility lowercases to
a Python keyword (e.g. "In" -> "in") blows up namedtuple construction inside TreeGrid.__init__, before any
row is produced. This builds the grid exactly as run() does, with an empty generator, for every ferric
plugin that exposes a COLUMNS constant. Run: python3 tests/test_columns.py (needs volatility3 2.28.2)."""
import keyword, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from volatility3.framework import renderers  # noqa: E402
from volatility3.framework.renderers import TreeGrid  # noqa: E402
from ferric import vtables, tokio  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

for mod in (vtables, tokio):
    cols = mod.COLUMNS
    sanitized = [TreeGrid.sanitize_name(name) for name, _t in cols]
    bad = [s for s in sanitized if keyword.iskeyword(s)]
    check(f"{mod.__name__}: no column sanitizes to a Python keyword ({sanitized})", not bad)
    try:
        TreeGrid(cols, iter([]))          # the exact call that crashed on the host
        ok = True
    except Exception as e:
        ok = False
        print("   ", repr(e))
    check(f"{mod.__name__}: TreeGrid builds from COLUMNS", ok)

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
