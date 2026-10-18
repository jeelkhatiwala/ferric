#!/usr/bin/env python3
"""Unit tests for the eval scorers' parsers (eval/ferric_out.py, eval/make_table_maps.py,
eval/make_table_vtables.py). Pure; no volatility needed. Run: python3 tests/test_eval_parsers.py
"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
from ferric_out import parse_grid  # noqa: E402
from make_table_maps import parse_fields, value_matches, score_entries  # noqa: E402
from make_table_vtables import identifiers  # noqa: E402

fails = 0
def check(n, c):
    global fails
    print(("ok   " if c else "FAIL ") + n)
    if not c: fails += 1

# quick-renderer text: banner, blank, header, blank, rows; '-' is an absent cell
txt = ("Volatility 3 Framework 2.28.2\n\nPID\tProcess\tKind\tHeader\tItems\tStride\tFields\tNote\n\n"
       "12\tseed\ttable\t0x5588aa\t2\t48\t\tcap=3 gl stride=48:chunk\n"
       "12\tseed\tentry\t0x5588bb\t2\t48\tString \"mode\" | String \"control\"\tlayout=cap,ptr,len\n"
       "12\tseed\tnear\t0x5588cc\t2\t-\t\tNEAR items!=full\n"
       "garbage line without tabs\n")
d = tempfile.mkdtemp(); p = os.path.join(d, "ferric_maps.txt"); open(p, "w").write(txt)
rows = parse_grid(p)
check("parse_grid: three rows, keyed by header", len(rows) == 3 and rows[0]["Kind"] == "table" and rows[1]["Fields"].startswith("String"))
check("parse_grid: ints and hex converted, '-' is None", rows[0]["Items"] == 2 and rows[0]["Header"] == 0x5588aa and rows[2]["Stride"] is None)
check("parse_grid: missing file -> None", parse_grid(os.path.join(d, "nope.txt")) is None)
open(p, "w").write("Volatility 3 Framework 2.28.2\n\nTraceback (most recent call last):\n")
check("parse_grid: crashed run (no header) -> None", parse_grid(p) is None)

f = parse_fields('String "mode" | String "control"')
check("parse_fields: two Strings", f == [("String", "mode"), ("String", "control")])
f = parse_fields('String "circle-a" | u64 0x402921fb54442d18 (f64 12.5664)')
check("parse_fields: f64 rendering captured", f[1][0] == "u64" and f[1][2] == "12.5664")
check("value_matches f64 within 6 significant digits", value_matches("f64", "12.566370614359172", f[1]) and not value_matches("f64", "12.6", f[1]))
f = parse_fields('u64 1007 | String "host-1"(cap 8)')
check("parse_fields: u64 key and a String with spare capacity", f == [("u64", "1007", None), ("String", "host-1")])
check("value_matches u64", value_matches("u64", "1007", f[0]) and not value_matches("u64", "1008", f[0]))
f = parse_fields('String "east-1" | u64 0xdeadbeef0000000a')
check("value_matches u32 ignores the padding half of the word", value_matches("u32", "10", f[1]))
f = parse_fields('String "iv" | Vec<u8>[12] 0102030405060708090a0b0c')
check("value_matches Vec<u8> hex", value_matches("Vec<u8>", bytes(range(1, 13)).hex(), f[1]))
f = parse_fields('String "east" | HashMap table ctrl=0x5f00 items=3')
check("value_matches HashMap by inner item count", value_matches("HashMap", "3", f[1]))

m = {"ktype": "String", "vtype": "String", "items": 2, "entries": [("mode", "control"), ("targets", "docx,xlsx,pdf")]}
ers = [{"Fields": 'String "mode" | String "control"'}, {"Fields": 'String "targets" | String "docx,xlsx,pdf"'},
       {"Fields": 'String "stale" | String "x"'}]
check("score_entries: 2/2 pairs, 2 correct of 3 rows, no misses", score_entries(m, ers) == (2, 2, 2, 3, []))
check("score_entries: a missing pair is reported", score_entries(m, ers[:1])[4] == [("targets", "docx,xlsx,pdf")])

v0 = "_RNvXCs7JeivII29ZR_12seed03_graphNtB2_6CircleNtB2_5Shape4area"
leg = "_ZN58_$LT$seed03_graph..Circle$u20$as$u20$seed03_graph..Shape$GT$4name17h0123456789abcdefE"
check("identifiers: v0 mangling", {"Circle", "Shape", "area"} <= identifiers(v0))
check("identifiers: legacy mangling", {"Circle", "Shape", "name"} <= identifiers(leg))

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
