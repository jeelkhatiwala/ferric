#!/usr/bin/env python3
"""Score ferric.maps outputs against the control seeds' known HashMaps.

Two levels, both pre-registered in eval/METRICS.md:
  TABLE  (maps >= v0.3): the known map is recovered when a 'table' row in the target process reports
         exactly its item count. Other accepted rows in the target process are listed as unattributed
         (std-internal tables or false positives; inspected by hand, counted as neither).
  ENTRY  (maps >= v0.4): every known (key, value) pair must appear as an 'entry' row of a table with the
         known item count, decoded with the right types. entry recall = pairs found / pairs known; entry
         precision = correct entry rows / entry rows of that table (an extra or mis-decoded entry counts
         against precision).
Ground truth comes from control-corpus/seeds/<seed>/TRUTH.maps.tsv (format documented there); the three
original seeds are also built in below so older checkouts still score.
NEAR rows (--explain) are diagnostics, never results. v0.3 outputs (no Kind column) are read as table rows
only, so the overnight 20261008T034522Z baseline (37/37) reproduces from this script unchanged.

Inputs : MANIFEST/images.csv; analysis/<img>.vol/ferric_maps.txt (target pid, --explain);
         analysis/<img>.vol/ferric_maps_allprocs.txt (all processes, optional negative control).
Usage  : python3 eval/make_table_maps.py [--repo .] [--tsv out.tsv]
"""
import argparse
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import image_class, parse_grid, images, find_output, read_truth  # noqa: E402

BUILTIN = {
    "seed01_collections": [["map", "cfg", "String", "String", "2"],
                           ["entry", "cfg", "mode", "control"], ["entry", "cfg", "targets", "docx,xlsx,pdf"]],
    "seed02_tokio": [["map", "settings", "String", "String", "2"],
                     ["entry", "settings", "profile", "control"], ["entry", "settings", "region", "lab-1"]],
    "seed03_graph": [["map", "areas", "String", "f64", "3"],
                     ["entry", "areas", "circle-a", "12.566370614359172"], ["entry", "areas", "rect-b", "12"],
                     ["entry", "areas", "tri-c", "6"]],
}


def load_truth(repo, fam):
    """{map_name: {"ktype", "vtype", "items", "entries": [(key, value)]}} for a seed family."""
    rows = read_truth(os.path.join(repo, "control-corpus", "seeds", fam, "TRUTH.maps.tsv"))
    if rows is None:
        rows = BUILTIN.get(fam)
    if rows is None:
        return None
    maps = {}
    for r in rows:
        if r[0] == "map":
            maps[r[1]] = {"ktype": r[2], "vtype": r[3], "items": int(r[4]), "entries": []}
        elif r[0] == "entry":
            maps[r[1]]["entries"].append((r[2], r[3] if len(r) > 3 else ""))
    return maps


_FIELD = re.compile(r'^(String|&str) "(.*)"(?:\(cap \d+\))?$|^Vec<u8>\[(\d+)\] ([0-9a-f.]*)$|^HashMap table ctrl=0x[0-9a-f]+ items=(\d+)$|^u64 (\S+)(?: \(f64 ([^)]+)\))?$|^ptr (.*)$')


def parse_fields(s):
    """'String "mode" | String "control"' -> [("String","mode"), ("String","control")] etc."""
    out = []
    for part in (s or "").split(" | "):
        m = _FIELD.match(part)
        if not m:
            out.append(("?", part))
        elif m.group(1):
            out.append((m.group(1), m.group(2)))
        elif m.group(3) is not None:
            out.append(("Vec<u8>", m.group(4)))
        elif m.group(5) is not None:
            out.append(("HashMap", m.group(5)))
        elif m.group(6) is not None:
            out.append(("u64", m.group(6), m.group(7)))
        else:
            out.append(("ptr", m.group(8)))
    return out


def value_matches(vtype, truth, field):
    if vtype == "String":
        return field[0] in ("String", "&str") and field[1] == truth
    if vtype in ("u64", "u32"):
        if field[0] != "u64":
            return False
        try:
            got = int(field[1], 0)
        except ValueError:
            return False
        if vtype == "u32":                       # a u32 shares its word with 4 padding bytes
            got &= 0xFFFFFFFF
        return got == int(truth)
    if vtype == "f64":
        if field[0] != "u64" or len(field) < 3 or field[2] is None:
            return False
        try:
            a, b = float(field[2]), float(truth)
        except ValueError:
            return False
        return abs(a - b) <= 1e-4 * max(1.0, abs(b))
    if vtype == "Vec<u8>":
        return field[0] == "Vec<u8>" and (field[1] == truth or (field[1].endswith("...") and truth.startswith(field[1][:-3])))
    if vtype == "HashMap":
        return field[0] == "HashMap" and field[1] == truth
    return False


def key_matches(ktype, truth, field):
    return value_matches(ktype, truth, field)


def score_entries(m, entry_rows):
    """(pairs_found, pairs_known, correct_rows, total_rows, misses) for one truth map vs one table's entries."""
    known = m["entries"]
    found = set()
    correct = 0
    for r in entry_rows:
        f = parse_fields(r["Fields"])
        if not f:
            continue
        hit = None
        for idx, (k, v) in enumerate(known):
            if idx in found:
                continue
            if not key_matches(m["ktype"], k, f[0]):
                continue
            if m["vtype"] == "none":
                hit = idx
            elif len(f) >= 2 and value_matches(m["vtype"], v, f[1]):
                hit = idx
            if hit is not None:
                break
        if hit is not None:
            found.add(hit)
            correct += 1
    misses = [known[i] for i in range(len(known)) if i not in found]
    return len(found), len(known), correct, len(entry_rows), misses


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = images(a.repo)
    tsv = open(a.tsv, "w") if a.tsv else None
    if tsv:
        tsv.write("image_id\trustc\tfamily\tmap\texpect_items\ttable\tpairs_found\tpairs_known\tentry_rows_correct\tentry_rows\tstride\tunattributed\n")
    t_total = t_found = noout = 0
    e_known = e_found = e_rows = e_correct = 0
    e_scored_tables = 0
    by_ver_t, by_ver_e = {}, {}
    print(f"{'image_id':66s} rustc   map        items  table    entries(found/known  correct/rows)  stride  near unattributed(items)")
    for im in imgs:
        fam, pid = im["family_or_label"], int(im["pid"] or 0)
        if image_class(im) in ("negative", "benign", "wild"):
            continue          # scored by make_table_negatives.py: any table there is a false positive / observation
        truth = load_truth(a.repo, fam) if pid else None
        if not truth:
            continue
        f = find_output(a.repo, im["image_id"], "ferric_maps.txt")
        rows = parse_grid(f) if f else None
        if rows is None:
            noout += 1
            for mn in truth:
                t_total += 1
            print(f"{im['image_id']:66s} {im['rustc_version']:7s} NO OUTPUT")
            continue
        has_kind = "Kind" in rows[0] if rows else True
        mine = [r for r in rows if r["PID"] == pid]
        tables = [r for r in mine if (r.get("Kind") == "table" if has_kind else not str(r["Note"]).startswith("NEAR"))]
        entries = [r for r in mine if has_kind and r.get("Kind") == "entry"]
        near = [r for r in mine if (r.get("Kind") == "near" if has_kind else str(r["Note"]).startswith("NEAR"))]
        expect_items = {m["items"] for m in truth.values()}
        extra = [r["Items"] for r in tables if r["Items"] not in expect_items]
        for mn, m in truth.items():
            t_total += 1
            cands = [r for r in tables if r["Items"] == m["items"]]
            # entry level: the table whose entries best match the truth (one truth map may share an item
            # count with a std-internal table; the match decides which is which)
            best = None
            for c in cands:
                ers = [r for r in entries if r["Ctrl"] == c["Ctrl"]]
                sc = score_entries(m, ers)
                if best is None or sc[0] > best[1][0]:
                    best = (c, sc, ers)
            # a table counts as recovered only when its entries match at least one truth pair (Session 77):
            # an item count alone credited seed05's 'set' (5 items) to the 'nested.west' table (5 items) on
            # the one Windows image where the set's header was not found. Maps without entry truth, and
            # outputs without entry rows, keep the item-count rule.
            hit = bool(cands) if not (has_kind and m["entries"]) else (best is not None and best[1][0] > 0)
            t_found += hit
            by_ver_t.setdefault(im["rustc_version"], [0, 0])
            by_ver_t[im["rustc_version"]][0] += hit
            by_ver_t[im["rustc_version"]][1] += 1
            if best is not None and has_kind and m["entries"]:
                c, (pf, pk, cr, tr, misses), ers = best
                e_known += pk; e_found += pf; e_rows += tr; e_correct += cr; e_scored_tables += 1
                by_ver_e.setdefault(im["rustc_version"], [0, 0])
                by_ver_e[im["rustc_version"]][0] += pf
                by_ver_e[im["rustc_version"]][1] += pk
                stride = c.get("Stride")
                etxt = f"{pf}/{pk}  {cr}/{tr}" + (f"  MISSING {misses}" if misses else "")
            else:
                stride = None
                etxt = "(no entry rows)" if has_kind else "(v0.3 output: tables only)"
                pf = pk = cr = tr = ""
            print(f"{im['image_id']:66s} {im['rustc_version']:7s} {mn:10s} {m['items']:<6d} {'FOUND' if hit else 'MISSED':8s} "
                  f"{etxt:40s} {str(stride) if stride else '-':6s}  {len(near):<4d} {extra}")
            if tsv:
                tsv.write("\t".join(str(x) for x in (im["image_id"], im["rustc_version"], fam, mn, m["items"],
                                                      "FOUND" if hit else "MISSED", pf, pk, cr, tr, stride or "", len(extra))) + "\n")
    print("\nSUMMARY")
    print(f"  known maps on control images   : {t_total}")
    print(f"  known map recovered (table)    : {t_found}")
    print(f"  no usable output               : {noout}")
    print("  table recall by rustc version  :", {v: f"{x[0]}/{x[1]}" for v, x in sorted(by_ver_t.items())})
    if e_scored_tables:
        print(f"  entry recall  (pairs)          : {e_found}/{e_known} over {e_scored_tables} tables")
        print(f"  entry precision (rows)         : {e_correct}/{e_rows}")
        print("  entry recall by rustc version  :", {v: f"{x[0]}/{x[1]}" for v, x in sorted(by_ver_e.items())})
    else:
        print("  entry level                    : not scored (no v0.4 outputs with entry rows)")
    print("  negative control (all processes; table rows outside the target pid are candidate false positives):")
    for im in imgs:
        f = find_output(a.repo, im["image_id"], "ferric_maps_allprocs.txt")
        if not f:
            continue
        rows = parse_grid(f)
        if rows is None:
            print(f"    {im['image_id']}: NO OUTPUT")
            continue
        pid = int(im["pid"] or 0)
        has_kind = "Kind" in rows[0] if rows else True
        tables = [r for r in rows if (r.get("Kind") == "table" if has_kind else not str(r["Note"]).startswith("NEAR"))]
        other = [r for r in tables if r["PID"] != pid]
        procs = Counter(r["Process"] for r in other)
        print(f"    {im['image_id']}: processes with table rows={len({r['PID'] for r in tables})} "
              f"rows outside target={len(other)} {dict(procs)}")
    if tsv:
        tsv.close()


if __name__ == "__main__":
    main()
