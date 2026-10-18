#!/usr/bin/env python3
"""Survival matrix: what each plugin still recovers under every build configuration, capture method and
countermeasure in the control corpus. Every cell is read from the saved plugin outputs; nothing is typed.

Rows are conditions (one control image each); columns are the five plugins:
  provenance  compiler hits in the target process, and whether the recovered version equals the manifest's
  strings     known String objects found / known (TRUTH.strings.tsv of the seed), + location, + template or str
  maps        the known map: table found, (key,value) pairs decoded / known, stride source
  vtables     rows reported; known trait objects matched by shape (and by symbols when the scorer ran)
  tokio       seed02 only: parked worker tasks with both locals / 4
The condition label comes from the image: version sweep, remap, opt level, panic=abort, memory pressure,
UPX, musl, AVML vs hypervisor capture, strip=none (the ad hoc Phase 2 builds).
Usage: python3 eval/make_table_survival.py [--repo .] [--tsv out.tsv]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import parse_grid, images, find_output, read_truth  # noqa: E402
from make_table_maps import load_truth as maps_truth, score_entries  # noqa: E402

EXPECT_VTABLES = {   # family -> [(label, size, align, methods)]  (same shapes as make_table_vtables.EXPECT)
    "seed01_collections": [("<usize as Display>", 8, 8, 1)],
    "seed03_graph": [("<Circle as Shape>", 32, 8, 2), ("<Rect as Shape>", 40, 8, 2), ("<Triangle as Shape>", 40, 8, 2)],
}
SEED01_STRINGS = [("string", s) for s in ("mode", "control", "targets", "docx,xlsx,pdf")] + [("string", f"item-{i}") for i in range(8)]
SEED01_LOCATION = ("src/main.rs", "12")

CONDITIONS = [   # (image_id prefix or exact id, label)
    ("vsweep-05", "baseline: 1.99 o2 unwind strip=symbols, virsh dump"),
    ("vsweep-01", "rustc 1.71 (GNU ld, legacy mangling)"),
    ("vsweep-02", "rustc 1.77"),
    ("vsweep-03", "rustc 1.83"),
    ("vsweep-04", "rustc 1.89"),
    ("lin-img03-t1", "strip=none (ad hoc build), virsh dump"),
    ("lin-img02-avml", "strip=none, AVML in-guest capture (same PID as lin-img03-t1)"),
    ("rsweep-05", "--remap-path-prefix (home + sysroot)"),
    ("cfgsweep-01", "opt-level 0"),
    ("cfgsweep-02", "opt-level 3"),
    ("cfgsweep-03", "opt-level s"),
    ("cfgsweep-04", "opt-level z"),
    ("cfgsweep-05", "panic = abort"),
    ("pressure-01", "memory pressure, 552 MB available"),
    ("pressure-02", "memory pressure, 101 MB available (near OOM)"),
    ("upx-01", "UPX -9 packed"),
    ("musl-01", "musl static-pie (x86_64-unknown-linux-musl)"),
    ("s3sweep-05", "seed03 (trait objects), 1.99"),
    ("s3fix-01", "seed03, 1.71"),
    ("s2sweep-05", "seed02 (tokio 1.53.2), 1.99"),
    ("s2sweep-01", "seed02, 1.71"),
]


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def strings_truth(repo, fam):
    rows = read_truth(os.path.join(repo, "control-corpus", "seeds", fam, "TRUTH.strings.tsv"))
    if rows is None:
        if fam != "seed01_collections":
            return None
        return ([(k, s, "-") for k, s in SEED01_STRINGS] + [("location",) + SEED01_LOCATION + ("-",)]
                + [("template", t, "rustc>=1.93") for t in ("t1 reached (pid {}); holding for capture\\n", "{} {} {}\\n", "item-{}")])
    out = []
    for r in rows:
        k, text = r[0], r[1]
        applies = r[5] if len(r) > 5 else "-"
        if k == "location":
            out.append((k, text, r[4] if len(r) > 4 else "?", applies))
        else:
            out.append((k, text, applies))
    return out


def applies(rule, ver):
    if rule in ("-", "", None) or not ver:
        return True
    try:
        v = tuple(int(x) for x in ver.split(".")[:2])
        op, num = rule[5:7], rule[7:]
        bound = tuple(int(x) for x in num.split(".")[:2])
    except Exception:
        return True
    return v <= bound if op == "<=" else v >= bound


def cell_provenance(repo, im):
    f = find_output(repo, im["image_id"], "ferric_provenance.txt")
    rows = parse_grid(f) if f else None
    if rows is None:
        return "no output"
    pid = int(im["pid"] or 0)
    comp = [r for r in rows if r["PID"] == pid and r["Tier"] == "compiler"]
    if not comp:
        return "0 hits"
    best = max(comp, key=lambda r: r["Hits"])
    ver = str(best["Evidence"]).split("=")[-1].strip()
    return f"{best['Hits']} hits, {ver}" + ("" if ver == im["rustc_version"] else f" (manifest {im['rustc_version']})")


def cell_strings(repo, im):
    f = find_output(repo, im["image_id"], "ferric_strings.txt")
    rows = parse_grid(f) if f else None
    truth = strings_truth(repo, im["family_or_label"])
    if rows is None or truth is None:
        return "no output" if rows is None else "no truth"
    pid = int(im["pid"] or 0)
    mine = [r for r in rows if r["PID"] == pid]
    texts = {}
    for r in mine:
        texts.setdefault(r["Kind"], set()).add(str(r["Text"]))
    found = {}
    total = {}
    for t in truth:
        k = t[0]
        rule = t[-1]
        if not applies(rule, im["rustc_version"]):
            continue
        total[k] = total.get(k, 0) + 1
        if k == "location":
            hit = any(str(r["Text"]).startswith(t[1] + ":" + t[2] + ":") for r in mine if r["Kind"] == "location")
        else:
            hit = t[1] in texts.get(k, set())
        found[k] = found.get(k, 0) + hit
    return "  ".join(f"{k} {found[k]}/{total[k]}" for k in ("string", "location", "template", "str") if k in total)


def cell_maps(repo, im):
    f = find_output(repo, im["image_id"], "ferric_maps.txt")
    rows = parse_grid(f) if f else None
    truth = maps_truth(repo, im["family_or_label"])
    if rows is None or not truth:
        return "no output" if rows is None else "no truth"
    pid = int(im["pid"] or 0)
    mine = [r for r in rows if r["PID"] == pid]
    has_kind = "Kind" in mine[0] if mine else True
    tables = [r for r in mine if (r.get("Kind") == "table" if has_kind else not str(r["Note"]).startswith("NEAR"))]
    entries = [r for r in mine if has_kind and r.get("Kind") == "entry"]
    out = []
    for mn, m in truth.items():
        cands = [r for r in tables if r["Items"] == m["items"]]
        if not cands:
            out.append(f"{mn}: table MISSED")
            continue
        best = None
        for c in cands:
            sc = score_entries(m, [r for r in entries if r["Ctrl"] == c["Ctrl"]])
            if best is None or sc[0] > best[1][0]:
                best = (c, sc)
        c, (pf, pk, cr, tr, _miss) = best
        how = str(c.get("Note") or "").split("stride=")[-1].split()[0] if "stride=" in str(c.get("Note") or "") else "?"
        out.append(f"{mn}: table ok, pairs {pf}/{pk}, stride {how}")
    return "; ".join(out)


def cell_vtables(repo, im):
    f = find_output(repo, im["image_id"], "ferric_vtables.txt")
    rows = parse_grid(f) if f else None
    if rows is None:
        return "no output"
    pid = int(im["pid"] or 0)
    mine = [r for r in rows if r["PID"] == pid]
    exp = EXPECT_VTABLES.get(im["family_or_label"], [])
    hits = sum(1 for _l, size, align, nm in exp if any(r["Size"] == size and r["Align"] == align and r["Methods"] == nm for r in mine))
    where = {r["VTableIn"] for r in mine}
    return f"{len(mine)} rows" + (f", known {hits}/{len(exp)} by shape" if exp else "") + (f", in {'/'.join(sorted(where))}" if where else "")


def cell_tokio(repo, im):
    if im["family_or_label"] != "seed02_tokio":
        return "n/a"
    f = find_output(repo, im["image_id"], "ferric_tokio.txt")
    rows = parse_grid(f) if f else None
    if rows is None:
        return "no output"
    pid = int(im["pid"] or 0)
    tasks = [r for r in rows if r["PID"] == pid and r["Kind"] == "task"]
    parked = [r for r in tasks if "join-interest" in str(r["Flags"]) and "complete" not in str(r["Flags"])]
    workers = sum(1 for r in parked if "worker-" in str(r["Locals"]) and "seed02-scheduler" in str(r["Locals"]))
    return f"{len(tasks)} tasks, {workers}/4 workers with locals"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = images(a.repo)
    tsv = open(a.tsv, "w") if a.tsv else None
    if tsv:
        tsv.write("condition\timage_id\tprovenance\tstrings\tmaps\tvtables\ttokio\n")
    print(f"{'condition':58s} {'provenance':24s} {'strings':52s} {'maps':44s} {'vtables':40s} tokio")
    for prefix, label in CONDITIONS:
        im = next((i for i in imgs if i["image_id"] == prefix or i["image_id"].startswith(prefix + "-")), None)
        if im is None:
            print(f"{label:58s} (image {prefix} not in manifest)")
            continue
        cells = (cell_provenance(a.repo, im), cell_strings(a.repo, im), cell_maps(a.repo, im), cell_vtables(a.repo, im), cell_tokio(a.repo, im))
        print(f"{label:58s} {cells[0]:24s} {cells[1]:52s} {cells[2]:44s} {cells[3]:40s} {cells[4]}")
        if tsv:
            tsv.write("\t".join([label, im["image_id"], *cells]) + "\n")
    if tsv:
        tsv.close()


if __name__ == "__main__":
    main()
