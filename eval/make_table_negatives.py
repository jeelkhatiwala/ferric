#!/usr/bin/env python3
"""Negative-control programs and the benign Rust control, scored per plugin from the saved outputs.

Images whose family is neg_cpp / neg_go / neg_dotnet (image_class 'negative') hold a non-Rust program at
t1; every row a ferric plugin reports in that process is a false positive by construction
(control-corpus/negatives/README.md, predictions in each program's README). The family neg_rust_benign
('benign') holds a benign Rust binary from the distribution: provenance, strings and vtables rows are
expected there and maps / tokio rows are observations, so nothing on it counts as recall or as a false
positive; it shows the plugins find Rust structures in benign Rust too.

Per image and plugin (only outputs that exist are read):
  provenance  rows in the target pid by tier (prediction on a negative: 0)
  strings     the 'compiler' row's verdict and the rows beyond it by kind (0.4.0 prediction on a negative:
              "no Rust compiler fingerprint ... not scanned" and 0 rows)
  maps        table rows and entry rows (prediction 0; Go >= 1.24 is flagged as the case to look at)
  vtables     rows and where they live (prediction 0)
  tokio       rows by kind (prediction 0)
Usage: python3 eval/make_table_negatives.py [--repo .] [--tsv out.tsv]
"""
import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import parse_grid, images, find_output, image_class  # noqa: E402

PLUGINS = ("provenance", "strings", "maps", "vtables", "tokio")


def cell(repo, im, plugin):
    """(n_rows_counted_against_the_prediction, text) or (None, 'no output')."""
    f = find_output(repo, im["image_id"], f"ferric_{plugin}.txt")
    rows = parse_grid(f) if f else None
    if rows is None:
        return None, "no output"
    pid = int(im["pid"] or 0)
    mine = [r for r in rows if r["PID"] == pid]
    if plugin == "provenance":
        tiers = Counter(str(r["Tier"]) for r in mine)
        return len(mine), (f"{len(mine)} rows " + " ".join(f"{t}={n}" for t, n in sorted(tiers.items()))) if mine else "0 rows"
    if plugin == "strings":
        comp = next((str(r["Text"]) for r in mine if r["Kind"] == "compiler"), None)
        beyond = [r for r in mine if r["Kind"] not in ("compiler", "layout", "templates")]
        kinds = Counter(str(r["Kind"]) for r in beyond)
        if comp is None:
            verdict = "no compiler row"
        elif "not scanned" in comp:
            verdict = "not scanned (no fingerprint)"
        elif comp.startswith("rustc"):
            verdict = comp.split(":")[0]
        else:
            verdict = comp[:40]
        return len(beyond), f"{verdict}; {len(beyond)} rows" + (" " + " ".join(f"{k}={n}" for k, n in sorted(kinds.items())) if beyond else "")
    if plugin == "maps":
        has_kind = bool(mine) and "Kind" in mine[0]
        tables = [r for r in mine if (r.get("Kind") == "table" if has_kind else not str(r.get("Note") or "").startswith("NEAR"))]
        entries = [r for r in mine if has_kind and r.get("Kind") == "entry"]
        return len(tables), f"{len(tables)} tables, {len(entries)} entries"
    if plugin == "vtables":
        where = Counter(str(r.get("VTableIn")) for r in mine)
        return len(mine), f"{len(mine)} rows" + (" in " + "/".join(f"{k}={n}" for k, n in sorted(where.items())) if mine else "")
    if plugin == "tokio":
        kinds = Counter(str(r["Kind"]) for r in mine)
        return len(mine), f"{len(mine)} rows" + (" " + " ".join(f"{k}={n}" for k, n in sorted(kinds.items())) if mine else "")
    return None, "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = [im for im in images(a.repo) if image_class(im) in ("negative", "benign")]
    tsv = open(a.tsv, "w") if a.tsv else None
    if tsv:
        tsv.write("image_id\tclass\tfamily\t" + "\t".join(PLUGINS) + "\n")
    print(f"{'image_id':52s} {'class':9s} {'provenance':28s} {'strings':44s} {'maps':22s} {'vtables':26s} tokio")
    fp = Counter()
    clean = Counter()
    scored = Counter()
    noout = Counter()
    for im in imgs:
        cls = image_class(im)
        cells = {p: cell(a.repo, im, p) for p in PLUGINS}
        print(f"{im['image_id'][:52]:52s} {cls:9s} {cells['provenance'][1]:28s} {cells['strings'][1][:44]:44s} "
              f"{cells['maps'][1]:22s} {cells['vtables'][1][:26]:26s} {cells['tokio'][1]}")
        if tsv:
            tsv.write("\t".join([im["image_id"], cls, im["family_or_label"]] + [cells[p][1] for p in PLUGINS]) + "\n")
        for p in PLUGINS:
            n, _ = cells[p]
            if n is None:
                noout[p] += 1
                continue
            if cls == "negative":
                scored[p] += 1
                fp[p] += n
                clean[p] += (n == 0)
    if tsv:
        tsv.close()
    neg = [im for im in imgs if image_class(im) == "negative"]
    ben = [im for im in imgs if image_class(im) == "benign"]
    print("\nSUMMARY")
    print(f"  negative-control program images : {len(neg)}  (" + ", ".join(sorted(Counter(im['family_or_label'] for im in neg))) + ")" if neg else "  negative-control program images : 0 (none captured yet)")
    print(f"  benign Rust control images      : {len(ben)}")
    for p in PLUGINS:
        if scored[p] or noout[p]:
            print(f"  {p:11s} clean on {clean[p]}/{scored[p]} negative images, false-positive rows {fp[p]}" + (f", no output on {noout[p]}" if noout[p] else ""))
    if not neg and not ben:
        print("  nothing to score: no image with family neg_* in MANIFEST/images.csv")


if __name__ == "__main__":
    main()
