#!/usr/bin/env python3
"""ferric.strings result table, from the saved plugin outputs only (nothing typed in).

Per control image with a Rust target process (analysis/<img>.vol/ferric_strings.txt, target pid):
  rows by kind; String truth recall and the String rows outside the truth ("extra": unverified, not called
  false, because seed02's runtime owns Strings the truth does not list); location and &str truth recall;
  fmt-template candidates -> kept (the 'templates' pseudo-row of strings >= 0.4.0: Len = kept, Cap =
  candidates) and the truth templates' reference evidence (lea / ptr / ref=unverifiable).
Negative control (ferric_strings_allprocs.txt, every process on the five all-process images):
  gated (default 0.4.0 run): processes with any row beyond the 'compiler' row, outside the target pid
    (prediction: 0; a non-Rust process carries no /rustc/<commit>/ fingerprint).
  ungated (ferric_strings_allprocs_ungated.txt, --force-scan --all-candidates): what the header heuristics
    alone report in non-Rust processes: String rows and their chunk-consistent share, &str rows, location
    rows, template candidates and how many of them anything in the process refers to (the residual
    false-positive rate of the reference gate; prediction: 0).
Usage: python3 eval/make_table_strings.py [--repo .] [--tsv out.tsv]
"""
import argparse
import hashlib
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import parse_grid, images, find_output, image_class  # noqa: E402
from make_table_survival import strings_truth, applies  # noqa: E402

ALLPROC = ("lin-img00-t0", "vsweep-01", "vsweep-05", "s2sweep-05", "musl-01")


def lits(r):
    m = re.search(r"lits=(\d+)", str(r.get("Checks") or ""))
    return int(m.group(1)) if m else None


def refs_of(r):
    c = str(r.get("Checks") or "")
    return [x for x in c.split(",") if x.startswith(("lea:", "ptr:", "ref="))]


def plugin_hash(repo):
    try:
        return hashlib.sha256(open(os.path.join(repo, "plugins", "ferric", "strings.py"), "rb").read()).hexdigest()
    except OSError:
        return None


def produced_by_current(path, current):
    """'current' when the output's .meta sidecar names the strings.py now in the repo, 'older' when it names
    another hash, '?' when there is no sidecar or no hash in it."""
    try:
        for l in open(path + ".meta", encoding="utf-8", errors="replace"):
            if l.startswith("plugin_sha256="):
                h = l.split("=", 1)[1].split()[0]
                return "current" if h == current else ("older" if re.fullmatch(r"[0-9a-f]{64}", h) else "?")
    except OSError:
        pass
    return "?"


def score_target(repo, im, current=None):
    """One image: dict of cells, or None when there is no usable output."""
    f = find_output(repo, im["image_id"], "ferric_strings.txt")
    rows = parse_grid(f) if f else None
    if rows is None:
        return None
    pid = int(im["pid"] or 0)
    mine = [r for r in rows if r["PID"] == pid]
    ver = im["rustc_version"]
    kinds = Counter(r["Kind"] for r in mine)
    comp = next((str(r["Text"]) for r in mine if r["Kind"] == "compiler"), "")
    truth = strings_truth(repo, im["family_or_label"]) or []
    texts = {}
    for r in mine:
        texts.setdefault(r["Kind"], []).append(str(r["Text"]))
    found, total = Counter(), Counter()
    truth_strings = set()
    truth_tmpl_refs = []
    for t in truth:
        k, rule = t[0], t[-1]
        if not applies(rule, ver):
            continue
        total[k] += 1
        if k == "location":
            # Windows writes src\main.rs (escaped src\\main.rs in the output), possibly absolute: compare on
            # forward slashes, the truth path as the whole path or its tail, line taken from the end (Session 77)
            def _loc_hit(s, want=t[1], line=t[2]):
                parts = s.replace("\\\\", "/").replace("\\", "/").rsplit(":", 2)
                return len(parts) == 3 and parts[1] == line and (parts[0] == want or parts[0].endswith("/" + want))
            hit = any(_loc_hit(s) for s in texts.get("location", []))
        else:
            hit = t[1] in texts.get(k, [])
            if k == "string":
                truth_strings.add(t[1])
            if k == "template" and hit:
                rr = [refs_of(r) for r in mine if r["Kind"] == "template" and str(r["Text"]) == t[1]]
                truth_tmpl_refs.append(",".join(rr[0]) if rr and rr[0] else "none")
        found[k] += hit
    strings = [r for r in mine if r["Kind"] == "string"]
    extra = [r for r in strings if str(r["Text"]) not in truth_strings]
    chunk = sum(1 for r in strings if "chunk" in str(r["Checks"]))
    pseudo = next((r for r in mine if r["Kind"] == "templates"), None)
    cand = pseudo["Cap"] if pseudo else None
    kept = pseudo["Len"] if pseudo else None
    tm = [r for r in mine if r["Kind"] == "template"]
    return dict(
        image=im["image_id"], rustc=ver, family=im["family_or_label"], version=produced_by_current(f, current),
        string_rows=len(strings), string_truth=f"{found['string']}/{total['string']}" if total["string"] else "-",
        string_extra=len(extra), string_chunk=chunk,
        location_rows=kinds["location"], location_truth=f"{found['location']}/{total['location']}" if total["location"] else "-",
        str_rows=kinds["str"], str_truth=f"{found['str']}/{total['str']}" if total["str"] else "-",
        template_rows=len(tm), template_cand=cand, template_kept=kept,
        template_truth=f"{found['template']}/{total['template']}" if total["template"] else "-",
        template_truth_refs=";".join(truth_tmpl_refs) if truth_tmpl_refs else "-",
        template_lits1=sum(1 for r in tm if lits(r) == 1),
        compiler=comp[:60],
    )


def negative_control(repo, imgs):
    out = []
    for want in ALLPROC:
        im = next((i for i in imgs if i["image_id"] == want or i["image_id"].startswith(want + "-")), None)
        if im is None:
            continue
        pid = int(im["pid"] or 0)
        rec = dict(image=im["image_id"], target=pid)
        g = find_output(repo, im["image_id"], "ferric_strings_allprocs.txt")
        rows = parse_grid(g) if g else None
        if rows is not None:
            other = [r for r in rows if r["PID"] != pid]
            procs = {r["PID"] for r in other}
            beyond = [r for r in other if r["Kind"] != "compiler"]
            scanned = sum(1 for r in other if r["Kind"] == "compiler" and "not scanned" not in str(r["Text"]))
            rec.update(gated_procs=len(procs), gated_rows_beyond_compiler=len(beyond),
                       gated_procs_with_rows=len({r["PID"] for r in beyond}), gated_procs_scanned=scanned,
                       gated_kinds=dict(Counter(r["Kind"] for r in beyond)))
        u = find_output(repo, im["image_id"], "ferric_strings_allprocs_ungated.txt")
        rows = parse_grid(u) if u else None
        if rows is not None:
            other = [r for r in rows if r["PID"] != pid]
            st = [r for r in other if r["Kind"] == "string"]
            tm = [r for r in other if r["Kind"] == "template"]
            referenced = [r for r in tm if any(x.startswith(("lea:", "ptr:")) for x in refs_of(r))]
            unverifiable = [r for r in tm if "ref=unverifiable" in refs_of(r)]
            rec.update(ungated_procs=len({r["PID"] for r in other}), ungated_string=len(st),
                       ungated_string_chunk=sum(1 for r in st if "chunk" in str(r["Checks"])),
                       ungated_str=sum(1 for r in other if r["Kind"] == "str"),
                       ungated_location=sum(1 for r in other if r["Kind"] == "location"),
                       ungated_template_cand=len(tm), ungated_template_referenced=len(referenced),
                       ungated_template_unverifiable=len(unverifiable),
                       ungated_template_lits1=sum(1 for r in tm if lits(r) == 1),
                       ungated_top_string_procs=Counter(str(r["Process"]) for r in st).most_common(3),
                       ungated_referenced_examples=[(str(r["Process"]), str(r["Text"])[:40]) for r in referenced[:5]])
        out.append(rec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = images(a.repo)
    current = plugin_hash(a.repo)
    recs = []
    for im in imgs:
        if image_class(im) != "rust":
            continue          # baseline, negative and benign images are scored elsewhere (make_table_negatives.py)
        r = score_target(a.repo, im, current)
        if r is None:
            print(f"{im['image_id']:66s} no usable ferric_strings.txt")
            continue
        recs.append(r)
    cols = ["image", "rustc", "version", "string_rows", "string_truth", "string_extra", "string_chunk", "location_rows", "location_truth",
            "str_rows", "str_truth", "template_rows", "template_cand", "template_kept", "template_truth", "template_truth_refs", "template_lits1"]
    print(f"{'image':66s} {'rustc':7s} {'plugin':7s} {'String':16s} {'extra':5s} {'chunk':5s} {'Location':13s} {'&str':12s} {'templates cand->kept (truth; refs)':50s}")
    for r in recs:
        tm = (f"{r['template_cand']}->{r['template_kept']}" if r["template_cand"] is not None else f"{r['template_rows']} (ungated)") + f" ({r['template_truth']}; {r['template_truth_refs'][:28]})"
        print(f"{r['image'][:66]:66s} {r['rustc']:7s} {r['version']:7s} {str(r['string_rows']) + ' rows ' + r['string_truth']:16s} "
              f"{r['string_extra']:<5d} {r['string_chunk']:<5d} {str(r['location_rows']) + ' rows ' + r['location_truth']:13s} "
              f"{str(r['str_rows']) + ' rows ' + r['str_truth']:12s} {tm:50s}")
    if a.tsv:
        with open(a.tsv, "w") as f:
            f.write("\t".join(cols) + "\n")
            for r in recs:
                f.write("\t".join(str(r[c]) for c in cols) + "\n")

    def frac(key):
        n = d = 0
        for r in recs:
            if r[key] != "-":
                x, y = r[key].split("/"); n += int(x); d += int(y)
        return f"{n}/{d}"
    print("\nSUMMARY")
    print(f"  images with a target and a usable output : {len(recs)}")
    print(f"  String truth recall                      : {frac('string_truth')} over {sum(1 for r in recs if r['string_truth'] != '-')} images")
    print(f"  String rows outside the truth (extra)    : {sum(r['string_extra'] for r in recs)} over all images (unverified, not called false)")
    print(f"    by family: " + ", ".join(f"{fam}={sum(r['string_extra'] for r in recs if r['family'] == fam)}" for fam in sorted({r['family'] for r in recs})))
    print(f"  Location truth recall                    : {frac('location_truth')}")
    print(f"  &str truth recall (rustc <= 1.92 images) : {frac('str_truth')}")
    print(f"  template truth recall (rustc >= 1.93)    : {frac('template_truth')}")
    v4 = [r for r in recs if r["template_cand"] is not None]
    if v4:
        print(f"  template candidates -> kept (0.4.0 gate) : {sum(r['template_cand'] for r in v4)} -> {sum(r['template_kept'] for r in v4)} over {len(v4)} images; "
              f"kept rows with one literal byte: {sum(r['template_lits1'] for r in v4)}")
        unv = [r for r in v4 if "unverifiable" in r["template_truth_refs"]]
        print(f"  truth templates with ref=unverifiable    : {len(unv)} images" + (f" ({', '.join(r['image'][:20] for r in unv)})" if unv else ""))
        noref = [r for r in v4 if "none" in r["template_truth_refs"].split(";")]
        print(f"  truth templates kept without a reference : {len(noref)} images (would mean the gate dropped a true template)")
    old = [r for r in recs if r["template_cand"] is None and r["template_rows"]]
    if old:
        print(f"  images whose output predates the 0.4.0 gate: {len(old)} (template rows ungated there: {sum(r['template_rows'] for r in old)}, "
              f"with one literal byte: {sum(r['template_lits1'] for r in old)})")
    print(f"  outputs produced by the strings.py now in the repo: {sum(1 for r in recs if r['version'] == 'current')} of {len(recs)} "
          f"(older: {sum(1 for r in recs if r['version'] == 'older')}, no sidecar hash: {sum(1 for r in recs if r['version'] == '?')})")
    print("  negative control (all processes; rows outside the target pid):")
    for rec in negative_control(a.repo, imgs):
        if "gated_procs" in rec:
            print(f"    {rec['image'][:40]}: GATED   non-target processes={rec['gated_procs']} scanned={rec['gated_procs_scanned']} "
                  f"rows beyond 'compiler'={rec['gated_rows_beyond_compiler']} in {rec['gated_procs_with_rows']} processes {rec['gated_kinds']}")
        if "ungated_procs" in rec:
            s = rec
            print(f"    {rec['image'][:40]}: UNGATED non-target processes={s['ungated_procs']} String={s['ungated_string']} "
                  f"(chunk {s['ungated_string_chunk']}, {100 * s['ungated_string_chunk'] / max(1, s['ungated_string']):.0f}%) &str={s['ungated_str']} "
                  f"location={s['ungated_location']} template candidates={s['ungated_template_cand']} referenced={s['ungated_template_referenced']} "
                  f"unverifiable={s['ungated_template_unverifiable']} lits=1: {s['ungated_template_lits1']}  top String procs={s['ungated_top_string_procs']}")
            if s["ungated_referenced_examples"]:
                print(f"       referenced templates in non-Rust processes (gate residue): {s['ungated_referenced_examples']}")
        if "gated_procs" not in rec and "ungated_procs" not in rec:
            print(f"    {rec['image'][:40]}: no all-process output")


if __name__ == "__main__":
    main()
