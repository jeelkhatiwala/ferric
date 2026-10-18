#!/usr/bin/env python3
"""Regenerate the control-corpus provenance table from files in the repo only.

Inputs : MANIFEST/images.csv, analysis/<image>.vol/ferric_provenance.txt (text renderer output of
         ferric.provenance.Provenance run with --pid <target pid>).
Output : one row per image (expected compiler, recovered compiler, hits, placement, std-dep set),
         then the counts a results table needs. Every image without a usable plugin output is listed
         as a failure with the reason; nothing is skipped silently (EVIDENCE-STANDARD sections 1.6, 2).

Usage  : python3 eval/make_table_provenance.py [--repo .] [--tsv eval/table_provenance.tsv]
Exit   : 0 when every image with a Rust target has a correct, unambiguous compiler row; 1 otherwise.
"""
import argparse, csv, glob, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import image_class  # noqa: E402

# rustc release -> commit, verified in the lab by `rustc +<ver> -vV` and read back from binaries
# (NOTEBOOK Session 12). Kept here, not imported from the plugin, so the scorer is independent of it.
COMMIT_OF = {
    "1.71.0": "8ede3aae28fe6e4d52b38157d7bfe0d3bceef225",
    "1.77.0": "aedd173a2c086e558c2b66d3743b344f977621a7",
    "1.83.0": "90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf",
    "1.89.0": "29483883eed69d5fb4db01964cdf2af4d86e9cb2",
    "1.99.0": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4",
}


def parse_output(path):
    """Return (rows, problem). rows: list of dicts with pid, process, tier, evidence, hits, vmas, file, anon."""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return None, f"unreadable ({e})"
    lines = [l for l in text.splitlines() if l.strip()]
    hdr = [i for i, l in enumerate(lines) if l.startswith("PID\t")]
    if not hdr:
        return None, "no table header (truncated or failed run)"
    rows = []
    for l in lines[hdr[0] + 1:]:
        p = l.split("\t")
        if len(p) < 9 or not p[0].isdigit():
            continue
        rows.append({"pid": int(p[0]), "process": p[1], "tier": p[2], "evidence": p[3], "hits": int(p[4]),
                     "vmas": int(p[5]), "file": int(p[6]), "anon": int(p[7])})
    return rows, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = list(csv.DictReader(open(os.path.join(a.repo, "MANIFEST", "images.csv"), newline="")))
    out, failures = [], []
    n_target = n_scored = n_correct = n_cross = n_neg = n_neg_clean = 0
    n_other = 0
    n_wild = 0
    n_win = n_win_ok = n_win_pending = 0     # Windows target row (win.Provenance >= 0.1.4)
    for im in imgs:
        iid = im["image_id"]
        if image_class(im) == "wild":
            n_wild += 1           # detonated real samples: no ground truth; summarised by scripts/run_wild_plugins.sh
            continue
        if image_class(im) in ("negative", "benign"):
            n_other += 1          # scored by eval/make_table_negatives.py (rows are false positives / observations)
            continue
        cands = glob.glob(os.path.join(a.repo, "analysis", iid + ".*.vol", "ferric_provenance.txt"))
        has_target = im["target_binary_id"] not in ("", "none")
        expected = COMMIT_OF.get(im["rustc_version"], "")
        if has_target:
            n_target += 1
        else:
            n_neg += 1
        if len(cands) != 1:
            failures.append((iid, f"{len(cands)} plugin output files found"))
            continue
        rows, problem = parse_output(cands[0])
        if problem:
            failures.append((iid, problem))
            continue
        pid = int(im["pid"] or 0)
        mine = [r for r in rows if r["pid"] == pid] if has_target else rows
        comp = [r for r in mine if r["tier"] == "compiler"]
        commits = {re.search(r"rustc ([0-9a-f]{12})", r["evidence"]).group(1): r for r in comp
                   if re.search(r"rustc ([0-9a-f]{12})", r["evidence"])}
        stddep = sorted(r["evidence"] for r in mine if r["tier"] == "std-dep")
        deps = sorted(r["evidence"] for r in mine if r["tier"] == "dependency")
        authors = sorted({r["evidence"] for r in mine if r["tier"] == "author"})
        if has_target and im.get("os") == "windows":
            n_win += 1
            tg = [r["evidence"].split(" ", 1)[0] for r in mine if r["tier"] == "target"]
            if not tg:
                n_win_pending += 1      # output from a plugin older than 0.1.4: not scored, not a failure
            elif tg == [im["target_triple"]]:
                n_win_ok += 1
            else:
                failures.append((iid, f"target {tg} != manifest {im['target_triple']}"))
        if not has_target:
            clean = not rows
            n_neg_clean += clean
            out.append([iid, "(no target)", "-", "-", "-", "-", "-", "clean" if clean else f"{len(rows)} rows", "", ""])
            if not clean:
                failures.append((iid, f"baseline image produced {len(rows)} provenance rows"))
            continue
        n_scored += 1
        right = commits.get(expected[:12])
        wrong = [c for c in commits if c != expected[:12]]
        n_correct += right is not None and not wrong
        n_cross += len(wrong)
        if right is None:
            failures.append((iid, f"expected commit {expected[:12]} not recovered (found: {sorted(commits) or 'none'})"))
        if wrong:
            failures.append((iid, f"unexpected compiler commit(s) {wrong}"))
        placement = "-"
        if right:
            placement = "file" if right["anon"] == 0 else ("anon" if right["file"] == 0 else "mixed")
        out.append([iid, im["rustc_version"], expected[:12], "yes" if right else "NO",
                    right["hits"] if right else 0, right["file"] if right else 0, right["anon"] if right else 0,
                    placement, " ".join(stddep), " ".join(deps) + (" | author:" + ",".join(authors) if authors else "")])
    hdr = ["image_id", "rustc", "expected_commit", "recovered", "hits", "file_hits", "anon_hits", "placement",
           "std_dep_set", "dependency_and_author"]
    w = max(len(r[0]) for r in out) if out else 10
    print(f"{'image_id':{w}s} rustc   recovered hits file anon placement  std-dep set")
    for r in out:
        print(f"{r[0]:{w}s} {r[1]:7s} {str(r[3]):9s} {str(r[4]):>4s} {str(r[5]):>4s} {str(r[6]):>4s} {r[7]:9s}  {r[8]}")
    print()
    print(f"images in manifest            : {len(imgs)}")
    print(f"  with a Rust target process  : {n_target}")
    print(f"  with a usable plugin output : {n_scored}")
    print(f"  correct compiler, no other  : {n_correct}")
    print(f"  cross-version compiler rows : {n_cross}")
    print(f"baseline images (no target)   : {n_neg}  clean: {n_neg_clean}")
    print(f"negative / benign programs    : {n_other}  (scored in make_table_negatives.py, not here)")
    print(f"wild detonation images        : {n_wild}  (no ground truth; see eval/wild_*/SUMMARY.txt)")
    print(f"Windows target triple correct: {n_win_ok}/{n_win - n_win_pending}  (not yet reported by the plugin: {n_win_pending})")
    sets = {}
    for r in out:
        if r[3] == "yes":
            sets.setdefault(r[1], set()).add(r[8])
    print("std-dep sets per rustc version (distinct sets observed):")
    for v in sorted(sets):
        for s in sorted(sets[v]):
            print(f"  {v}: {s}")
    if failures:
        print(f"\nFAILURES / EXCLUSIONS ({len(failures)}):")
        for iid, why in failures:
            print(f"  {iid}: {why}")
    if a.tsv:
        with open(a.tsv, "w", newline="") as f:
            cw = csv.writer(f, delimiter="\t"); cw.writerow(hdr); cw.writerows(out)
    sys.exit(0 if (n_scored == n_target and n_correct == n_scored and not failures) else 1)


if __name__ == "__main__":
    main()
