#!/usr/bin/env python3
"""Shared helpers for the eval/make_table_*.py scorers.

parse_grid(path)  -> list of row dicts keyed by the column names in the file's header line, or None when
                     the file is missing or has no header (a crashed or timed-out run). Volatility's quick
                     renderer writes a banner, a blank line, a tab-separated header, a blank line, then one
                     tab-separated row per line; absent cells are "-" (NotAvailableValue) and are returned
                     as None. Integers and 0x-hex are converted; everything else stays a string.
images(repo)      -> the MANIFEST/images.csv rows (dicts).
binaries(repo)    -> binary_id -> MANIFEST/binaries.csv row.
find_output(repo, image_id, name) -> path of analysis/<image_id>.*.vol/<name>, or None.
"""
import csv
import glob
import os


def _cell(s: str):
    if s == "-":
        return None
    if s.startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return s
    if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
        return int(s)
    return s


def parse_grid(path):
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return None
    hdr = [i for i, l in enumerate(lines) if l.startswith("PID\t")]
    if not hdr:
        return None
    cols = lines[hdr[0]].split("\t")
    out = []
    for l in lines[hdr[0] + 1:]:
        if not l or l.startswith("*"):
            continue
        p = l.split("\t")
        if len(p) != len(cols) or not p[0].isdigit():
            continue
        out.append({c: _cell(v) for c, v in zip(cols, p)})
    return out


def images(repo):
    return list(csv.DictReader(open(os.path.join(repo, "MANIFEST", "images.csv"), newline="")))


def binaries(repo):
    p = os.path.join(repo, "MANIFEST", "binaries.csv")
    if not os.path.exists(p):
        return {}
    return {r["binary_id"]: r for r in csv.DictReader(open(p, newline=""))}


def find_output(repo, image_id, name):
    f = glob.glob(os.path.join(repo, "analysis", image_id + ".*.vol", name))
    return f[0] if f else None


def read_truth(path):
    """TRUTH.*.tsv: tab-separated, '#' comments, first column is the record kind. Returns list of lists."""
    rows = []
    try:
        for line in open(path, encoding="utf-8"):
            if not line.strip() or line.startswith("#"):
                continue
            rows.append(line.rstrip("\n").split("\t"))
    except OSError:
        return None
    return rows


def image_class(im) -> str:
    """How a manifest row is scored (Session 68):
       'baseline'  no target process (pid 0 / no target binary): the whole image is a negative control
       'negative'  a non-Rust program captured on purpose (family neg_cpp, neg_go, neg_dotnet, ...):
                   every row a plugin reports in its process is a false positive by construction
       'benign'    a benign Rust program (family neg_rust_benign): provenance/strings/vtables rows are
                   expected, maps/tokio rows are observations; never counted as recall
       'rust'      a Rust seed with ground truth: the images the recall and precision tables are made of
       'wild'      a detonated real sample (det-*): no ground truth, never scored by these tables
    The per-plugin tables score 'rust' images only; eval/make_table_negatives.py scores 'negative' and
    'benign'; 'baseline' rows are reported by provenance; 'wild' rows by scripts/run_wild_plugins.sh."""
    # 'wild' (Session 94): a detonated real sample (image id det-*, registered by scripts/det_register.py).
    #   It has no source and so no ground truth; the control tables never score it. Its plugin outputs live
    #   in eval/wild_<UTC>/ and are summarised by scripts/run_wild_plugins.sh. Checked before the pid, so a
    #   wild baseline (pid 0) is 'wild' too, never mixed into the control baselines.
    if (im.get("image_id") or "").startswith("det-") or "wild sample" in (im.get("ground_truth_notes") or ""):
        return "wild"
    pid = int(im.get("pid") or 0)
    fam = im.get("family_or_label") or ""
    if pid == 0 or im.get("target_binary_id", "") in ("", "none"):
        return "baseline"
    if fam == "neg_rust_benign":
        return "benign"
    if fam.startswith("neg_"):
        return "negative"
    return "rust"
