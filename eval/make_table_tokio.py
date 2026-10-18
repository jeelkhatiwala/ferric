#!/usr/bin/env python3
"""Score ferric.tokio outputs against seed02_tokio's known task set. Pre-registered in eval/METRICS.md.

Ground truth (control-corpus/seeds/seed02_tokio/src/main.rs, held at t1)
  Four tasks spawned with tokio::spawn and parked on a 24-hour sleep. Each future keeps two String
  locals alive across the await: `worker` = "worker-<i>" (i in 0..4) and `name` = "seed02-scheduler".
  main() keeps every JoinHandle in `handles`, so each task's state carries JOIN_INTEREST; none has run
  to completion, so none carries COMPLETE.
What is scored (target pid only)
  task rows        'task' rows: a live, validated task Header (kind=task).
  worker recall    how many of worker-0..worker-3 appear in the Locals of a task row that also carries
                   join-interest and not complete  (needs tokio >= 1.28, whose vtable publishes the
                   offsets; older runtimes score task rows only and report locals as n/a).
  name recall      how many of those same rows also carry "seed02-scheduler".
  runtime workers  live task rows that are the scheduler's own worker threads: the multi-thread runtime
                   launches each worker thread through the blocking pool as a task that runs for the life
                   of the process (state RUNNING, 2 references, owner_id 0, task ids allocated before the
                   first user spawn). seed02 asks for worker_threads = 2, so 2 are expected; a build with 3
                   showed 3 (Session 59, live). When analysis/<img>.vol/pslist_threads.txt exists
                   (linux.pslist --threads --pid <pid>), the count of tokio-rt-worker threads is printed
                   next to it as an independent check.
  unattributed     any other live task row (listed, counted as neither).
  stale / remnant  reported for information; never counted as tasks.
Negative control
  ferric_tokio_allprocs.txt: task rows outside the target pid, by process (a non-tokio process must
  have none; a vtable or candidate row there is a candidate false positive and is listed).

Inputs : MANIFEST/images.csv; analysis/<img>.vol/ferric_tokio.txt [ferric_tokio_allprocs.txt]
Usage  : python3 eval/make_table_tokio.py [--repo .] [--tsv out.tsv]
"""
import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ferric_out import parse_grid, images, find_output  # noqa: E402

FAMILY = "seed02_tokio"
WORKERS = [f"worker-{i}" for i in range(4)]
NAME = "seed02-scheduler"
RUNTIME_WORKERS = 2                      # #[tokio::main(flavor = "multi_thread", worker_threads = 2)]


def parse_grid_pslist(path):
    """linux.pslist text output -> rows keyed by column (its header starts with OFFSET, not PID)."""
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return None
    hdr = [i for i, l in enumerate(lines) if l.startswith("OFFSET")]
    if not hdr:
        return None
    cols = lines[hdr[0]].split("\t")
    out = []
    for l in lines[hdr[0] + 1:]:
        p = l.split("\t")
        if len(p) != len(cols):
            continue
        d = dict(zip(cols, p))
        try:
            d["PID"] = int(d["PID"]); d["TID"] = int(d["TID"])
        except (KeyError, ValueError):
            continue
        out.append(d)
    return out


def locals_of(row):
    s = row.get("Locals") or ""
    return [p.strip('"') for p in s.split(" | ") if p]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    imgs = images(a.repo)
    tsv = open(a.tsv, "w") if a.tsv else None
    if tsv:
        tsv.write("image_id\trustc\tvtables\ttask_rows\tjoin_interest_rows\tworkers_found\tname_found\truntime_workers\trt_threads\tunattributed\tstale\tremnant\tlayout\n")
    tot = Counter()
    print(f"{'image_id':66s} rustc   vt  tasks  join  workers  name  rt-workers   unattr  stale/remn  layout")
    for im in imgs:
        pid = int(im["pid"] or 0)
        if pid == 0 or im["family_or_label"] != FAMILY:
            continue
        tot["images"] += 1
        f = find_output(a.repo, im["image_id"], "ferric_tokio.txt")
        rows = parse_grid(f) if f else None
        if rows is None:
            tot["noout"] += 1
            print(f"{im['image_id']:66s} {im['rustc_version']:7s} NO OUTPUT")
            continue
        mine = [r for r in rows if r["PID"] == pid]
        vts = [r for r in mine if r["Kind"] == "vtable"]
        tasks = [r for r in mine if r["Kind"] == "task"]
        stale = [r for r in mine if r["Kind"] == "stale"]
        remn = [r for r in mine if r["Kind"] == "remnant"]
        layout = ""
        for v in vts:
            n = str(v.get("Note") or "")
            if "layout" in n:
                layout = n.split(";")[0]
                break
        has_offsets = any("trailer_offset" in str(v.get("Note") or "") for v in vts)
        parked = [r for r in tasks if "join-interest" in str(r["Flags"]) and "complete" not in str(r["Flags"])]
        found_w, found_n, attributed = set(), 0, set()
        for r in parked:
            locs = locals_of(r)
            w = [x for x in locs if x in WORKERS]
            if w:
                found_w.add(w[0])
                attributed.add(r["Header"])
                if NAME in locs:
                    found_n += 1
        first_user = min([r["TaskId"] for r in parked if isinstance(r["TaskId"], int)] or [1 << 62])
        runtime = [r for r in tasks if r["Header"] not in attributed and "running" in str(r["Flags"]) and r["Refs"] == 2
                   and isinstance(r["TaskId"], int) and r["TaskId"] < first_user and "owner_id=0" in str(r["Note"])]
        for r in runtime:
            attributed.add(r["Header"])
        unattr = [r for r in tasks if r["Header"] not in attributed]
        rt_threads = None
        pt = find_output(a.repo, im["image_id"], "pslist_threads.txt")
        if pt:
            prow = parse_grid_pslist(pt)
            if prow is not None:
                rt_threads = sum(1 for r in prow if r["PID"] == pid and r["COMM"] == "tokio-rt-worker")
        tot["vtables"] += len(vts); tot["tasks"] += len(tasks); tot["parked"] += len(parked)
        tot["workers"] += len(found_w); tot["names"] += found_n; tot["unattr"] += len(unattr)
        tot["runtime"] += len(runtime); tot["runtime_expected"] += RUNTIME_WORKERS
        if rt_threads is not None:
            tot["thread_checked"] += 1; tot["thread_agree"] += (rt_threads == len(runtime))
        tot["expected_workers"] += 4
        if has_offsets:
            tot["images_with_offsets"] += 1
        wtxt = f"{len(found_w)}/4" if has_offsets else "n/a"
        ntxt = f"{found_n}/4" if has_offsets else "n/a"
        rt_txt = f"{len(runtime)}/{RUNTIME_WORKERS}" + (f" thr={rt_threads}" if rt_threads is not None else "")
        print(f"{im['image_id']:66s} {im['rustc_version']:7s} {len(vts):<3d} {len(tasks):<6d} {len(parked):<5d} {wtxt:8s} {ntxt:5s} "
              f"{rt_txt:12s} {len(unattr):<7d} {len(stale)}/{len(remn):<8d} {layout}")
        for r in unattr[:6]:
            print(f"      unattributed task hdr={r['Header']:#x} state={r['State']:#x} [{r['Flags']}] refs={r['Refs']} id={r['TaskId']} locals={r['Locals']}")
        if tsv:
            tsv.write("\t".join(str(x) for x in (im["image_id"], im["rustc_version"], len(vts), len(tasks), len(parked),
                                                  len(found_w) if has_offsets else "", found_n if has_offsets else "",
                                                  len(runtime), rt_threads if rt_threads is not None else "",
                                                  len(unattr), len(stale), len(remn), layout)) + "\n")
    print("\nSUMMARY")
    print(f"  seed02 images                  : {tot['images']}   no output: {tot['noout']}")
    print(f"  task vtables found             : {tot['vtables']}")
    print(f"  live task rows                 : {tot['tasks']}   parked with join-interest: {tot['parked']}")
    off = tot["images_with_offsets"]
    if off:
        print(f"  worker locals recovered        : {tot['workers']}/{4 * off} over {off} images whose vtable publishes offsets")
        print(f"  scheduler name in those tasks  : {tot['names']}/{4 * off}")
    else:
        print("  worker locals                  : not scorable (no vtable with offsets; tokio < 1.28)")
    print(f"  runtime worker cells           : {tot['runtime']}/{tot['runtime_expected']}  (worker_threads = {RUNTIME_WORKERS} in the seed)"
          + (f"; thread-list check agrees on {tot['thread_agree']}/{tot['thread_checked']} images" if tot["thread_checked"] else "; no pslist_threads.txt yet"))
    print(f"  unattributed live task rows    : {tot['unattr']}")
    print("  negative control (all processes; rows outside the target pid, by process and kind):")
    for im in imgs:
        f = find_output(a.repo, im["image_id"], "ferric_tokio_allprocs.txt")
        if not f:
            continue
        rows = parse_grid(f)
        if rows is None:
            print(f"    {im['image_id']}: NO OUTPUT")
            continue
        pid = int(im["pid"] or 0)
        other = [r for r in rows if r["PID"] != pid]
        kinds = Counter(f"{r['Process']}:{r['Kind']}" for r in other)
        print(f"    {im['image_id']}: processes with rows={len({r['PID'] for r in rows})} rows outside target={len(other)} "
              f"task rows outside target={sum(1 for r in other if r['Kind'] == 'task')} {dict(kinds)}")
    if tsv:
        tsv.close()


if __name__ == "__main__":
    main()
