#!/usr/bin/env python3
"""eval/ferric_out.image_class: which table scores which manifest row.

Session 94 added 'wild': detonated real samples (det-*) have no ground truth and must never enter the
control tables' denominators or failure lists. Before it, a det row with a real pid classified as 'rust'
(a control seed with ground truth). Run: python3 tests/test_image_class.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
from ferric_out import image_class   # noqa: E402

FAILS = []


def check(name, row, want):
    got = image_class(row)
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


check("control seed", dict(image_id="vsweep-05-seed01", pid="9999", target_binary_id="seed01_x",
                            family_or_label="seed01_collections"), "rust")
check("control baseline", dict(image_id="lin-img00-t0", pid="0", target_binary_id="none",
                                family_or_label="seed01_collections"), "baseline")
check("negative program", dict(image_id="neg-01-neg_go", pid="1919", target_binary_id="neg_go_x",
                                family_or_label="neg_go"), "negative")
check("benign rust", dict(image_id="neg-01-neg_rust_benign", pid="77", target_binary_id="rg",
                           family_or_label="neg_rust_benign"), "benign")
check("wild sample with pid", dict(image_id="det-blackcat-f8c08d00-exit", pid="1279",
                                    target_binary_id="f8c08d00ff6e",
                                    family_or_label="BlackCat (MalwareBazaar label, unverified)",
                                    ground_truth_notes="wild sample batch-1; pid from pslist"), "wild")
check("wild baseline (pid 0)", dict(image_id="det-blackcat-f8c08d00-t0", pid="0",
                                     target_binary_id="f8c08d00ff6e", family_or_label="BlackCat",
                                     ground_truth_notes="wild sample batch-1"), "wild")
check("wild by notes only", dict(image_id="x-01", pid="5", target_binary_id="t", family_or_label="Unknown",
                                  ground_truth_notes="wild sample batch-2"), "wild")

if FAILS:
    print("\n".join(FAILS)); print(f"FAILED {len(FAILS)}"); sys.exit(1)
print("ALL PASS")
