#!/usr/bin/env python3
"""Documents a Volatility 3 framework behaviour that affects every scan-based plugin on a
translation (process or kernel) layer: TranslationLayerInterface._scan_iterator ships each
physically-contiguous run as its own chunk, with no overlap between runs. A virtually-contiguous
section whose pages are scattered in physical memory is therefore scanned page by page, and a
pattern straddling a page boundary is never matched.

Observed on real images (NOTEBOOK session 39-40): 96/97 and 43/45 /rustc/<hash>/library/ strings
found by layer.scan; the misses straddle 4 KiB boundaries. This test reproduces the chunking with a
mock layer against the installed framework; it is evidence, not a plugin test.

Run:  python3 tests/test_framework_scan_pagegap.py   (needs volatility3 importable; pinned 2.28.2)
"""
import sys
import volatility3
from volatility3.framework.interfaces import layers as il
from volatility3.framework.layers import scanners


class ScatteredPages(il.TranslationLayerInterface):
    """4 virtually-contiguous 4 KiB pages at scattered physical offsets."""
    PAGES = [(0x0000, 0x10000), (0x1000, 0x50000), (0x2000, 0x30000), (0x3000, 0x70000)]

    def __init__(self):
        self._name = "mock"; self._context = None; self._config_path = "x"; self._dependencies = ["phys"]
    @property
    def name(self): return self._name
    @property
    def dependencies(self): return self._dependencies
    @property
    def minimum_address(self): return 0
    @property
    def maximum_address(self): return 0x4000
    def is_valid(self, offset, length=1): return True
    def mapping(self, offset, length, ignore_errors=False):
        for v, p in self.PAGES:
            if v + 0x1000 <= offset or v >= offset + length:
                continue
            yield (v, 0x1000, p, 0x1000, "phys")
    def _decode(self, *a, **k): raise NotImplementedError
    def _translate(self, *a, **k): raise NotImplementedError
    def _scan_chunk(self, *a, **k): raise NotImplementedError


def main():
    layer = ScatteredPages()
    sc = scanners.RegExScanner(rb"x")
    chunks = list(layer._scan_iterator(sc, [(0x0, 0x4000)]))
    spans = []
    for pieces, _pos in chunks:
        spans.append((min(o for _, o, _ in pieces), max(o + s for _, o, s in pieces)))
    spans.sort()
    gaps_without_overlap = sum(1 for a, b in zip(spans, spans[1:]) if a[1] <= b[0])
    fw = getattr(volatility3.framework.constants, "PACKAGE_VERSION", "?") if hasattr(volatility3, "framework") else "?"
    print(f"volatility3 {fw}: one 16 KiB virtually-contiguous section -> {len(chunks)} scan chunk(s)")
    print(f"chunk spans: {[(hex(a), hex(b)) for a, b in spans]}")
    print(f"chunk boundaries with no overlap: {gaps_without_overlap}")
    if len(chunks) == 4 and gaps_without_overlap == 3:
        print("REPRODUCED: scattered pages are scanned as separate, non-overlapping chunks; "
              "patterns straddling page boundaries cannot match.")
        return 0
    if len(chunks) == 1:
        print("NOT REPRODUCED: this framework version joins scattered pages into one chunk "
              "(behaviour fixed upstream?). Re-evaluate the plugin's direct-read design note.")
        return 2
    print("UNEXPECTED chunking; inspect.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
