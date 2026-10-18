# RESULTS-linux.md: the Linux control-corpus results as they stand (closed 2026-10-11)

Source of every number: the host sweep `20261011T025629Z` (eval/sweep_20261011T025629Z/SUMMARY.txt
and the per-plugin tables next to it), produced by `scripts/plugin_sweep.sh` on the plugin files whose
hashes its preflight recorded (maps.py bf8337e1, provenance.py a02777bf, strings.py 95042c3c,
tokio.py f1f03cd9, vtables.py 1f021972; Volatility 3 2.28.2, Python 3.14.4, ISF
ubuntu-6.8.0-146-generic.json 95c00255). One bookkeeping note: provenance.py a02777bf carries the
0.3.2 author-tier change (its changelog comment says so) while its `_version` constant still reads
0.3.1; the constant is bumped at the next edit of that file, not here, so the hash the tables cite
stays the hash that ran. `bash eval/run_all.sh` regenerates the same tables from the
saved plugin outputs in analysis/; the sweep that produced each output is named in its .meta sidecar.
Pre-registered predictions and their read-outs are in eval/metrics.md (Sessions 60 to 72); this file
only states what the tables say now and what they do not cover.

## 1. The images (45)

| Class | Images | Ids |
|---|---|---|
| seed01_collections (Vec, String, HashMap; the survival seed) | 22 | vsweep-01..05 (rustc 1.71/1.77/1.83/1.89/1.99), rsweep-01..05 (same, --remap-path-prefix), cfgsweep-01..05 (1.99: opt 0/3/s/z, panic=abort), pressure-01/02 (552 MB and 101 MB free), upx-01, musl-01, lin-img01, lin-img02-avml (AVML in-guest capture), lin-img03-t1 |
| seed02_tokio (tokio 1.53.2 runtime, 2 workers, 4 user tasks) | 6 | s2sweep-01..05, lin-img04-seed02-t1 |
| seed03_graph (trait objects, Arc/Rc) | 9 | s3sweep-01..05, s3fix-01/02 (1.71 and 1.77 rebuilt), vtest-01, lin-img05-seed03-t1 |
| seed05_maps (seven maps incl. a nested one) | 5 | s5sweep-01..04 and the 1.99 image (id s5sweep-01-seed05_maps__1.99.0, numbered per invocation) |
| baseline, no Rust target | 1 | lin-img00-t0 (the idle guest) |
| negative programs (not Rust) | 2 | neg-01-neg_cpp, neg-01-neg_go |

All captures are `virsh dump --memory-only --format elf` of the libvirt guest except lin-img02-avml
(AVML LiME, same held PID as lin-img03-t1). Every seed binary is held at its t1 point; binaries and
images are hashed in MANIFEST/.

## 2. Per plugin, scored against symbols or the seed's truth file

| Plugin (version in the sweep) | Measure | Result |
|---|---|---|
| ferric.provenance 0.3.2 | correct compiler and no other on the 42 images with a Rust target | 42/42, 0 cross-version rows; baseline image clean |
| ferric.strings 0.4.0 | String truth recall over 42 images | 455/455 |
| | Location truth recall | 24/24 |
| | &str pieces (rustc <= 1.92 images) | 76/76 |
| | fmt templates (rustc >= 1.93 images) | 63/63; 0 truth templates dropped by the reference gate, 0 unverifiable |
| | template candidates kept by the gate | 1,535 to 847 over 21 images (42 kept rows hold a single literal byte) |
| | String rows outside the truth (extra, unverified, not called false) | 1,273 (seed01 3, seed02 22, seed03 14, seed05 1,234) |
| ferric.maps 0.4.1 | known tables recovered | 72/72 (1.71 11/11, 1.77 11/11, 1.83 12/12, 1.89 11/11, 1.99 27/27) |
| | key/value pairs, recall and precision | 618/618 and 618/618 |
| ferric.vtables 0.2.4 | rows in the target binary confirmed against the unstripped twin (28 images with a twin) | 1,285/1,285, 0 false, precision 1.000; 38 rows unverifiable (twin differs locally), not counted |
| | known trait objects | 35/35 on the scored images; 14 images without a twin match by shape only (not a recall figure) |
| | drop entry form, all target rows | null only from rustc 1.83 on (1.71: 0 null / 331 fn; 1.77: 0 / 276; 1.83: 209 / 86; 1.89: 178 / 81; 1.99: 688 / 330), as predicted for >= 1.79 |
| ferric.tokio 0.3.0 | seed02, 6 images | 12 task vtables, 36 live task rows (24 parked with join interest), worker locals 24/24, scheduler name 24/24, runtime worker cells 12/12, thread-list check 6/6, 0 unattributed |

Negative controls, same sweep:

| Control | Result |
|---|---|
| all processes of 5 whole images (lin-img00-t0, vsweep-01, vsweep-05, s2sweep-05, musl-01) | 0 rows outside the target PID for maps, vtables and tokio; strings scans 0 of the 27 non-target processes per image (no compiler fingerprint), 0 rows beyond the 'compiler' line |
| the same 5 images with the strings gates off (`--force-scan --all-candidates`) | about 6,400 String rows, 3,835 &str rows and 440 template candidates per image in non-Rust processes; 1 template candidate referenced from code (cron, `{:...}{:...}_`), the gate's residue |
| neg_cpp and neg_go, one image each | 0 rows from all five plugins (strings: not scanned, no fingerprint); the Go image is the one that produced 45 false tokio rows under 0.2.1 and 0 under 0.3.0 |

## 3. Survival matrix (seed01 unless stated; 21 conditions, all five plugins)

```
condition                                                  provenance        strings                                   maps                                        vtables
baseline: 1.99 o2 unwind strip=symbols, virsh dump         45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     cfg: table ok, pairs 2/2, stride 48:chunk   45 rows, known 1/1, in rodata
rustc 1.71 (GNU ld, legacy mangling)                       11 hits, 1.71.0   string 12/12 location 1/1 str 4/4          same                                        54 rows, known 1/1, in rodata
rustc 1.77                                                 13 hits, 1.77.0   string 12/12 location 1/1 str 4/4          same                                        46 rows, known 1/1, in rodata
rustc 1.83                                                 11 hits, 1.83.0   string 12/12 location 1/1 str 4/4          same                                        42 rows, known 1/1, in rodata
rustc 1.89                                                 20 hits, 1.89.0   string 12/12 location 1/1 str 4/4          same                                        44 rows, known 1/1, in rodata
strip=none (ad hoc build), virsh dump                      45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
strip=none, AVML in-guest capture (same PID)               45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
--remap-path-prefix (home + sysroot)                       45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
opt-level 0                                                53 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        46 rows, known 1/1, in rodata
opt-level 3 / s / z (three conditions)                     45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
panic = abort                                              46 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
memory pressure, 552 MB and 101 MB available (two)         45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
UPX -9 packed                                              45 hits, 1.99.0   string 12/12 location 1/1 template 3/3     same                                        45 rows, known 1/1, in rodata
musl static-pie                                            97 hits, 1.99.0   string 12/12 location 1/1 template 3/3     cfg: table ok, pairs 2/2, stride 48:content 44 rows, known 1/1, in data
seed03 (trait objects), 1.99 / 1.71                        43 / 10 hits      string 6/6; template 2/2 (1.99), location 1/1 str 4/4 (1.71)   areas: table ok, pairs 3/3, stride 32:chunk   45 / 54 rows, known 3/3
seed02 (tokio 1.53.2), 1.99 / 1.71                         52 / 19 hits      string 12/12; template 4/4 (1.99), str 4/4 (1.71)              settings: table ok, pairs 2/2, stride 48:chunk 78 / 102 rows; tokio 6 tasks, 4/4 workers with locals
```

(The full-width table with every condition on its own row is survival_table.txt in the sweep
directory; the three opt levels and the two pressure points are collapsed here because their cells
are identical.) Reading: no condition in the matrix changed any plugin's recall. Two conditions change
*how* things are found without changing the result: under musl the vtables sit in a writable data
region (static-pie relocation) and the map's bucket stride is inferred from the bucket contents
because musl's allocator has no glibc chunk header to pin it; under --remap-path-prefix the
provenance hit count stays at 45 because the `/rustc/<commit>/` paths are baked into the prebuilt
standard library, which a remap applied while compiling the seed does not rewrite.

## 4. What this file does not cover (so nobody reads silence as success)

- Windows: 0 images; the ferric.win classes have not run on any image (W-D is the first).
- Real samples: the six batch-1 images were scored by provenance only; the maps/vtables/tokio/strings
  re-run on them is pending.
- Benign Rust control (a large non-malicious Rust program in the image): 0 images; the ripgrep
  control is written but not captured.
- .NET negative program: not built (guest sudo password).
- tokio: every real cell reads list=lone (sharded OwnedTasks, 8 shards, 4 tasks), so the back-link
  check of 0.3.0 is exercised by unit tests only; a seed02 variant with more tasks than shards would
  exercise it on a real cell.
- vtables: 14 of 42 images have no unstripped twin on the host and are matched by shape only.
- strings: the 1,273 "extra" String rows are unverified, neither confirmed nor called false; most are
  seed05's, whose truth file lists the strings its maps hold and not every String the program builds.
- Execution points: t1 (held) everywhere except the one t0 baseline; no t2 (after teardown) images.
- Second Volatility release and stored YARA/stock-strings baselines: not run.
