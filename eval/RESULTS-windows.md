# RESULTS-windows.md: the Windows control-corpus results (second edition, 2026-10-17)

Source: run 20261013T032228Z on 36 Windows images (win.py 52616bfa, maps 0.5.2), scored with the eval/
scripts as of update-s78. Regenerate: `bash eval/run_all.sh`; the Windows figures are the combined
totals minus the Linux figures in eval/RESULTS-linux.md (sweep 20261011T025629Z), which no Windows run
touches. Guest: Windows 11 Pro 26H2 build 26300.9457, libvirt/KVM, virsh dump.
First edition (2026-10-13) was written from run 20261013T015407Z (maps 0.5.1); this edition replaces it.

## Images (36 scanned, 1 not scanned)
| Class | Images |
|---|---|
| MSVC, five rustc versions (1.71, 1.77, 1.83, 1.89, 1.99) x four seeds | wsweep-01 to wsweep-20 |
| gnu host toolchain: seed01 on all five versions, seed02/03/05 on 1.99 | wgnu-01 to wgnu-08 |
| seed01 1.99 MSVC configuration cells: opt 0/3/s/z, panic=abort with strip symbols and none | wcfg-01 to wcfg-06 |
| seed01 1.99 MSVC, held at t1 | win-img01, win-img01b |
| idle guest, no Rust seed | win-img00-t0: captured (Session 77), NOT yet scanned by any plugin |

## Per plugin
| Plugin | Windows result | Linux, same measure |
|---|---|---|
| provenance | correct compiler and no other on 36/36; every hit file-backed in the seed's image; 0 anonymous | 42/42 |
| strings | String 402/402, Location 20/20, &str 72/72 (rustc <= 1.92), templates 51/52 (rustc >= 1.93) | 455/455, 24/24, 76/76, 63/63 |
| maps | tables 70/72, pairs 701/708 recall, 701/708 precision | 72/72, 618/618 |
| vtables | 36/36 known trait objects by shape; 0 rows outside the seed's module; drop entry null only from 1.83 on | same; Linux also symbol-confirmed 1,285/1,285 |
| tokio | 12 task vtables, 36 live tasks, worker locals 24/24, runtime cells 12/12, 0 rows on the 30 non-tokio images | identical |

Pre-registered prediction for maps 0.5.2 (eval/metrics.md, Session 78): "pairs at least 701/708; tables at
least 70/72". HELD exactly. The six seed05 (u64, String) tables went from 0/20 to 20/20 each.

Correction to the first edition: &str was printed as 40/40, carried over from Session 77; the current
scorer gives 72/72 on all three Windows runs (wsweep 01-04, 06-09, 11-14 at 4/4; 16-19 at 2/2; wgnu-01..04
at 4/4). The image count was printed as 37; 36 were scanned.

## Known gaps on Windows
- maps: wsweep-20 (1.99 MSVC) only: HashSet<String> 0/5 (header not found) and (String, Vec<u8>) 0/2
  (stride read 24). These 7 pairs are the whole Windows maps shortfall.
- strings: `item-{}` at opt-level s (wcfg-05) is in memory but read as `{:...}item-{}` with no code
  reference at that start, so the reference gate drops it (51/52).
- provenance: the compiler commit is right on every image, but (a) no row separates MSVC from gnu builds
  (no target-triple evidence on Windows), and (b) the std-dependency set is mostly absent (only 1.71 builds
  show part of it; wgnu-01 shows the full 1.71 set). Linux recovers the full std-dep set on 42/42.
- provenance author rows carry the operator's account name from the C:\Users\<name>\.cargo path. Every
  Windows image contains it; scrub or replace before any image is released.
- vtables: no symbol confirmation until a PE/PDB scorer exists; every figure is by shape.
- Whole-guest control: run 20261011T222721Z on win-img01 and on the image then named win-img00-t0, which
  held a running seed01 (PID 5692) and is now win-img01b. So no idle-guest Windows negative exists yet.
  strings scanned only the seed; vtables 1 row in sshd.exe; maps 0 tables outside the seed (3 near-miss
  rows in services.exe); maps, tokio and the ungated strings scan hit the 45 min cap (rc=124).
  provenance found Rust fingerprints in anonymous memory of MsMpEng.exe (rustc b940084d7eb6, an unmapped
  commit 3f5fd8dd4115, about 50 crate versions), SearchIndexer and one svchost; none file-backed, so none
  is called a Rust process. Source unverified.
- Kernel version: windows.info reports 15.26100 on all images; the manifest records build 26300. To reconcile.
- Not yet run on Windows: the idle baseline, negative programs (C++, Go), the benign Rust control
  (ripgrep MSVC), remap, UPX, memory pressure, WinPMEM, real samples.
