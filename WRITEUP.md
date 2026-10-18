# ferric: Rust-aware memory forensics for Volatility 3

Author: Jeel Piyushkumar Khatiwala

Volatility Plugin Contest 2026 submission, to be evaluated as one entry. Every number below was produced
by the scorers in `eval/` from stored plugin outputs over ground-truth control images; the per-image results
are in `eval/RESULTS-linux.md` and `eval/RESULTS-windows.md`, and every prediction made before a run, with
its outcome, is in the pre-registration log `eval/metrics.md`. The Linux wild-sample results are in; a
Windows capture of the same family is planned as a follow-up.

## What it is

ferric is a suite of Volatility 3 plugins that recovers Rust program state from memory images. It detects
which processes are Rust, identifies the compiler and crates that built them, and reconstructs their
strings, their `HashMap` contents, their trait objects and their tokio async tasks. It works on stripped
release builds with no symbols, on Linux and Windows x86-64. Volatility 3 ships no Rust-aware capability
today, and a systematic search found no prior Rust memory-forensics plugin, tool or dataset.

Ten plugin classes, five capabilities on each OS:

| Capability | Linux | Windows |
|---|---|---|
| detection + provenance | ferric.provenance.Provenance | ferric.win.Provenance |
| strings and panic locations | ferric.strings.Strings | ferric.win.Strings |
| hashbrown HashMap/HashSet | ferric.maps.Maps | ferric.win.Maps |
| trait-object vtables | ferric.vtables.VTables | ferric.win.VTables |
| tokio tasks | ferric.tokio.Tokio | ferric.win.Tokio |

## Motivation

Rust has become a mainstream language for serious malware. BlackCat/ALPHV, the Rust rewrite of Hive, the
Rust variants of Agenda/Qilin and Akira, and stealers such as Luca are all written in it. An investigator
holding a memory image from a host hit by one of these faces a process whose binary is stripped, whose
constants may sit inside its code pages, and for which no symbol server, runtime table or existing plugin
offers a foothold. Memory forensics for runtime-rich languages has matured over a decade, from Objective-C
and .NET through the V8 engine and Python to Go, whose memory-forensics paper took the best paper award at
DFRWS USA 2026. Rust was left out, and the reason is structural: it ships none of the runtime metadata
those tools bootstrap from. ferric was built to show that Rust state can be recovered anyway, from
compiler-stable layout invariants rather than metadata, and to measure that recovery against ground truth
so that an analyst knows exactly which rows to trust.

## Why it should win

**It fills a real and current gap.** Until ferric, an analyst with a memory image of any of the families
named above had no Rust-aware tooling at all. ferric is the first, on Linux and on Windows.

**It is technically harder than the languages already covered, and solves that difficulty.** Go embeds
pclntab and moduledata, a program-wide table a tool can parse to bootstrap everything else. Python, .NET
and V8 keep comparably rich runtime metadata. Rust keeps none: no central runtime object, no type table,
no managed heap, and after stripping no symbols. ferric recovers Rust state structurally instead, from
compiler-stable invariants: fat-pointer header shapes, the hashbrown SwissTable control-byte layout, the
trait-object vtable prologue, the tokio task header. Each recogniser works without a single symbol.

**It is validated quantitatively, not by anecdote.** Prior language-runtime forensics papers report
qualitative case studies. ferric is scored against ground truth taken from the control programs' own source,
on 45 Linux and 36 Windows memory images spanning five rustc versions (1.71 to 1.99), both Windows linkers
(MSVC and gnu), optimization levels 0/2/3/s/z, panic=abort, stripped and unstripped, path remapping, UPX
packing, musl static linking and memory pressure:

| Capability | Linux | Windows |
|---|---|---|
| provenance: correct compiler, nothing spurious | 42/42 images | 36/36; MSVC-vs-gnu target 36/36 |
| strings: String / panic Location | 455/455, 24/24 | 402/402, 20/20 |
| strings: &str / fmt templates | 76/76, 63/63 | 72/72, 51/52 |
| maps: tables / key-value pairs | 72/72, 618/618 | 70/72, 701/708 |
| vtables | 1,285/1,285 confirmed against symbols, 0 false | 36/36 by shape |
| tokio: live tasks / worker locals | 36, 24/24 | 36, 24/24 |

**It has real negative controls on both operating systems.** C++, Go and .NET programs built to the same
shape as the Rust seeds produce zero rows from every plugin, on Linux and on Windows: five negative images,
zero false-positive rows across all five plugins. The Go program is the sharp test, since its maps are
SwissTable-derived like Rust's and an early tokio recogniser fired 45 false task rows on it; fixing that
(version 0.3.0) brought it to zero while keeping every true task, and the production gate now declines all
three non-Rust languages before any recogniser runs. The complement is a benign Rust program, ripgrep:
ferric detects it, names its compiler and crate set, and recovers its strings and trait objects, with tokio
correctly empty because ripgrep is not async. So a ferric row means Rust, and the suite stays silent on
everything else. On an idle Windows 11 image ferric reports only anonymous, correctly unclassified Rust
residue left by Defender scanning the disk.

**It shows what memory recovers that disk cannot.** On a UPX-packed control, `strings` and YARA on the
file find no compiler path; ferric recovers the exact rustc version and the crate set from the process's
anonymous memory. This is the forensic case for the tool in one image.

**It is reproducible and upstream-ready.** Every table regenerates from the released artifact with one
command. The plugins follow Volatility 3's conventions (requirements interface, versioned classes, OS
namespaces, ISF handling) and carry a unit-test suite (21 files) that runs without an image.

**It contributes a finding back to Volatility.** While building ferric we found that Volatility 3's
`layer.scan()` sends each physically contiguous run of pages to the scanner with no overlap, so a pattern
that straddles a 4 KiB page boundary is never matched (measured: 1 of 97 and 2 of 45 compiler paths lost on
real images). ferric reads each mapping as one virtual range to avoid it; `tests/test_framework_scan_pagegap.py`
reproduces the behaviour against 2.28.2. This affects every scan-based plugin on a process layer and is
offered as an upstream report.

## Wild malware

ferric was run on real, confirmed-Rust malware detonated in an isolated lab and captured from live process
memory. These samples have no source, so there is no ground truth; the figures are counts of what the
plugins reported, corroborated only by each sample's own recovered compiler fingerprint and by inspection
of the recovered strings. Acquisition and detonation were performed entirely by the investigator; the tool
read the resulting images.

Six Linux ELF samples were captured at an execution-hold point and handed to the suite with no per-sample
tuning. The Rust-fingerprint gate, the same mechanism that keeps a whole-guest scan to minutes, made the
Rust-or-not decision unattended. For the three genuine Rust samples, the per-kind recovery:

| sample (sha256 prefix) | gate | compiler recovered | String | &str | panic Location | vtables |
|---|---|---|---|---|---|---|
| 1cbbf108 | scanned | rustc 1.61.0 | 1 | 137 | 335 | 74 |
| 45b8678f (BlackCat-labelled) | scanned | 1.59.0-nightly e012a191 | 20 | 363 | 686 | 300 |
| f8c08d00 (BlackCat) | scanned | nightly 532d2b14, 47-crate set | 411 | 481 | 969 | 292 |
| 2e52494e, cb408d45, cd27a31e | refused | no fingerprint present | not scanned | | | |

The three samples with no `/rustc/` path were refused by the gate with no prompting: the suite declines
non-Rust processes instead of emitting heuristic noise on them, which on real triage is the common case and
is itself a result. Each genuine Rust sample carried its own distinct compiler commit, and f8c08d00's
47-crate dependency set was read from its compiler paths.

Two of these samples were recoverable at all only after a defect uncovered during this work, and the fix is
a clean before-and-after. f8c08d00 and 45b8678f link their read-only constants into the text segment, a
layout none of the ground-truth control images use. The original recogniser inspected only a separate read-only-data
segment, so it both refused to scan these two (the compiler fingerprint was in the code pages, not a rodata
segment) and, once that was addressed, still rejected every `&str` and Location whose bytes lived in that
merged segment. Two gated changes fixed this. The first widened the fingerprint test to the executable's
own code pages; it moved no control number (pre-registered, then verified on every control). The second
reads `&str` and Location literals from the executable's code when, and only when, the binary is detected to
be merged-text, so no separate-rodata control can be affected; this too was pre-registered and verified to
move zero of the validly-scanned controls. Together they took 45b8678f and f8c08d00 from returning nothing
to the recovery in the table above: compiler, crate set, hundreds of trait-object vtables, heap `String`
objects, and now the static `&str` and panic-Location records as well.

The recovered `&str` rows were inspected to confirm they are genuine literals rather than coincidental byte
matches: they include the standard library's `Vec` bounds-check panic messages, returned as the separate
format pieces the compiler splits a `panic!` template into, and a date crate's month and weekday names.
Recovering the pieces in exactly the form the compiler stores them is itself evidence the reconstruction is
faithful. This is the forensic argument for the structural approach, demonstrated on live ransomware: from a
memory image alone, with no symbols and no file on the disk being examined, an analyst recovers the
compiler, the crate set, the live trait-object population, and the program's string and panic-site tables.

A same-family Windows capture of BlackCat, giving a direct Windows-versus-Linux comparison on one family,
is the remaining piece and is pending sample acquisition.

## What is in the submission

- Repository: https://github.com/jeelkhatiwala/ferric
- Source: the ten plugin classes and the shared recognisers, plus the unit tests.
- Memory samples demonstrating the capabilities: two images of the same self-compiled control program
  (`seed02_tokio`, the one seed that exercises all five capabilities at once; no malware), one Linux and one
  Windows, so the outputs can be compared plugin for plugin. On the single target process every plugin
  returns rows: Linux provenance 7, strings 538, maps 6, vtables 78, tokio 9; Windows provenance 5, strings
  415, maps 4, vtables 71, tokio 9. Both are built with path remapping, so ferric's output carries no
  build-account path. README-DEMO.md gives their hashes, the five commands per image and the expected output.
- Usage: plugins/README.md (every option, output column and example).
- This write-up.
- A signed Individual Contributor License Agreement.
- Entry type: one entry, the ferric suite (the capabilities share the recognisers and are strongest together).
- Copyright: the author owns the copyright to the submitted source code and is authorized to submit it. The
  code is released under the MIT licence (LICENSE in the repository).

## Honest limitations

x86-64 only. On Windows the read-only data examined is the main executable's; Rust loaded as a DLL or mapped
without a PE header is out of scope. Detection relies on the `/rustc/<commit>/` path that programs linked
against Rust's shipped std carry; a binary built with a remapped custom std needs `--force-scan`. Compiler
versions are named for a built-in commit table; others are reported by commit and can be extended.
Wild-sample rows are counts, not scored against source. The idle-Windows baseline shows a toolchain-path
artifact from building controls on the analysis guest, documented as a threat to validity.
