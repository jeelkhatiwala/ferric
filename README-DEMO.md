# ferric demo memory images: expected output

The memory sample(s) for the Volatility Plugin Contest 2026 submission. Each holds one process running a
self-compiled Rust program (`seed02_tokio`, the project's tokio control seed) that exercises all five
ferric capabilities at once. It is not malware and contains no third-party code beyond the program's
crates.io dependencies. Built with `--remap-path-prefix`, so ferric's output carries no build-account path.
The Linux and Windows images hold the same program built for each OS, so the two outputs can be compared
plugin for plugin.

## Linux demo image

| field | value |
|---|---|
| file | `demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf` |
| sha256 | `a1d77226ade48d3287f7860e9143b59c810c14eee453cfc64850b29540b52191` |
| size | 4,303,554,739 bytes |
| format | virsh-dump-elf (libvirt) |
| guest | linux Ubuntu 24.04.3 Server, kernel 6.8.0-146-generic, x86_64 |
| target process | PID 49021 |
| program | `seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on` |
| program sha256 | `ce34c3d40a21b34182b63b8c2ac7baa0686301845441e87798ddeab66613789c` (612,800 bytes) |
| compiler | rustc 1.99.0 (x86_64-unknown-linux-gnu), opt-level 2, panic=unwind, strip=symbols |
| symbols | `symbols/linux/` holds the ISF for this kernel (ships with the submission) |

### Reproduce

From the submission root, with Volatility 3 2.28.2 installed. Each command prints a table; the counts
below are rows for the target PID. `--dump`/`--dump-hits` additionally write evidence files and do
not change the printed rows.

#### provenance

```
vol -q -p plugins -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf -s symbols/linux ferric.provenance.Provenance --pid 49021 --dump-hits --commit-map eval/commit_map.csv
```

Expected: **7 rows** (std-dep 5, compiler 1, dependency 1).

First rows:

| Tier | Evidence | Hits |
|---|---|---|
| compiler | rustc b940084d7eb6 = 1.99.0 | 52 |
| std-dep | addr2line-0.27.1 | 3 |
| std-dep | gimli-0.34.0 | 3 |
| std-dep | rustc-demangle-0.1.28 | 3 |
| std-dep | miniz_oxide-0.9.1 | 2 |
| std-dep | hashbrown-0.17.1 | 1 |

#### strings

```
vol -q -p plugins -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf -s symbols/linux ferric.strings.Strings --pid 49021 --dump --commit-map eval/commit_map.csv
```

Expected: **538 rows** (location 434, template 59, string 24, str 18; plus 3 bookkeeping row(s): compiler, layout, templates).

First rows:

| Kind | Len | Text |
|---|---|---|
| compiler | 0 | rustc 1.99.0 (b940084d7eb6, 52 hits): templates scanned |
| location | 104 | /redacted/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1... |
| location | 76 | /rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/io/wr... |
| location | 100 | /redacted/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1... |
| str | 28 | failed to write whole buffer |
| location | 76 | /rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/io/wr... |

#### maps

```
vol -q -p plugins -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf -s symbols/linux ferric.maps.Maps --pid 49021 --explain
```

Expected: **6 rows** (entry 4, table 2).

First rows:

| Kind | Items | Stride | Note |
|---|---|---|---|
| table | 2 | 32 | cap=3 gl stride=32:chunk |
| entry | 2 | 32 |  |
| entry | 2 | 32 |  |
| table | 2 | 48 | cap=3 gl stride=48:chunk |
| entry | 2 | 48 | layout=cap,ptr,len |
| entry | 2 | 48 | layout=cap,ptr,len |

#### vtables

```
vol -q -p plugins -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf -s symbols/linux ferric.vtables.VTables --pid 49021 --objects
```

Expected: **78 rows** (vtable 78).

First rows:

| VTable | VTableIn | Size | Align | Methods | CodeRefs | Refs |
|---|---|---|---|---|---|---|
| 97315933218992 | rodata | 16 | 8 | 3 | 2 | 0 |
| 97315933219088 | rodata | 8 | 8 | 1 | 1 | 0 |
| 97315933219464 | rodata | 0 | 1 | 1 | 2 | 0 |
| 97315933219552 | rodata | 8 | 8 | 1 | 1 | 0 |
| 97315933219584 | rodata | 8 | 8 | 3 | 1 | 0 |
| 97315933219680 | rodata | 8 | 8 | 1 | 1 | 0 |

#### tokio

```
vol -q -p plugins -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf -s symbols/linux ferric.tokio.Tokio --pid 49021
```

Expected: **9 rows** (task 6, vtable 2, stale 1).

First rows:

| Kind | TaskId | Locals | Note |
|---|---|---|---|
| vtable | - |  | tokio 1.28+ layout; vtable at header+16; trailer_offset=0xe8 scheduler... |
| task | 3 | "worker-0" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 4 | "worker-1" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 5 | "worker-2" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 6 | "worker-3" \| "seed02-scheduler" | owner_id=1 list=lone |
| stale | - |  | vtable reference on a stack: a cell built there before boxing |

### Summary

| plugin | rows | by kind |
|---|---|---|
| provenance | 7 | std-dep 5, compiler 1, dependency 1 |
| strings | 538 | location 434, template 59, string 24, str 18; plus 3 bookkeeping row(s): compiler, layout, templates |
| maps | 6 | entry 4, table 2 |
| vtables | 78 | vtable 78 |
| tokio | 9 | task 6, vtable 2, stale 1 |

## Windows demo image

| field | value |
|---|---|
| file | `wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf` |
| sha256 | `4dc24977c19b2dcd5727800bc664f2f91971c5b731e7416aeb3c21508e2fec57` |
| size | 6,509,248,539 bytes |
| format | virsh-dump-elf (libvirt) |
| guest | windows Windows 11 10.0.26300, x86_64 |
| target process | PID 5316 |
| program | `seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on` |
| program sha256 | `85b9620ffe1505c6cf663c5b83595e6f4363d08346756ff3da1d291a9a846b3e` (421,888 bytes) |
| compiler | rustc 1.99.0 (x86_64-pc-windows-msvc), opt-level 2, panic=unwind, strip=symbols |
| symbols | `symbols/windows/` holds the kernel PDB symbols for this build (ships with the submission); online, Volatility would fetch them itself |

### Reproduce

From the submission root, with Volatility 3 2.28.2 installed. Each command prints a table; the counts
below are rows for the target PID. `--dump`/`--dump-hits` additionally write evidence files and do
not change the printed rows.

#### provenance

```
vol -q -p plugins -f wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf -s symbols/windows ferric.win.Provenance --pid 5316 --dump-hits --commit-map eval/commit_map.csv
```

Expected: **5 rows** (std-dep 2, compiler 1, target 1, dependency 1).

First rows:

| Tier | Evidence | Hits |
|---|---|---|
| compiler | rustc b940084d7eb6 = 1.99.0 | 45 |
| target | x86_64-pc-windows-msvc (imports VCRUNTIME/UCRT; std-deps without gimli... | 2 |
| std-dep | rustc-demangle-0.1.28 | 3 |
| std-dep | hashbrown-0.17.1 | 1 |
| dependency | tokio-1.53.2 | 63 |

#### strings

```
vol -q -p plugins -f wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf -s symbols/windows ferric.win.Strings --pid 5316 --dump
```

Expected: **415 rows** (location 327, template 56, string 18, str 11; plus 3 bookkeeping row(s): compiler, layout, templates).

First rows:

| Kind | Len | Text |
|---|---|---|
| compiler | 0 | rustc 1.99.0 (b940084d7eb6, 45 hits): templates scanned |
| location | 76 | /rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library\\core\\src\\io... |
| location | 117 | /redacted\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\to... |
| location | 119 | /redacted\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\to... |
| location | 119 | /redacted\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\to... |
| location | 106 | /redacted\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\to... |

#### maps

```
vol -q -p plugins -f wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf -s symbols/windows ferric.win.Maps --pid 5316 --explain
```

Expected: **4 rows** (table 2, entry 2).

First rows:

| Kind | Items | Stride | Note |
|---|---|---|---|
| table | 2 | 48 | cap=3 gl stride=48:content |
| entry | 2 | 48 | layout=cap,ptr,len |
| entry | 2 | 48 | layout=cap,ptr,len |
| table | 2 | - | cap=3 gl stride=?:none |

#### vtables

```
vol -q -p plugins -f wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf -s symbols/windows ferric.win.VTables --pid 5316 --objects
```

Expected: **71 rows** (vtable 71).

First rows:

| VTable | VTableIn | Size | Align | Methods | CodeRefs | Refs |
|---|---|---|---|---|---|---|
| 140694629610448 | rodata | 16 | 8 | 3 | 2 | 0 |
| 140694629611392 | rodata | 0 | 1 | 1 | 2 | 0 |
| 140694629611560 | rodata | 8 | 8 | 1 | 1 | 0 |
| 140694629612728 | rodata | 8 | 8 | 1 | 1 | 0 |
| 140694629612760 | rodata | 8 | 8 | 3 | 1 | 0 |
| 140694629612904 | rodata | 8 | 8 | 1 | 1 | 0 |

#### tokio

```
vol -q -p plugins -f wdemo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_msvc_remap-on.elf -s symbols/windows ferric.win.Tokio --pid 5316
```

Expected: **9 rows** (task 6, vtable 2, stale 1).

First rows:

| Kind | TaskId | Locals | Note |
|---|---|---|---|
| vtable | - |  | tokio 1.28+ layout; vtable at header+16; trailer_offset=0xe8 scheduler... |
| task | 3 | "worker-0" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 4 | "worker-1" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 5 | "worker-2" \| "seed02-scheduler" | owner_id=1 list=lone |
| task | 6 | "worker-3" \| "seed02-scheduler" | owner_id=1 list=lone |
| stale | - |  | vtable reference on a stack: a cell built there before boxing |

### Summary

| plugin | rows | by kind |
|---|---|---|
| provenance | 5 | std-dep 2, compiler 1, target 1, dependency 1 |
| strings | 415 | location 327, template 56, string 18, str 11; plus 3 bookkeeping row(s): compiler, layout, templates |
| maps | 4 | table 2, entry 2 |
| vtables | 71 | vtable 71 |
| tokio | 9 | task 6, vtable 2, stale 1 |

## What the images show

Every plugin returns rows on the one target process: the compiler and crate set (provenance), String/&str/
panic Location records (strings), live hashbrown tables with their entries (maps), trait-object vtables
(vtables), and live tokio tasks with their worker-thread locals (tokio). The project's full evaluation,
with ground truth on 81 control images and zero false positives on five negative-control images, is in
WRITEUP.md; the usage guide is README.md.

Note: each file is a full guest memory dump, so like any memory sample it holds guest data beyond the
target process. The path remapping guarantees that ferric's reported output for the target carries no
build account path; it does not scrub the rest of the guest's memory.
