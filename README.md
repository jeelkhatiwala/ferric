# ferric: Rust memory forensics for Volatility 3

[![tests](https://github.com/jeelkhatiwala/ferric/actions/workflows/tests.yml/badge.svg)](https://github.com/jeelkhatiwala/ferric/actions/workflows/tests.yml)

ferric is a suite of Volatility 3 plugins that recovers Rust program state from Linux and Windows memory
images: which processes are Rust, what compiler and crates built them, and their live `String`s, `&str`
literals, panic sites, `HashMap`/`HashSet` tables with their keys and values, trait-object vtables with
live-instance counts, and tokio async tasks with their states and worker-thread locals. It works on stripped
release builds with no symbols for the program. Rust keeps no central runtime object, no type table and no
managed heap, so every recogniser is structural: it keys on invariants the compiler and the standard library
maintain in memory (fat-pointer header shapes, the hashbrown SwissTable control-byte layout, the trait-object
vtable prologue, the tokio task header) rather than on signatures of specific programs.

Ten plugin classes, five capabilities on each OS:

| Capability | Linux class | Windows class | Recovers |
|---|---|---|---|
| detection and provenance | `ferric.provenance.Provenance` | `ferric.win.Provenance` | rustc version and commit, std-dependency set, dependency crates with versions, toolchain and build paths; on Windows the MSVC-vs-gnu target |
| strings | `ferric.strings.Strings` | `ferric.win.Strings` | heap `String`/`Vec<u8>` with capacity, `&str` literals, `core::panic::Location` (file:line:col), `fmt::Arguments` templates |
| maps | `ferric.maps.Maps` | `ferric.win.Maps` | hashbrown `HashMap`/`HashSet` tables: bucket count, live items, deletions, and the decoded key/value entries |
| vtables | `ferric.vtables.VTables` | `ferric.win.VTables` | trait-object vtables: drop glue, size, alignment, method count, code references, live `Box<dyn>`/`&dyn` instance counts |
| tokio | `ferric.tokio.Tokio` | `ferric.win.Tokio` | tokio task vtables, live task cells (state flags, reference count, task id, scheduler, future), `String` locals held inside each task |

## Forensic applications

| Recovered | Use |
|---|---|
| `/rustc/<commit>/` fingerprint, decoded to a version | Is this process Rust at all, and which release built it. Works on packed samples whose file on disk shows nothing (see Validation). |
| dependency crates with versions | A software bill of materials of the binary, from memory: which HTTP, crypto, async, serialisation crates it links |
| toolchain and build paths | Build environment attribution (remapped builds hide these; the compiler fingerprint survives remapping) |
| `String` objects with capacity | Configuration, arguments, paths, hostnames and messages as the program holds them, with the allocation size that tells how each was built |
| panic `Location` records | Every panicking call site's source file, line and column, including the author's own files: a map of the program's source tree |
| `HashMap` entries | Configuration and lookup tables as typed key/value pairs, not byte soup |
| trait-object vtables and instance counts | The program's polymorphic types and how many of each are live |
| tokio tasks | What the async runtime was doing: live versus completed tasks, their states, and the strings each held |

## Requirements

- Volatility 3. Tested on **2.28.2** (the current release). The Linux classes declare framework 2.0.0 as their
  minimum, the Windows classes 2.4.0 (they use the `vadinfo` API). The plugins import nothing outside the
  Python standard library and Volatility itself.
- Python as required by your Volatility 3 release; developed and tested on Python 3.13.
- For the image under analysis, the symbols Volatility always needs: a Linux ISF for the kernel, or Windows
  symbols (Volatility fetches the kernel PDB automatically when online; offline, point `-s` at a directory
  holding the matching JSON).
- `pyelftools` only for one of the evaluation scorers' tests (`tests/test_eval_vtables_elf.py`), not for
  the plugins.

## Installation

### Method 1: external plugin directory (recommended, no files copied)

```bash
git clone https://github.com/jeelkhatiwala/ferric  ferric            # or unpack the release archive
vol -p ferric/plugins -h | grep ferric      # the ten classes are listed
```

`-p` must point at the directory that **contains** `ferric/` (`plugins/`), not at `ferric/` itself:
Volatility imports the directory as a package. Keep only plugins under `plugins/`; Volatility imports every
`.py` it finds there, which is why the unit tests live in `tests/`.

### Method 2: inside the Volatility tree

Copy the `plugins/ferric/` directory into your Volatility installation's plugin directory
(`volatility3/framework/plugins/ferric/` in a source checkout, or the `volatility3/framework/plugins/`
directory of the installed package). The classes then load without `-p`.

## Quick start

With the demo image from the submission (`README-DEMO.md` has its hash and the expected output of all five
plugins), from the directory holding `plugins/` and `symbols/`:

```bash
vol -q -p plugins -s symbols/linux -f demo-01-seed02_tokio__1.99.0_o2_unwind_strip-symbols_remap-on.elf \
    ferric.provenance.Provenance --pid 49021
```

The last rows of that run, verbatim:

```
PID    Process          Tier        Evidence                Hits  VMAs  FileHits  AnonHits  FirstOffset
49021  seed02_tokio__1  std-dep     rustc-demangle-0.1.28   3     1     3         0         0x588221996894
49021  seed02_tokio__1  std-dep     miniz_oxide-0.9.1       2     1     2         0         0x588221995954
49021  seed02_tokio__1  std-dep     hashbrown-0.17.1        1     1     1         0         0x58822199531f
49021  seed02_tokio__1  dependency  tokio-1.53.2            38    1     38        0         0x5882219951ca
```

Then the other four, each on the same process:

```bash
vol -q -p plugins -s symbols/linux -f <image> ferric.strings.Strings --pid 49021
vol -q -p plugins -s symbols/linux -f <image> ferric.maps.Maps     --pid 49021 --explain
vol -q -p plugins -s symbols/linux -f <image> ferric.vtables.VTables --pid 49021 --objects
vol -q -p plugins -s symbols/linux -f <image> ferric.tokio.Tokio   --pid 49021
```

On that image they return 538, 6, 78 and 9 rows respectively (README-DEMO.md lists the first rows of each).
Without `--pid` every plugin scans every process; non-Rust processes are declined by the fingerprint gate
(below), which is what keeps a whole-guest scan to about ten minutes on a 98-process Windows guest.

For a Windows image use the `ferric.win.*` classes with Windows symbols:

```bash
vol -q -p plugins -s symbols/windows -f <image.elf> ferric.win.Provenance --pid <PID>
```

## The fingerprint gate, and `--force-scan`

Every Rust binary linked against the shipped standard library carries `/rustc/<40-hex-commit>/` paths in
its read-only data (the std source paths baked into panic locations). ferric's structural scanners (strings,
maps, vtables, tokio) run on a process only when its own read-only data, including its executable's code
pages, carries that fingerprint; a process without it gets one row saying so and is otherwise skipped:

```
PID   Process  Kind      ... Text
1369  <name>   compiler  ... no Rust compiler fingerprint in read-only data: not scanned (--force-scan to scan anyway)
```

This is what makes the suite silent on non-Rust programs (zero rows from every plugin on the C++ and Go
controls on both OSes and on the .NET control on Windows) and fast on whole guests. `--force-scan` scans a process regardless, for a binary built with a remapped
custom std or for measurement. `ferric.provenance` is never gated: it is the detector.

## Plugins

### provenance: `ferric.provenance.Provenance`, `ferric.win.Provenance`

Scans every readable region of the process for the path strings the Rust toolchain embeds and reports them
in tiers. The compiler tier is decoded to a version with a built-in commit table (`--commit-map` extends it;
unknown commits are reported by commit). Std-dependency paths (`/rust/deps/<crate>-<semver>/` from rustc
1.77, `/cargo/registry/src/<index>/<crate>-<semver>/` on 1.71) identify std's vendored crates, a second
compiler-dating signal measured to be one distinct set per rustc version. Dependency paths give the
program's own crates with versions. Toolchain and author paths come from the build machine (absent in
remapped builds; the compiler tier survives remapping because it comes from the shipped std, not the build).

| Option | Default | Effect |
|---|---|---|
| `--pid` | all | restrict to these PIDs |
| `--commit-map CSV` | built-in table | extra `commit,version` rows |
| `--dump-hits` | off | write every individual hit (offset, tier, string, backing) to a file per process |
| `--all-authors` | off | also report author-tier paths that carry no Rust marker |
| `--maxsize N` | 1 GiB | skip (and log) regions larger than N bytes |

Columns: `PID Process Tier Evidence Hits VMAs FileHits AnonHits FirstOffset`. Tiers: `compiler`, `std-dep`,
`dependency`, `toolchain`, `author`, and on Windows `target` (`x86_64-pc-windows-msvc` or `-gnu`, decided
from the imported C runtime and the std-dependency form; both signals agreed on 36/36 controls).
`FileHits`/`AnonHits` split each tier between file-backed and anonymous memory: on Windows a process is
called Rust only when a compiler hit is file-backed, so toolchain residue cached by other processes
(Defender scanning a Rust binary on disk, for example) is reported but not misattributed.

### strings: `ferric.strings.Strings`, `ferric.win.Strings`

Recovers string objects by their headers rather than by printable byte runs, so each row carries exact
boundaries, the length, the capacity and, for panic locations, the source position.

| Kind | Header shape | Where headers are sought | Validation |
|---|---|---|---|
| `string` | `String`/`Vec<u8>`: (ptr, cap, len), 24 bytes | heap, stack, data | ptr into heap memory; 1 <= len <= cap <= `--max-cap`; UTF-8; printable floor; on glibc the malloc chunk size agrees (`chunk` in Checks) |
| `location` | `core::panic::Location`: (file ptr, len, u32 line, u32 col) | rodata, data (and the executable's own code on a merged-text binary) | file in read-only memory ending `.rs`, UTF-8, sane line and column; the 1.89 length-includes-NUL variant is tagged `len-with-nul` |
| `str` | `&str`: (ptr, len), 16 bytes; also the `fmt::Arguments` literal-only form (ptr, len<<1\|1) | rodata, data (`--str-anywhere` adds heap/stack) | ptr into read-only memory, 1 <= len <= 4096, UTF-8, printable |
| `template` | `fmt::Arguments` byte template (rustc >= 1.93) | rodata | well-formed parse with a placeholder; reported only when the process's own code or static data refers to it |

The order of `String`'s three fields in memory is a compiler decision, not a source one (1.71 lays out
ptr, cap, len; 1.77 and later cap, ptr, len), so the plugin tests all six orders and votes per process; the
chosen layout is printed as a `layout` row. Three bookkeeping rows accompany the data rows: `compiler` (the
gate decision and the version), `layout` (the vote), and `templates` (how many template candidates were
kept and why).

| Option | Default | Effect |
|---|---|---|
| `--kinds` | all | subset of `string,str,location,template` |
| `--max-cap N` | 1 MiB | largest `String` capacity considered |
| `--min-len N` | 1 | shortest string reported |
| `--strict-chunk` | off | report a `String` only when the glibc chunk size agrees (Linux) |
| `--str-anywhere` | off | also look for `&str` headers in heap and stack |
| `--layout ORDER` | vote | force the `String` field order, e.g. `cap,ptr,len` |
| `--all-layouts` | off | emit `String` candidates under every order, tagged |
| `--all-utf8` | off | lift the printable floor |
| `--dump` | off | write every row as TSV, one file per process |
| `--force-templates` | off | scan for templates on compilers older than 1.93 |
| `--all-candidates` | off | list unreferenced templates (tagged `ref=none`) instead of dropping them |
| `--commit-map CSV`, `--force-scan` | | as above |

Columns: `PID Process Kind Header HeaderIn Ptr PtrIn Len Cap Layout Checks Text`. `HeaderIn`/`PtrIn` name
the region kind (heap, stack, data, rodata, exec) of the header and of the bytes it points to.

### maps: `ferric.maps.Maps`, `ferric.win.Maps`

Recovers hashbrown tables, the implementation behind `std::collections::HashMap` and `HashSet`. A
`RawTableInner` is four words (`bucket_mask`, `ctrl`, `growth_left`, `items`) whose order the compiler may
change, so the plugin identifies the fields by their properties in every aligned four-word window: `ctrl`
points at readable memory, `bucket_mask` is `2^k - 1`, and `items` is pinned by the control bytes. A
candidate is accepted only when the control array holds at least one EMPTY byte (a live table never fills)
and carries hashbrown's replicated group signature: the leading 16 control bytes are echoed after the last
bucket so SIMD probes can wrap. An unrelated region satisfies that echo only by coincidence; the C++, Go
and .NET controls produce zero tables. Entries are then decoded: the bucket stride is inferred from the
allocator (glibc chunk sizes on Linux, content agreement on the NT heap) and each occupied bucket is read
as typed fields (`String`, `Vec<u8>`, `u64`; the control seeds exercise `HashMap<String,String>`,
`HashMap<u64,String>`, `HashMap<String,Vec<u8>>`, `HashMap<String,f64>`, a nested
`HashMap<String,HashMap<String,u32>>` and `HashSet<String>`).

| Option | Default | Effect |
|---|---|---|
| `--min-items N` | 1 | only tables with at least N live items |
| `--explain` | off | also report structural near-misses (`near` rows) with the failed check |
| `--no-entries` | off | tables only, no entry decoding |
| `--max-entries N` | 4096 | most entry rows per table |
| `--debug-ctrl HEX` | | (Windows) print the stride candidates' scores for the table with this ctrl address |
| `--force-scan` | off | as above |

Columns: `PID Process Kind Header HeaderIn Ctrl Buckets Items Deleted Load Stride Bucket Tag Fields Note`.
Row kinds: `table` (one per table), `entry` (one per decoded bucket, `Fields` holds the typed values),
`stride` (the stride decision, with `--explain`), `near` (rejected candidates, with `--explain`).

### vtables: `ferric.vtables.VTables`, `ferric.win.VTables`

A `dyn Trait` value is a fat pointer (data, vtable), and the vtable is a static with a fixed prologue:
`[drop_in_place, size, align, method...]`. The plugin scans read-only data for that shape (a code pointer
or, from rustc 1.83, a null when the type needs no drop; then a size that is a multiple of a power-of-two
alignment; then at least one more code pointer). A plain jump table has no size/align pair and does not
match. Each candidate is corroborated by the code that uses it (RIP-relative `lea` instructions computing its
address) and, with `--objects`, by live fat pointers in heap and stack memory. Candidates in writable
module data are reported only when something references them (C function-pointer tables live there too).

| Option | Default | Effect |
|---|---|---|
| `--objects` | off | scan writable memory for live instances: `Refs` (heap) and `StackRefs` |
| `--min-methods N` | 1 | only vtables with at least N trait methods |
| `--all-candidates` | off | also report null-drop candidates nothing references |
| `--force-scan` | off | as above |

Columns: `PID Process VTable VTableIn Drop DropIn Size Align Methods CodeRefs Refs StackRefs Module Base`.
Naming the trait needs type information a stripped binary does not carry; what is recovered is the type's
size, alignment, method count, where it is used from, and how many instances are live.

### tokio: `ferric.tokio.Tokio`, `ferric.win.Tokio`

A tokio task is a heap cell whose header holds a state word, a reference count, a pointer to the task's
vtable and, in recent versions, the offsets of its own fields. The task vtable is a run of code pointers in
read-only data (poll, schedule, dealloc, ...) that is not a trait vtable (no size/align pair breaks the
run); from tokio 1.28 it is followed by the three usize offsets that let the header be located and parsed
without version-specific knowledge. The plugin finds the vtables, follows every heap and stack reference to
them, validates each referrer as a task header, decodes the state (running, complete, notified,
join-interest, join-waker, cancelled), the reference count, the task id and the scheduler pointer, and then
scans the task's future for `String` locals.

| Option | Default | Effect |
|---|---|---|
| `--min-refs N` | 1 | only vtables with at least N references |
| `--no-locals` | off | skip the `String` scan inside each future |
| `--candidates` | off | also report referenced code tables that front no task header |
| `--force-scan` | off | as above |

Columns: `PID Process Kind Table TableIn Fns Header State Flags Refs TaskId Scheduler FutureAt FutureBytes
Locals Note`. Row kinds: `vtable` (one per task vtable), `task` (a live task cell), `stale` (a cell whose
state says complete), `remnant` (a freed cell still shaped like a task), `candidate` (with `--candidates`).
Worker-thread locals are the strings each parked worker holds; the control measured 24/24 of them.

## Validation

Every figure below is produced by the scorers in `eval/` from ground truth taken from the control
programs' own source, on 45 Linux and 36 Windows memory images across rustc 1.71, 1.77, 1.83, 1.89 and
1.99, both Windows linkers, optimisation levels 0/2/3/s/z, panic=abort, stripped and unstripped builds,
path remapping, UPX packing, musl static linking and memory pressure. The full tables and the per-image
detail are in the write-up and `eval/RESULTS-*.md`.

| Capability | Linux | Windows |
|---|---|---|
| provenance: correct compiler, nothing spurious | 42/42 images | 36/36; MSVC-vs-gnu target 36/36 |
| strings: `String` / panic `Location` | 455/455, 24/24 | 402/402, 20/20 |
| strings: `&str` / fmt templates | 76/76, 63/63 | 72/72, 51/52 |
| maps: tables / key-value pairs | 72/72, 618/618 | 70/72, 701/708 |
| vtables | 1,285/1,285 confirmed against symbols, 0 false | 36/36 by shape |
| tokio: live tasks / worker locals | 36, 24/24 | 36, 24/24 |
| negative controls: non-Rust programs of the same shape | C++, Go: 0 rows, every plugin | C++, Go, .NET: 0 rows, every plugin |
| benign Rust positive (ripgrep) | not run | detected: compiler, 25 crates, strings, maps, vtables; tokio 0 (not async) |

Packed input: on a UPX-packed control, `strings` and YARA on the file find no compiler path; ferric
recovers the exact rustc version and the crate set from the process's anonymous memory. Real samples: on
Rust ransomware captured live (Linux ELF), the suite recovered the compiler, a 47-crate dependency set,
hundreds of trait-object vtables and the string and panic-site tables, and declined the three non-Rust
samples in the same batch unprompted.

## Windows notes

- The five `ferric.win.*` classes run the same recognisers over VAD regions and the main executable's PE
  sections; reserved-only private VADs (commit charge 0) are not read.
- The read-only data examined is the main executable's. Rust loaded as a DLL, or mapped without a PE header,
  is out of scope.
- A process is called Rust only on a file-backed compiler hit (see provenance above).
- Whole-guest scans: about ten minutes for all five classes on a 98-process guest with the gate; without
  it (`--force-scan`) the structural scanners can take far longer, so scope `--force-scan` with `--pid`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `no Rust compiler fingerprint in read-only data: not scanned` | The process carries no `/rustc/` path: it is not Rust, or it was built against a custom std with remapped paths. Run `ferric.provenance` first; add `--force-scan` if you have reason to believe it is Rust. |
| `vol -p` lists no `ferric.*` classes | `-p` points at `ferric/` instead of its parent `plugins/`, or a non-plugin `.py` under `plugins/` failed to import. |
| No rows at all, every plugin | Wrong OS class (`ferric.*` on a Windows image, or `ferric.win.*` on Linux), or Volatility could not resolve the kernel symbols (check `linux.pslist` / `windows.pslist` first). |
| `compiler unknown (<commit>, N hits)` | The commit is not in the built-in table; detection still holds. Add `commit,version` to a CSV and pass `--commit-map`. |
| maps reports 0 tables on a process known to be Rust | The capture may predate the tables being built (a process held at its argument check has allocated nothing yet), or the tables hold fewer than `--min-items`. `--explain` shows near-misses. |
| strings `template` rows absent on a modern build | Templates exist from rustc 1.93; on older compilers they are not scanned (the `compiler` row says so). `--force-templates` overrides. |
| A `String` row that is clearly not a string | Lower `--max-cap`, raise `--min-len`, or on Linux use `--strict-chunk`. The gate keeps such rows out of non-Rust processes; inside a Rust process the controls measured 0 to 1 extra row per image. |
| Windows run is slow | Use `--pid`; the whole-guest case without the gate is the slow path. |

## Limitations

x86-64 only. Detection relies on the `/rustc/<commit>/` fingerprint that programs linked against the
shipped std carry; a build-std binary with remapped paths needs `--force-scan`. Compiler versions are named
from a built-in commit table; others are reported by commit. Trait names and struct type names are not
recoverable from a stripped binary; sizes, layouts, method counts and instance counts are. tokio task
parsing without the self-described offsets (tokio < 1.28) falls back to candidate offsets. On Windows,
vtables are validated by shape only (no PDB for the Rust program), and the read-only data examined is the
main executable's.

## Tests

```bash
for t in tests/test_*.py; do python3 "$t" | tail -1; done
```

Twenty-one test files, each a standalone script that prints `ALL PASS`, run against synthetic memory and
need no image (one, `test_framework_scan_pagegap.py`, reproduces a Volatility framework behaviour and
prints `REPRODUCED`; one, `test_win_target_builds.py`, skips when the compiled Windows control binaries are
absent). `tests/run_tests.sh` runs them all and is what the CI workflow runs. The scorers in `eval/` are the
code behind every number in Validation; the per-image plugin outputs they read carry build-machine paths and
belong to the dataset release accompanying the paper, so they are not in this repository. Their results are
summarised per image in `eval/RESULTS-linux.md` and `eval/RESULTS-windows.md`, and every prediction made
before a run, with its outcome, is in the pre-registration log `eval/metrics.md`.

## Project layout

```
plugins/ferric/   provenance.py strings.py maps.py vtables.py tokio.py  (Linux classes and shared recognisers)
                  win.py  (the five Windows classes over the same recognisers)
tests/            unit tests (synthetic memory; no image needed) and run_tests.sh
eval/             scorers (make_table_*.py), the rustc commit-to-version table (commit_map.csv),
                  RESULTS-linux.md and RESULTS-windows.md (per-image results), metrics.md (pre-registration log)
symbols/          the kernel symbols for the demo image(s): linux/ (ISF) and windows/ (PDB-derived)
README-DEMO.md    the demo image(s): hash, commands, expected output
WRITEUP.md        motivation, method, results, limitations
.github/          the CI workflow that runs the tests against Volatility 3 from PyPI
```

## Versions

| Class | Version | | Class | Version |
|---|---|---|---|---|
| `ferric.provenance.Provenance` | 0.3.3 | | `ferric.win.Provenance` | 0.1.4 |
| `ferric.strings.Strings` | 0.4.2 | | `ferric.win.Strings` | 0.2.1 |
| `ferric.maps.Maps` | 0.5.3 | | `ferric.win.Maps` | 0.1.5 |
| `ferric.vtables.VTables` | 0.2.5 | | `ferric.win.VTables` | 0.1.5 |
| `ferric.tokio.Tokio` | 0.3.1 | | `ferric.win.Tokio` | 0.1.5 |

## Author and licence

ferric is written by Jeel Piyushkumar Khatiwala and released under the MIT License (see `LICENSE`). It was
developed as the tooling for a study of Rust memory forensics; the write-up (`WRITEUP.md`) describes the
method and the full evaluation.

## References

- Volatility 3 documentation: https://volatility3.readthedocs.io/
- Rust `core::panic::Location` (`library/core/src/panic/location.rs`) and `alloc::string::String`
  (`library/alloc/src/string.rs`) in the rust-lang/rust repository; the field-order and NUL-termination
  history above was read at the release tags.
- hashbrown (`src/raw/mod.rs`): the SwissTable control-byte layout and the replicated group.
- tokio (`tokio/src/runtime/task/`): the task header, state word and vtable.
