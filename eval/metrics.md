# metrics.md: pre-registered metrics for the ferric plugin suite

Status: REGISTERED 2026-10-08 (Session 59), before the first host run of ferric.vtables v0.2, ferric.tokio
v0.2 and ferric.maps v0.4 over the control images. EVIDENCE-STANDARD.md section 2 requires this file to
exist before an evaluation run; any later change to a definition is a DECISIONS.md entry with a reason,
never a silent edit. Every metric below is emitted by the named script from files in the release.

Conventions
- n is always reported next to a rate. "Recall" is against ground truth derived from the seed source
  (and, where stated, from the unstripped twin binary's symbols). "Precision" is against a check that is
  independent of the plugin (symbols, the seed source, or a non-Rust process that cannot contain the
  structure).
- Target process = the pid recorded in MANIFEST/images.csv. Rows in any other process of the same image
  are the negative control and are never counted toward recall.
- A plugin output that is missing or has no header line (crash, timeout) is "no usable output" and counts
  as a miss for every recall item of that image. It is never dropped from n.
- Diagnostics (maps --explain NEAR rows; tokio stale/remnant rows; vtables --all-candidates) are stored
  and reported but are never results.

## 1. ferric.provenance  (eval/make_table_provenance.py; unchanged since Session 46)
- images with a Rust target process; with a usable output; "correct compiler, no other": the recovered
  rustc commit maps (eval/commit_map.csv) to exactly the manifest's rustc_version and to no other version.
- cross-version compiler rows: images where a second compiler fingerprint was recovered (must be 0 on
  single-seed images; any non-zero value is listed with the process it came from).
- baseline image (no target): must be clean.
Overnight 20261008T034522Z baseline: 37/37 correct, 0 cross-version, baseline clean.

## 2. ferric.strings  (scripts/check_strings_truth.py; per-seed TRUTH.strings.tsv)
- recall per kind (string, location, template or str) against TRUTH.strings.tsv, by image.
- precision items, reported as counts by image, not folded into one rate:
  a. String rows not in truth (distinct texts), each classified by hand as std-runtime, stale copy, or
     false positive. Overnight: 0 on 18 of 21 seed01 images; 1 each on rsweep-01, cfgsweep-01, musl-01.
  b. template rows on images built with rustc < 1.93: the byte-coded fmt::Arguments template that the
     recognizer targets only exists from 1.93, so every template row on an older image is a false parse
     by construction. Overnight: 10 (1.71), 20 (1.77), 10 (1.83), 13 (1.89) per seed01 image. This is an
     open precision defect of strings v0.3.1 and is reported, not hidden, until a version gate is added.
  c. str rows (ptr,len pairs) are a count only; no truth exists for them beyond the 4 in TRUTH on
     1.71-1.89 builds.

## 3. ferric.maps  (eval/make_table_maps.py; per-seed TRUTH.maps.tsv)
TABLE level (maps >= v0.3)
- known map recovered: a 'table' row in the target pid whose Items equals the known live item count.
  n = known maps over control images (37 on the current manifest: seed01 cfg, seed02 settings, seed03
  areas; seed05 adds 7 maps per image once captured).
- unattributed table rows in the target pid (Items not matching any known map): listed, inspected by
  hand, counted as neither.
- negative control: 'table' rows outside the target pid on the all-process runs (5 images), by process.
  Overnight (v0.3): 0 on all 5.
ENTRY level (maps >= v0.4)
- entry recall = known (key, value) pairs found / known pairs, where a pair is found when an 'entry' row
  of the recovered table decodes its key and value with the right types (String exact; u64 exact; u32 on
  the low 32 bits; f64 within 6 significant digits; Vec<u8> by bytes; a nested HashMap by its item count;
  a set by key only).
- entry precision = correct entry rows / entry rows of that table (an extra, duplicated or mis-decoded
  entry row counts against precision).
- stride source: how many tables had their stride pinned by the allocator (glibc chunk size) versus by
  content (musl, jemalloc, custom allocators), by image.
Sandbox pre-registration run (live processes, rustc 1.97, glibc): seed01/02/03 entries 7/7, seed05 114/114,
precision 1.000. The host run over 1.71/1.77/1.83/1.89/1.99 images is the first measurement across
compiler versions; a drop on 1.71 (String field order ptr,cap,len) is the expected sensitivity.

## 4. ferric.vtables  (eval/make_table_vtables.py; unstripped twins from MANIFEST/binaries.csv)
- precision = confirmed rows / rows in the target binary, where a row is confirmed when, at
  VTable - Base in the unstripped twin (relocations applied), the drop slot is null or the start of a
  drop_in_place function and every counted method slot is the start of a function. The twin is used only
  when its PT_LOAD bytes equal the captured binary's; otherwise the image is "unscored", reported as such.
- recall = known trait objects recovered / known, with known = seed01 <usize as Display> (size 8, align 8,
  1 method; method symbol carries Display and fmt) and seed03 <Circle|Rect|Triangle as Shape> (size
  32/40/40, align 8, 2 methods; symbols carry the type name, Shape, name, area). seed02's tokio vtables
  are not enumerable from the source and contribute to precision only.
- drop form: confirmed rows with a null drop slot versus a function, by rustc version. Expected from
  rust-lang/rust PR 122662: null forms only on rustc >= 1.79, i.e. on the 1.83, 1.89 and 1.99 images,
  none on 1.71 and 1.77. This is a prediction written before the run.
- rows in other modules (libc and friends) are counted and listed, not scored.
- negative control: rows outside the target pid on the all-process runs, by process and module. A C++
  vtable ([offset-to-top, typeinfo, methods...]) fails the align gate, so the prediction is 0; any row is
  listed with its module so it can be explained or counted as a false positive.
Sandbox pre-registration run (rustc 1.97, stripped binaries, twins by symbols): 171/171 confirmed,
precision 1.000, recall 4/4, null/fn = 111/60.

## 5. ferric.tokio  (eval/make_table_tokio.py; seed02 only)
- task rows: live, validated task headers in the target pid (kind=task).
- parked rows: task rows carrying join-interest and not complete (the four spawned workers hold their
  JoinHandles in main; none has completed).
- worker recall = distinct worker-0..worker-3 found in the Locals of parked rows / 4, scored only on
  images whose task vtable publishes the trailer/scheduler/id offsets (tokio >= 1.28; the controls run
  tokio 1.53.2). scheduler-name recall = parked rows that also carry "seed02-scheduler" / 4.
- unattributed task rows (the runtime's own tasks, blocking-pool cells): listed, counted as neither.
- negative control: rows outside the target pid on the all-process runs, by process and kind. Prediction:
  0 task rows; vtable/candidate rows in non-tokio processes are candidate false positives and are listed.
Sandbox pre-registration run (tokio 1.0.3 to 1.53.2): 4 parked workers on every version; locals 4/4 on
>= 1.28; 2 unattributed running tasks (state 0x81) on 1.53.2, believed to be the runtime's blocking-pool
cells; not yet attributed to source, so reported as unattributed.

## 6. What is NOT measured yet (so nobody reads silence as success)
- Real-sample images (det-*): the plugins are run and the outputs stored, but no ground truth exists;
  only provenance has a defensible real-sample result (Session 52-54). maps/vtables/tokio rows on real
  samples are observations until an independent check (debugger on a detonation, or the sample's own
  configuration format) is attached.
- Windows images: every metric above is Linux x86-64 only until a Windows control exists.
- Volatility version sensitivity: one release (2.28.2) so far.
- Go / C / C++ / .NET negative controls as whole images: the all-process runs on the Linux controls
  cover the non-Rust userland of Ubuntu 24.04 (systemd, udevd, python3, ...), not those runtimes.

## Addendum 2026-10-09 (Session 60), after the first host run (sweep 20261008T132704Z)
Nothing above is redefined. Three items are added and one scorer detail is made explicit:
- tokio: `runtime worker cells` is a new reported quantity. A live task row in state RUNNING with 2
  references, owner_id 0 and a task id lower than every parked user task is the scheduler's own worker
  thread, launched through the blocking pool (measured live in Session 59: 2 such cells with
  worker_threads = 2, 3 with worker_threads = 3). Expected on seed02: 2 per image. Where
  pslist_threads.txt exists, the count of tokio-rt-worker threads is printed as an independent check.
  The former "unattributed" count now excludes these cells; on the 6 seed02 images it is 0.
- tokio: candidate (non-task) code tables are no longer in the default output (plugin v0.2.1,
  --candidates shows them). The negative control therefore counts task rows and vtable rows outside the
  target; candidate rows are a diagnostic. On the first run: 3 candidate rows per image, all in udisksd
  and unattended-upgrades, 0 task rows, 0 vtable rows outside the target.
- vtables: the `drop form by rustc version` table is reported over ALL rows in the target module as well
  as over symbol-confirmed rows, because the first run could confirm nothing (twin comparison, below) and
  the prediction only needs the plugin's own Drop column. Result: 1.71 0/264 null, 1.77 0/224, 1.83
  168/243, 1.89 142/210, 1.99 619/922. The prediction (null only on rustc >= 1.79) held.
- vtables scorer: the twin comparison masks the ELF header and the .note.gnu.build-id payload (a stripped
  link's build-id hashes different input, so it always differs); a residual mismatch is printed with the
  sections it lands in. The first run reported MISMATCH on all 20 twinned images for this reason alone,
  so precision/recall by symbols is still unmeasured on the host; the re-run after this addendum is the
  measurement. s3sweep-01/-02 will stay MISMATCH on purpose: their manifest target_binary_id names the
  1.71/1.77 builds while the images ran the 1.99 build (notebook Session 29; manifest fix pending).
- vtables plugin v0.2.2 also scans the executable's writable file-backed data, because musl-01 (static-pie,
  no RELRO applied by musl's self-relocation) returned 0 of 45 vtables under v0.2.1. The negative control
  is re-run for v0.2.2; the prediction stays 0 rows outside the target.

## Addendum 2026-10-09 (Session 61), after the second host run (sweep 20261009T112409Z)
- vtables plugin v0.2.3: a candidate found in WRITABLE module data is reported only when referenced
  (CodeRefs, Refs or StackRefs >= 1). Reason, measured: v0.2.2's writable-data scan (the musl fix) also
  surfaced 8 rows per image in rsyslogd, a C program, all of the shape [fn, size 0, align 2, 15 fns] with
  no reference of any kind. Cost, measured: 1 of 45 musl-01 vtables, one that no code or object uses (its
  glibc twin row has no reference either). The negative-control prediction for vtables therefore stays
  "0 rows outside the target", now for v0.2.3; the v0.2.2 run that violated it is kept in the sweep
  outputs as the failure case the standard asks for.
- vtables scorer: the first symbol-scored run on the host crashed on the first twinned image
  (AttributeError: 'Elf' object has no attribute 'words'; a Session 60 edit displaced two methods out of
  the class, and the sandbox validation after that edit never reached the twin path because the sandbox
  holds no control binaries). tests/test_eval_vtables_elf.py now exercises that path; the scorer was
  re-validated end to end on stripped binaries with twins (171/171 confirmed, 4/4 recovered). Symbol-scored
  precision and recall on the host are still unmeasured; the Session 61 host commands produce them from
  the outputs already on disk.
- tokio: runtime worker cells 12/12 with the thread-list check agreeing on 6/6 images; negative control
  0 rows of any kind outside the target on 5 images (candidate rows off by default). No change.
- Windows: ferric.win (five plugin classes over VAD/PE-section regions) and provenance 0.3.1 (either path
  separator after /rustc/<hash>) ship untested on any image; every metric above is defined per OS and the
  Windows numbers start at 0/0 until win-img01 exists.

## Addendum 2026-10-10 (Session 62), after the first symbol-scored vtables run on the host
- vtables scorer, twin handling: a twin whose loaded bytes are not identical to the captured binary is
  no longer refused; each row is verified locally instead (the vtable's own words and the first 32 bytes
  of every function it points to must be identical in both files), and the image is reported as
  "local:<where the files differ>". Measured need: seed01's strip-none/strip-symbols pairs on the 1.71,
  1.77 and 1.83 toolchains differ in 17-18 64-byte chunks of .text plus .eh_frame; seed03's pairs on the
  same toolchains are identical. A row that fails the local check is a false row, as before.
- vtables scorer, stale binaries: when more than half of an image's rows fail the symbol check, the
  image is reported as STALE-BINARY? and excluded from precision (a real false-positive rate above 50%
  would contradict every other image). First run: s3sweep-01 and s3sweep-02, whose target_binary_id
  named the planned 1.71/1.77 builds while the images ran the 1.99 build (Session 29). Their 89 "false"
  rows were the 1.71/1.77 twins' symbols applied to a 1.99 process. scripts/fix_manifest_s62.py corrects
  the ids; after it, both images score against the right twin.
- First symbol-scored result, host, 2026-10-09 (outputs of sweep 20261009T112409Z, scorer before the
  local-verification change): 15 images with an identical twin, 679 rows, 679 confirmed, 0 false
  (precision 1.000 on every one of 1.71, 1.77, 1.83, 1.89, 1.99); known trait objects 26/27, the one miss
  <Triangle as Shape> on s3sweep-04 (rustc 1.89), under diagnosis (the scorer now prints the rows that
  match its shape or carry its name). 20 images unscored: 17 for lack of a recorded binary (manifest), 3
  seed01 twins non-identical (now scored locally).

## Addendum 2026-10-10 (Session 63), after the v0.2.3 negative control and the symbol-scored detail
- vtables plugin v0.2.4: a method run also ends at an address that code references directly (the
  RIP-relative LEA targets, collected in the same pass that produces CodeRefs). Measured need: on rustc
  1.89 the <Triangle as Shape> vtable is followed by a lone function pointer that no header check can
  separate from the run, so the plugin reported 3 methods for a 2-method trait and the recall matcher
  missed it (s3sweep-04). Checked against DWARF on the three sandbox seeds (32 described vtables):
  method counts exact for 29/32 under v0.2.1 and 32/32 under v0.2.4; the three corrections are the
  dyn Fn closure vtables of std::rt::lang_start and tokio's runtime builder (4 -> 3) and <u64 as Debug>
  (2 -> 1); no vtable lost a method it has. Symbol precision unchanged (171/171).
- vtables scorer: a row whose twin bytes differ locally (vtable words or a function prologue) is
  "unverifiable", reported in its own count and excluded from both precision terms; it is not a false
  row. First instance: 1 row on vsweep-02. A known trait object matched only by a row with extra method
  slots is reported as "found with an over-counted method run" and NOT credited to recall.
- Negative control, vtables v0.2.3 (sweep 20261010T002738Z): 0 rows outside the target process on all
  5 whole images (the rsyslogd rows of v0.2.2 are gone); musl-01 44 rows. The prediction holds again.
- Corpus: s3sweep-01/-02 ran an earlier 1.99 seed03 build that was overwritten; their binary is "not
  held" (scripts/fix_manifest_s63.py). They stay in every table that needs no binary.

## Linux control result for ferric.vtables, recorded 2026-10-10 (Session 64; sweep 20261010T004724Z, plugin v0.2.4)
- precision: 819 rows in the target binary on 18 twinned images, 819 confirmed by symbols, 0 false,
  1 unverifiable (1.000 on each of rustc 1.71, 1.77, 1.83, 1.89, 1.99).
- recall: known trait objects 30/30 (seed01 <usize as Display> on 13 images; seed03 Circle, Rect,
  Triangle on 17 images... counted per scored image: 4/4, 4/4, 7/7, 4/4, 11/11 by version); shape-only
  19/19 on the 19 images without a held or twinned binary.
- drop form: null only from rustc 1.83 on (0 of 488 rows on 1.71/1.77; 168/243, 142/210, 650/966 on
  1.83, 1.89, 1.99), as predicted before the first run from rust-lang/rust PR 122662.
- negative control: 0 rows outside the Rust target on 5 whole images (v0.2.3 and v0.2.4).
- method counts: v0.2.4 changed 5 of 1907 rows across the 37 images relative to v0.2.3, all reductions
  (3->2 on the s3sweep-04 Triangle vtable; 5->1, 8->1, 2->1, 2->1 on seed02 images), consistent with the
  DWARF check in the sandbox (32/32 exact after, 29/32 before).
- survival: the same vtables are recovered through strip, --remap-path-prefix, opt levels 0/2/3/s/z,
  panic=abort, memory pressure, UPX (in the unpacked anonymous image) and musl static-pie (44/45, in
  writable data).
These are the numbers the paper's vtables table regenerates from `python3 eval/make_table_vtables.py`.

## Addendum 2026-10-10 (Session 65): strings template gate, strings truth for three seeds, survival matrix, reproducibility
- strings plugin v0.3.2 resolves precision item 2b by construction: fmt templates are scanned only when
  the process's own /rustc/<commit>/ paths identify a compiler >= 1.93 (ferric.provenance's commit table,
  plus --commit-map); an older compiler gets a 'compiler' row saying why no template rows follow;
  an unknown compiler is scanned and tagged. --force-templates restores the old behaviour for
  measurement. Template recall on >= 1.93 images is unchanged (the recogniser is the same); the
  false-parse count on < 1.93 images goes from 10-20 per image to 0 by design. Logged as D-017.
- strings ground truth now exists for seed02 and seed03 (TRUTH.strings.tsv written from the sources and
  matched on the 2026-10-08 outputs: seed02 strings 12/12 on all five versions, templates 4/4 on 1.99,
  &str pieces 4/4 on 1.71-1.89; seed03 strings 6/6, templates 2/2, pieces 4/4) and for seed05 (unverified
  until it is captured). A measured survival fact goes into seed03's truth: its Option::expect Location
  record exists on 1.71 and 1.77 and is absent from 1.83 on (the optimizer folds the None branch of
  first() on a 3-element vec!), while seed01's HashMap::get().expect() Location survives on every
  version. The location metric therefore applies per compiler version where the record exists.
- eval/make_table_survival.py: the survival matrix (21 conditions x 5 plugins) regenerated from the
  saved outputs; eval/run_all.sh regenerates every table into eval/tables/<ts>/ with a sha256 list;
  every plugin output written by plugin_sweep.sh from now on carries a .meta sidecar (plugin hash,
  Volatility version, command), and scripts/write_meta_sidecars.py backfills the existing ones from the
  sweep logs (outputs made by hand before the sweeps are marked as such).
- A strings negative control is added to the sweep (all processes on the 5 control images): String,
  &str, Location and template rows in non-Rust processes are candidate false positives; prediction before
  the run: Location and template rows 0 (they need Rust-specific byte layouts), String rows few but not
  necessarily 0 (a 3-word (cap, ptr, len) shape with a readable UTF-8 target can occur in a C heap),
  reported by process.

## Addendum 2026-10-10 (Session 66): negative-control programs; provenance author tier tightened
- Three negative-control programs are added under control-corpus/negatives (C++17 with virtual classes
  and std containers, Go 1.24 with maps and goroutines, .NET 8 with Dictionary/List/Tasks), each shaped
  like the Rust seeds and holding at t1, with the prediction for every plugin written in its README
  before any capture. Run live in the sandbox before capture (C++ and Go): maps 0, vtables 0, tokio 0,
  provenance 1 row each, which was the finding below.
- provenance plugin 0.3.2: the author tier accepts only source-directory markers (.cargo/registry,
  .cargo/git, .rustup/toolchains, /target/, .rs) and rejects a path that is an element of a PATH-like
  list. Reason, measured: a shell with rustup puts ~/.cargo/bin into PATH, and that string sits in the
  environment block of every process started from it, so a C++ or Go process reported an "author"
  record (user name from the PATH). After the change: 0 provenance rows on both negative controls; the
  Rust seed keeps its compiler and std-dep tiers. Consequence for the tables: the compiler tier
  (37/37) is untouched; author rows on seed images that came from the environment block disappear on
  the re-run, which is correct (they described the capture host, not the binary). The negative control
  for provenance (all processes, 5 images) is added to the sweep; prediction: 0 compiler, 0 std-dep,
  0 author rows outside the Rust target.

## Addendum 2026-10-10 (Session 67): strings negative control read out; strings 0.4.0 gates pre-registered
Read-out of the two host runs made with the Session 65/66 code (strings 0.3.2, sweep 20261010T031415Z;
provenance 0.3.2, sweep 20261010T033130Z), against the predictions written in the two addenda above:
- strings truth, 0.3.2: string 390/390, location 24/24, &str pieces 36/36 (rustc <= 1.92 images),
  template 58/58 (rustc >= 1.93 images); a 'compiler' row on all 37 targets; 0 template rows on the 17
  images built by 1.71 to 1.89. Prediction held (precision item 2b closed by construction).
- provenance negative control: 0 rows of any tier in any process other than the Rust target on all 5
  all-process images (lin-img00-t0: 0 rows in 27 processes). Prediction held. Author rows on the 37
  targets went from 12 to 6 with 0.3.2; the 6 that remain are the six seed02 images, user name from
  tokio's registry source paths compiled into the binary (38 to 46 file-backed hits each), which is the
  record the tier is for. The compiler table is unchanged (37/37, 0 cross-version).
- strings negative control, 0.3.2 (27 non-Rust processes per image, 5 images): Location rows 0 on every
  image, as predicted. Template rows 440 per image (335 with one literal byte, 19 with two, 86 with
  three or more; 274 of them the same '({:...}' parse inside systemd-udevd), against a prediction of 0:
  WRONG. String rows 6,385 to 6,410 per image (bash 4,226 to 4,229, systemd 1,241 to 1,255, sshd 233),
  of which 892 to 896 (14%) pass the glibc chunk check, against a prediction of "few": WRONG by three
  orders of magnitude. &str rows 3,835 per image (3,696 on musl-01), one- and two-byte texts in the
  main. Inside the Rust targets the same heuristics are precise: String rows outside the truth 39 over
  37 images (seed01 3, seed02 22, seed03 14; unverified, most of seed02's are runtime-owned), and
  seed01 at 1.99 reports exactly its 12 truth Strings on 12 of 14 images (cfgsweep-01 and musl-01 carry
  one extra row each). The template parser is the
  weak one even there: 1,460 template rows over the 20 rustc-1.99 images, 568 with one literal byte.
- Conclusion: the header heuristics separate Rust from non-Rust only when they are run inside a Rust
  process. Two gates follow (strings 0.4.0, D-018), both decided from the image itself:
  (1) a process is scanned only when its read-only data carries the /rustc/<commit>/ fingerprint
      (the provenance compiler tier, already computed per process for D-017); without it the plugin
      emits one 'compiler' row that says so, --force-scan scans anyway;
  (2) a fmt template is reported only when something in the process refers to it: a RIP-relative LEA in
      executable memory computes its address (rustc builds a fmt::Arguments that way; the vtables
      plugin's LEA pass is reused) or a word in read-only, writable or stack memory holds it;
      --all-candidates lists the rest tagged ref=none; when no LEA decodes anywhere (code pages absent)
      the candidates are kept and tagged ref=unverifiable.
  Measured live before pre-registration, seed01 built with rustc 1.97 (sandbox): 70 template candidates,
  35 referenced (all by LEA, 2 also by a data or stack word), all 3 truth templates among them; the 35
  unreferenced are 32 one-literal-byte parses and 2 long false spans (67 and 422 literal bytes). bash on
  the same machine: 5 candidates, 0 referenced; 63 String rows (22 chunk-consistent) without gate (1),
  one 'compiler' row with it.
- Metric definitions, restated for the strings table (eval/make_table_strings.py, new):
  recall per kind as before; template candidates -> kept per image from the plugin's 'templates' row;
  the negative control is reported twice and both numbers go into the paper: GATED (the default run;
  rows beyond 'compiler' outside the target) and UNGATED (--force-scan --all-candidates; what the
  heuristics alone report, with the reference gate's residue = templates in non-Rust processes that
  something refers to). Every output is marked as produced by the current strings.py or an older one
  from its .meta sidecar, so stale rows cannot pass as current.
- Pre-registered for the 0.4.0 re-run (strings only, same 37 images, same 5 all-process images):
  P1 truth unchanged: string 390/390, location 24/24, &str 36/36, template 58/58; every truth template
     carries lea:N (ptr:M allowed in addition); none tagged ref=unverifiable; none dropped.
  P2 template candidates -> kept over the 20 rustc-1.99 images: kept 45% to 60% of the 1,460
     candidates; kept rows with one literal byte at most 3 per image.
  P3 GATED negative control: 0 of 27 non-target processes scanned on each of the 5 images (none carries
     the fingerprint; the provenance negative control already found 0 compiler rows there); 0 rows
     beyond 'compiler'. If a non-target process IS scanned, it is a Rust-built component of the guest
     and gets written up as a finding, not patched around.
  P4 UNGATED negative control: String and &str rows within 2% of the 0.3.2 counts (the heuristics are
     unchanged), Location 0, template candidates 440 per image, referenced templates at most 5 per
     image (expected 0), unverifiable 0.
  P5 no ref=unverifiable row on any control image, pressure-02 included (vtables v0.2.4 decoded LEAs
     there).
  P6 runtime: per-image run <= 30 s; the gated all-process run faster than 0.3.2's 54 to 58 s (27 of 28
     processes skip the scan); the ungated run <= 120 s per image.
  Items 2a and 2c of section 2 stay as counts; item 2b stays closed. What P1 to P6 cannot show: the
  gates' behaviour on real samples whose std paths were removed (build-std plus remapping), which is
  the --force-scan case and a stated limit.

## Addendum 2026-10-10 (Session 68): strings 0.4.0 re-run read out against P1 to P6 (sweep 20261010T052555Z)
Preflight hashes equal the delivered files (strings.py 95042c3c, win.py 3e64780b); 13 test files passed on
the host; no timeouts or errors. All 37 outputs carry the current plugin hash in their sidecar.
- P1 HELD. string 390/390, location 24/24, template 58/58; every truth template carries lea:N
  (seed01 "lea:1,ptr:1 / lea:1,ptr:1 / lea:8", seed02 "lea:1 / lea:2 / lea:2 / lea:1", seed03
  "lea:1,ptr:1 / lea:1,ptr:1"), none unverifiable, none dropped. &str pieces 68/68, where the prediction
  said 36/36: the prediction was computed in the sandbox, which lacks seed01's TRUTH.strings.tsv (its 4
  pieces on 8 pre-1.93 seed01 images are the missing 32). A denominator error in the prediction, recorded
  as such; recall is complete under either count.
- P2 HELD. 1,460 candidates -> 799 kept (54.7%) over the 20 rustc-1.99 images; 57 to 59% on 19 of them
  and 25% on musl-01 (149 candidates from the statically linked libc and std read-only data, 37 kept).
  Kept rows with one literal byte: at most 2 per image, 39 in all.
- P3 HELD. 0 of 27 non-target processes scanned on each of the 5 images (every one gets the "no Rust
  compiler fingerprint" row); 0 rows beyond 'compiler'.
- P4 HELD, with the residue measured. Ungated counts identical to 0.3.2 (String 6,385 to 6,410 with 14%
  chunk-consistent; &str 3,835, 3,696 on musl-01; Location 0; template candidates 440 with 335 single-
  literal-byte parses). Referenced templates in non-Rust processes: 1 per image, the same row every time:
  cron, '{:...}{:...}_', one literal byte, kept by one data pointer (ptr:1) with no LEA. Residue of the
  reference gate: 1 of 440 candidates (0.2%); the prediction allowed up to 5 and expected 0.
- P5 HELD. 0 ref=unverifiable rows anywhere, pressure-02 included.
- P6 HELD. Per-image runs 14 to 18 s; gated all-process runs 20 to 25 s (0.3.2: 54 to 58 s); ungated
  runs 52 to 57 s.
- Observation, no decision taken: no true template in the corpus is kept by a data pointer alone (every
  one of the 799 kept rows has a LEA; ptr appears only in addition), and the single residue is ptr-only.
  A rule "LEA required, ptr-only listed as candidate" would remove the residue at no measured cost, but
  a promoted static fmt::Arguments would be ptr-only by construction and none has been observed yet; the
  question is parked until the Windows images and the real-sample re-run add evidence.
- Scoring defect found and fixed: strings_truth.txt for the 5 all-process images was scored from the
  newest --dump TSV, which the ungated run (--all-candidates) had written after the target-pid run, so
  its "plugin rows" line shows template=65 for vsweep-05 while the table output has 38. Recall figures
  are unaffected (the truth templates are in both; eval/make_table_strings.py scores the table output and
  agrees), but the scored file was the wrong one. From now on the all-process runs write no TSV and the
  checker scores ferric_strings.txt first (the file with the .meta sidecar), TSV only as a fallback.
- Scorer classes added for the negative-control programs (eval/ferric_out.image_class: rust, baseline,
  negative, benign): recall tables score 'rust' images only; eval/make_table_negatives.py scores the
  neg_* programs per plugin, every row in their process a false positive by construction, and the benign
  Rust binary as observations. Pre-registered for the first C++ and Go captures (per their READMEs):
  provenance 0 rows; strings one 'compiler' row "no Rust compiler fingerprint ... not scanned" and 0
  other rows; maps 0 tables (Go >= 1.24 is the case to look at: a table row there is a finding to report
  either way); vtables 0; tokio 0.

## Addendum 2026-10-11 (Session 71): negative programs and seed05 read out; tokio 0.3.0 and maps 0.4.1 pre-registered
Negative programs (sweep 20261010T202126Z; neg-01-neg_cpp with g++ 13.3.0, neg-01-neg_go with Go 1.27.2):
- provenance 0 rows on both; strings "not scanned (no fingerprint); 0 rows" on both (D-018's gate on a
  non-Rust program for the first time); maps 0 tables on both, Go 1.27's SwissTable-derived maps
  included; vtables 0 on both. Predictions held.
- tokio: 0 on C++, 45 rows on Go (10 vtable, 15 task, 20 remnant) against a prediction of 0: WRONG.
  Read from the rows: every "vtable" is a Go method table (itab fun array) in the binary's read-only
  data, referenced from heap interface values; the "task" cells passed the 0.2.1 header checks because
  those checks were loose: the ref-count bound was 1<<20 (the Go cells read 74,893 to 89,516 where real
  cells read 2 or 3), the flag check `state & 0x3F > 0x3F` was a tautology that never rejected, the
  state words were data-segment addresses (0x492360 .. 0x576b00), the owner word was unchecked for the
  legacy layouts, and the legacy layouts (vtable at +32 / +40) were chosen by "most references validate",
  a race the loosest layout wins. Five cells with state 0x101 (refs 4, RUNNING) survive the ref bound;
  their owner words point into the data segment.
- tokio 0.3.0: refs in 1..4096 (measured 2 to 3 on 36 live cells; Go look-alikes 74k to 89k); the state
  word must not be an address in a mapped region; RUNNING and COMPLETE never together; the word after the
  vtable pointer must be a small owner_id at +16, a small owner_id or a heap pointer (the 1.1 .. 1.7
  scheduler Arc) at +32, null or a heap/data pointer at +40; and the OwnedTasks doubly linked list is
  read back: a non-null prev/next link must point back at the cell (Pointers<Header> at header+8 for
  the +32/+40 eras, inside the trailer for 1.28+). A legacy-era table (no self-described offsets) is
  reported only when at least one of its cells is linked; lone legacy cells appear with --candidates,
  with a histogram of why the other references were rejected. Unit tests cover the linked, lone and
  bad-link cells and the four Go-shaped rejections.
seed05 (sweep 20261010T224638Z; s5sweep-01..04 for rustc 1.71 .. 1.89; the 1.99 build or capture is
missing and is queried): maps tables 28/28 (7 per image), pairs 427/428 (107 per image): the one miss is the nested map's
'west' value on 1.71, decoded as String "L`"(cap 7) instead of HashMap ctrl=... items=5, because the
1.71 field order (ctrl, bucket_mask, growth_left, items) reads as a String (ptr, cap, len) when the
first growth_left control bytes are printable, and the String reading ran before the cross reference.
Strings truth for seed05 (written from the source in Session 65, unverified until now): String 13/13
and &str pieces 2/2 on all four images; the truth file stands as written.
- maps 0.4.1: the nested-table cross reference (ctrl and bucket mask leading the four-word struct, either
  order) is tested before the String reading; a String key followed by a nested table's ctrl word is
  still read as String then HashMap (the ctrl must lead the struct). Unit tests for both.
Pre-registered for the re-run (PLUGINS="tokio maps", all images):
  T1 seed02 unchanged: 36 live task rows over 6 images, worker locals 24/24, runtime worker cells 12/12,
     thread check 6/6; no cell rejected (the vtable rows keep live=... counts of 0.2.1); every task note
     carries list=linked or list=lone (which of the two is reported, not predicted).
  T2 neg_go: 0 vtable, task, stale and remnant rows (candidates only with --candidates); neg_cpp 0.
  T3 all-process negative control: 0 rows outside the target on the 5 images (as 0.2.1).
  M1 maps tables 65/65 (37 + 28), pairs 511/511; s5sweep-01 nested 2/2; the earlier 83/83 unchanged;
     negative control 0 tables outside the target; neg_cpp and neg_go 0 tables.
  M2 if s5sweep-05 (1.99) exists by then: 7/7 tables, 107/107 pairs, strings 13/13 with templates per
     its truth.

## Addendum 2026-10-11 (Session 72): tokio 0.3.0 and maps 0.4.1 re-run read out (sweep 20261011T010156Z)
Preflight hashes equal the delivered files (tokio.py f1f03cd9, maps.py bf8337e1); 14 test files passed
on the host; no timeouts or errors; 44 images at the start (the 1.99 seed05 image was captured during
the run and is scored in the follow-up sweep).
- T1 HELD. seed02: 12 task vtables, 36 live task rows, worker locals 24/24, runtime worker cells
  12/12, thread check 6/6, 0 unattributed; the vtable rows keep the 0.2.1 counts (2 vtables, 6 tasks,
  1 to 2 stale, 0 remnants per image). Every task note reads list=lone: tokio 1.53's OwnedTasks is
  a sharded list (8 shards for two workers) and the seed's 4 user tasks land in different shards, so
  no cell has a non-null link. Consequence, stated plainly: the back-link check is exercised by the
  unit tests only, not yet by a real cell; a control with more tasks than shards (9 or more) would
  produce linked cells and is noted for seed02's t2 or a later seed.
- T2 HELD. neg_go: 0 rows of any kind (the file holds the header only); neg_cpp 0.
- T3 HELD. 0 rows outside the target on the 5 all-process images.
- M1 HELD. maps tables 65/65 scored (72 known; the 7 of the 1.99 seed05 image had no output yet),
  pairs 511/511, s5sweep-01's nested map 2/2 (1.71: 116/116), the earlier 83/83 unchanged, 0 tables
  outside the target on the 5 all-process images, 0 tables on both negatives.
- M2 HELD (follow-up sweep 20261011T025629Z on s5sweep-01-seed05_maps__1.99.0, whose id carries "01"
  because capture_matrix.sh numbers per invocation; ids stay unique through the binary name): 7/7
  tables, 107/107 pairs, so the maps table now reads 72/72 known tables and 618/618 pairs over the five
  rustc versions and five seeds' worth of images; strings 13/13 and templates 5/5 (seed05's truth,
  written blind in Session 65, holds on all five versions); vtables 52/52 confirmed against the
  unstripped twin pulled from the guest, 0 false; provenance correct (47 hits); tokio 0 rows.

## Addendum 2026-10-11 (Session 74): the first Windows image pre-registered (W-D on rustvictim-win)
Written before win-img01 exists. Guest: Windows 11 10.0.26300, 6 GB, seed01_collections built with the
1.99.0 MSVC host toolchain (commit b940084d7, the same commit the Linux 1.99.0 toolchain carries, so
provenance.KNOWN_COMMITS needs no addition), strip=symbols, held at t1, captured with virsh dump. The
region builder in plugins/ferric/win.py (VADs split by PE sections, TEB stacks, PEB image base) has
never run on an image; every scanner behind it is the Linux code. Predictions, to be read out in the
Session 75 addendum:
- G1 (stock Volatility gate): windows.info parses the image with the auto-fetched PDB; windows.pslist
  lists `seed01_collect` under the PID Start-Process returned. A failure here is a symbol or capture
  problem, not a plugin result.
- G2: `strings | grep "mode must exist"` finds the seed's panic message at least once (the .rdata of a
  held process is resident).
- G3 (naive baseline): `strings -n 8 | grep -c /rustc/` over the whole image is at least the compiler
  hit count ferric.win.Provenance reports for the PID (the plugin's hits are a subset of the image's);
  the number itself is recorded, not predicted.
- P1 ferric.win.Provenance --pid: exactly one compiler row, `rustc b940084d7e = 1.99.0`, Hits >= 1,
  0 cross-version rows; the hits sit in file-backed regions of the executable's own image (FileHits
  >= 1), because the fingerprint strings live in .rdata. Not predicted: the hit count (45 on the Linux
  1.99 seed01 images; Windows-built std is a different binary) and the std-dep / toolchain / author
  rows, which are recorded as the first Windows observation. Separator check: the matched text is
  expected to read `/rustc/<hash>\library\core\<file>` (backslash after the remapped prefix, the win.py
  header note), which the 0.3.1 pattern accepts; if the slash form appears instead, that is a finding
  about how the Windows std was built, also to record.
- S1 ferric.win.Strings --pid: the process passes the fingerprint gate (the compiler pseudo-row says
  scanned); String 12/12, Location 1/1, templates 3/3 against seed01's TRUTH.strings.tsv, every truth
  template with a lea:N reference (the RIP-relative LEA decoder is ISA-level and the .text section is
  the X region). String data pointers must classify as HEAP (NT heap segments are private committed
  VADs); a String row whose PtrIn is not HEAP, or a Location/template miss, is a region-builder
  finding. The Location text is expected as `src\main.rs:<line>:<col>` (cargo's relative path on
  Windows); scripts/check_strings_truth.py compares on forward slashes and takes line and column from
  the end as of this session (15 of 15 Linux images with the host's outputs in the sandbox re-scored
  identically after the change, including both s3fix location truths).
- M1 ferric.win.Maps --pid: seed01's known map `cfg` found, 2/2 pairs, stride inferred by content (no
  glibc chunk header in front of NT heap blocks; stride_by_chunk returns None and the content rule
  takes over, as on musl).
- V1 ferric.win.VTables --pid: the known trait object 1/1 by shape, rows in the executable's .rdata
  region. Symbol confirmation against an unstripped twin is not available on Windows yet
  (make_table_vtables.py reads ELF symbol tables; a PE/PDB reader is a later addition), so every
  Windows vtables figure is shape-only until then and is labelled so.
- T1 ferric.win.Tokio --pid: 0 rows (seed01 has no runtime).
- N1 (all processes, no --pid, time permitting on a 6 GB image): the strings fingerprint gate scans 0
  non-target processes. If a Windows system process is scanned, its compiler row is a finding, not a
  bug: Microsoft has shipped Rust-built code in Windows since 2023 (kernel-side GDI region code,
  announced by Microsoft at BlueHat IL 2023), and whether any user-mode process of build 26300
  carries a /rustc/ fingerprint is unknown and is exactly what this control measures; such a row is
  recorded with the process name and the commit, and the image is kept as a baseline for the
  negative-control tables.
- N2: maps, vtables and tokio report 0 rows outside the target PID. Windows user land carries far
  more C++ vtables (COM) than the Linux baseline's 27 processes; the Linux C++ negative read 0 rows,
  and this is the first test at Windows scale, so a non-zero count is reported with the process and
  the row kind, not explained away.

## Addendum 2026-10-11 (Session 75): the Windows baseline image exists before the first seed image
The first W-D attempt captured the provisioned guest with no seed running (the build had been refused
by the client's Restricted execution policy and the pid variable was empty). That image is recorded as
win-img00-t0 (pid 0, target none), the Windows twin of lin-img00-t0, captured with the guest clock
still three hours ahead (noted in its manifest row; the clock was corrected before win-img01).
- Measured on it already: `strings -n 8 | grep -c /rustc/` = 4 over the whole image. Four fingerprint
  strings on a Rust-free guest: the rustup toolchains on the guest's disk sit in the file cache. What
  the four lines are is read out in the next session (the grep is in HOST-COMMANDS-s74's block B).
- N1 and N2 of the Session 74 addendum apply to win-img00-t0 unchanged: the strings gate scans 0
  processes and maps, vtables and tokio report 0 rows on every process. A compiler row on any
  process of this image is the finding described there (Rust-built Windows components), recorded,
  not explained away. The all-process runs on this image are part of the overnight plugins phase
  (ALLPROC_IMAGES in scripts/overnight_windows.sh).
- G1 is HELD on the first attempt: windows.info and windows.pslist parsed the 6.5 GB ELF with the
  PDB Volatility fetched (ntkrnlmp.pdb C29EBFB06B78B3C020DCA66D99713F9E-1, pinned under
  symbols/windows), 98 processes listed. G2 to G3, P1, S1, M1, V1, T1 wait for win-img01.

## Addendum 2026-10-11 (Session 76): win-img01 read out against the Session 74 predictions; win.py 0.1.1
win-img01: seed01_collections 1.99.0 MSVC, strip=symbols, PID 4316, virsh dump 6,509,248,539 bytes;
plugins/ferric/win.py 3e64780b (classes 0.1.0, Strings 0.2.0); outputs analysis/win-img01.elf.vol.
- G1 HELD (windows.info, windows.pslist: PID 4316 seed01_collect among 94 processes, pinned PDB).
  G2 and G3 were run but their lines were not in the pasted terminal; read from the next upload.
- P1 HELD exactly: one compiler row, rustc b940084d7eb6 = 1.99.0, 34 hits, 1 region, FileHits 34,
  AnonHits 0, first offset 0x7ff64722a418 in the executable's image. Separator as predicted: every std
  Location reads /rustc/<hash>/library\alloc\src\str.rs:200:22 and the like (backslashes after the
  remapped prefix). No std-dep, toolchain or author rows (recorded, not predicted).
- S1 HELD: the process passed the fingerprint gate ("34 hits: templates scanned"); String layout
  chosen by vote cap,ptr,len (13 votes); the 12 truth Strings all present with their headers and data in
  HEAP (item-0 to item-7 len 6 cap 10; mode/control/targets/docx,xlsx,pdf exact caps); Location
  src\main.rs:12:29 (the expect line); the three seed templates item-{}, "{} {} {}\n" and the hold
  message each referenced by LEA; 30 of 80 template candidates kept, 119 Location rows (std's). One row
  outside the truth: the joined "item-0,...,item-7" String (len 55) read with its header on the stack
  and capacity 4316, which is the PID, so a neighbouring stack word was taken as the capacity; an extra
  row, not a miss, and a note for the String validator (a capacity equal to the PID is a coincidence
  worth a check rule only if it recurs).
- M1 HELD exactly: table cfg (4 buckets, 2 items, load 50%, stride=48:content, header on the stack,
  ctrl on the heap), entries "mode" -> "control" and "targets" -> "docx,xlsx,pdf" (2/2).
- V1: 41 vtable rows, every one in the executable's .rdata; the usize Display object reads as size 8,
  align 8, null drop, 1 method, 1 code reference, 1 stack reference. Shape-only on Windows until a
  PE/PDB symbol scorer exists.
- T1 HELD: 0 rows.
- Timing, the finding that changed the plugin: provenance 4 s, vtables 24 s, tokio 73 s, strings 349 s,
  maps 433 s for a 300 KB process. The VAD list holds a 4 GB PAGE_READWRITE private reservation with
  CommitCharge 0 (and a 32 MB one with 1 committed page); read with pad=True it is 4 GB of zeros that
  the word-by-word scanners walked in Python. win.py 0.1.1 (classes 0.1.1, Strings 0.2.1): a private
  VAD with no committed page is not handed to the scanners (scan_vad, unit-tested); file-backed VADs
  are scanned regardless of CommitCharge. Prediction for the 0.1.1 re-run of win-img01 (the overnight
  plugins phase regenerates outputs whose sidecar names an older win.py): identical rows for all five
  plugins (the skipped region contained nothing), maps and strings under 60 s each.
- Overnight (scripts/overnight_windows.sh, 34 cells): predictions per image are those of Session 74
  P1/S1/M1/V1/T1 for seed01 cells, with the gnu cells expected to differ only in the module name and
  the CRT (msvcrt.dll); for seed02, seed03 and seed05 cells the Linux truth files apply unchanged
  (strings, maps) and tokio's T1 becomes the Linux seed02 figures per image (2 task vtables, 6 live
  tasks, worker locals 4/4, runtime worker cells 2/2); N1/N2 on win-img00-t0 and win-img01 as stated.

## Addendum 2026-10-13 (Session 77): Windows matrix read out; maps 0.5.1, win.py 0.1.2
Source: overnight run 20261011T222721Z, 35 seed images (34 matrix cells plus win-img01), win.py 0.1.1,
maps.py 0.4.1, 17 s per image.
- provenance: correct compiler and no other on 35/35 (rustc 1.71, 1.77, 1.83, 1.89, 1.99; MSVC and gnu);
  every hit file-backed in the seed's own image.
- strings: String 390/390, Location 19/19 (scorer now compares Windows paths on forward slashes),
  &str 40/40, templates 48/49; the miss is item-{} on wcfg-05 (opt-level s, MSVC), to be checked with
  the gate off.
- tokio: 6 seed02 images, 12 task vtables, 36 live tasks, worker locals 24/24, runtime cells 12/12.
- vtables: every row on every seed image lies in the seed's own module (shape-only on Windows).
- maps: 71/71 tables found, pairs 432/706. All misses on seed05: the content stride rule chose a
  multiple of the true stride (240 for 48, 256 for 32), and Vec<u8> values were only accepted with a
  glibc chunk header. maps 0.5.1: candidate strides are scored by mean typed fraction times the share
  of full buckets agreeing on one field signature; Vec<u8> is accepted without a chunk header when the
  regions are tagged allocator=nt (win.py 0.1.2). tests/test_maps_ntheap.py: six synthetic NT-heap
  tables, true strides 32/48/48/48/72/32; 0.4.1 inferred 240/48/248/232/208/32, 0.5.1 all six correct.
  Prediction for the re-run: 706/706 pairs, every other plugin's rows unchanged. Linux impact: none
  expected (glibc regions keep the chunk rule); the next Linux sweep re-runs maps to confirm 618/618.
- Manifest correction: the file named win-img00-t0.elf holds a seed01 capture (PID 5692) after block B
  was run twice; it is re-labelled win-img01b and a new idle baseline is captured.
- Whole-guest controls (win-img01 and the re-labelled image): strings scanned only the seed process;
  vtables 1 row outside the seed (sshd.exe); maps tables outside the seed 0 (3 near-miss rows in
  services.exe); provenance reports Rust fingerprints in MsMpEng.exe, SearchIndexer and one svchost,
  all in anonymous memory, none file-backed (the guest's own Rust files read by those services is the
  likely source, unverified). On Windows a process is called Rust-built only on file-backed compiler
  hits. maps and tokio hit the 45 min cap on both images.

## Addendum 2026-10-13 (Session 78): maps 0.5.1 re-run read out; maps 0.5.2
Re-run 20261013T015407Z (37 images, win.py 0.1.2): pairs 432/706 to 581/708 (the denominator grew by
win-img01b's two pairs). The Session 77 prediction of 706/706 did NOT hold. Remaining misses:
- ids (u64, String), 0/20 on all six seed05 images: the stride (32) is now right, but without a glibc
  chunk check the u64 key reads as the capacity of a String under the order cap,len,ptr, and the table's
  own vote follows that misreading. maps 0.5.2: off glibc the String order is voted over all tables in
  the process (the 70-entry String table decides); on glibc the per-table vote is unchanged.
  tests/test_maps_ntheap.py adds the scan-level case.
- wsweep-20 (1.99 MSVC) only: the HashSet<String> table was not found (5 pairs) and the (String,
  Vec<u8>) table's stride read 24 (2 pairs). maps 0.5.2 adds --debug-ctrl to print the stride scores for
  one table; HOST-COMMANDS-s78 runs it on that table.
- Scorer: a truth map now counts as recovered only when its table's entries match at least one truth
  pair (an equal item count credited 'set' to 'nested.west' on wsweep-20). Linux unchanged under the
  stricter rule: 72/72 tables, 618/618 pairs on the sweep 20261011T025629Z outputs. Windows under it:
  64/72 tables.
- vtables scorer: Windows image paths are matched on their last component; result 36/36 by shape,
  0 rows outside the seed module, drop form null only from rustc 1.83 (1.71: 0/738, 1.77: 0/361).
Prediction for the 0.5.2 re-run: pairs at least 701/708 (ids 120 recovered); tables at least 70/72;
the wsweep-20 set and blobs tables decided by the debug read-out; every other plugin's rows unchanged.

## Addendum 2026-10-17 (Session 82): provenance 0.3.3 and win.Provenance 0.1.4 pre-registered
Written before any host run of these versions. Nothing above is redefined.
- Cause found off-host: Windows-built std writes its vendored deps as /rust/deps\<crate>-<ver>\ (backslash
  directly after deps); 0.3.1 accepted either separator only after the version, so every Windows std-dep
  row was lost. rustc 1.71 Windows std reads C:\Users\runneradmin\.cargo\registry\src\<idx>\<crate>-<ver>\
  (GitHub-hosted runner, cargo home not remapped); those rows were reported as dependency + author.
- 0.3.3: /rust/deps[\\/]; a registry path under C:\Users\runneradmin\ naming a crate in STD_VENDORED is
  std-dep and produces no author row. Linux: identical output on all 229 Linux ELF builds (old vs new
  classifier over the files).
- win.Provenance 0.1.4 adds one 'target' row per process called Rust-built (file-backed compiler hits):
  x86_64-pc-windows-msvc or -gnu from (a) the main image's import directory (VCRUNTIME/api-ms-win-crt -> msvc;
  msvcrt.dll without them -> gnu) and (b) the std-dep set (gimli or addr2line -> gnu; otherwise msvc).
  Hits = number of agreeing signals; disagreement is printed as 'conflict'. Scored by
  eval/make_table_provenance.py against the manifest's target_triple.
- Off-host check (tests/test_win_target_builds.py, files mapped to their in-memory layout): 34/34 builds give
  the right commit, the right triple with both signals, a non-empty std-dep set, no runneradmin author.
Predictions for the host re-run of the 36 Windows images:
- PW1: compiler unchanged, correct and no other on 36/36.
- PW2: target triple correct on 36/36; 2 agreeing signals wherever the std-dep set is non-empty; 0 conflicts.
- PW3: std-dep set per image equals the file-level set: MSVC {hashbrown, rustc-demangle} at the version's
  versions; gnu adds addr2line, gimli, memchr, and object on 1.71 to 1.89. A smaller set is reported as a
  residency shortfall with the missing crates named, not hidden.
- PW4: no author row 'runneradmin' on any image; 'OPERATOR' author rows remain on the six seed02 images
  (seed02's own tokio dependency path), unchanged.
- PW5: strings, maps, vtables, tokio rows unchanged (maps 70/72 tables, 701/708 pairs).

## Addendum 2026-10-17 (Session 83): PW1-PW5 read out; Rust fingerprint gate (D-021) pre-registered
Read-out of the s82 host re-run (win_results_20261017T184758Z), win.Provenance 0.1.4:
- PW1 HELD: correct compiler, no other, 36/36 Windows (78/78 overall).
- PW2 HELD: target triple 36/36 (28 msvc, 8 gnu), every row with both signals, 0 conflicts.
- PW3 HELD as far as read: every image carries std-deps with the version's rustc-demangle; full per-image sets
  are in the outputs (make_table_provenance 'std-dep sets per rustc version').
- PW4 HELD: author rows: 'OPERATOR' 6 (the six seed02 images), 'runneradmin' 0.
- PW5 HELD: maps 142/144 tables and 1319/1326 pairs overall, i.e. Windows 70/72 and 701/708, unchanged.
D-021 (proposed): maps 0.5.3, vtables 0.2.5, tokio 0.3.1 and win.Maps/VTables/Tokio 0.1.5 scan a process only
when strings.detect_rustc finds the /rustc/<commit>/ fingerprint in its read-only data (the D-018 test strings
has applied since 0.4.0); --force-scan restores the ungated scan. Reason: the Windows whole-guest runs of maps
and tokio hit the 45 min cap on a 98-process guest. Every control target already passes this test (strings
857/857 String truth with the gate on), so no control score can change.
Predictions for the host run (36 per-PID images re-run because win.py changed; whole-guest on win-img01 and
win-img00-t0 with SKIP_UNGATED=1):
- G1: per-PID rows on the 36 seed images unchanged for every plugin (maps 70/72, 701/708; vtables 36/36;
  tokio 36 live tasks; strings 402/402; provenance and target 36/36).
- G2: every whole-guest run (provenance, strings, maps, vtables, tokio) on both images finishes under 45 min.
- G3: win-img01 whole guest: maps, vtables and tokio rows only in the seed PID; the earlier sshd.exe vtables row
  is gone (sshd carries no fingerprint and is not scanned).
- G4: win-img00-t0 (idle guest, first scan ever): maps, vtables, tokio, strings 0 rows; provenance may show
  anonymous-only fingerprints (Defender, indexer) and no process with a file-backed compiler row, so no target row.
- Linux: no rows can change (every Linux target passes the same test); confirmed at the next Linux sweep.

## Addendum 2026-10-18 (Session 92): D-022, the fingerprint gate reads the executable's EXEC pages
Written before the host run. Nothing above is redefined.

Cause, measured with ferric.diag.Regions on det-blackcat-f8c08d00-exit (pid 1279): start_code readable, the
executable correctly identified, its r-- mapping correctly classified rodata, and all 27 /rustc/ compiler
hits sitting in the executable's 1.8 MB r-x mapping with 0 in the 48 KB r-- mapping. classify_vma returns
EXEC on the X bit before consulting is_exe, the gate (strings.detect_rustc) read RODATA only, and content
scanning uses {HEAP, STACK, DATA, RODATA}; so that memory was read by nothing. ferric.provenance scans every
region and therefore saw what the gate could not. On det-1cbbf108-exit the hits are in rodata, which is why
that sample worked. Scope: strings since 0.4.0 (D-018), and maps/vtables/tokio since Session 83 (D-021).
All 82 control images identify their executable AND keep .rodata in a separate r-- segment, which is why
the control corpus never exposed this; it took a real sample.

D-022 (proposed): Regions carries the main executable's backing name, and Regions.exe_const_rows() returns
its RODATA rows plus its EXEC rows. strings.detect_rustc uses that set. Libraries' EXEC pages stay excluded,
so only the program under analysis is read. strings 0.4.1; maps, vtables and win builders record the exe.
This changes only WHETHER a process is scanned, never what is recovered from a scanned process.

Predictions for the host run:
- C1: every control number bit-identical on both OSes, because every control already passed the gate.
  provenance 42/42 and 36/36 with target 36/36; strings 455/455, 24/24, 76/76, 63/63 and 402/402, 20/20,
  72/72, 51/52; maps 72/72 and 618/618, 70/72 and 701/708; vtables 1,285/1,285; tokio 36 tasks each OS.
- C2: the C++ and Go negatives stay clean, 0 rows from all five plugins. Neither has a /rustc/ path in any
  mapping, so widening the gate to the executable's own code cannot reach them.
- W1: det-blackcat-f8c08d00-exit and det-45b8678f-exit now PASS the gate, so maps, vtables, tokio and
  strings run on them instead of refusing.
- W2: strings on det-blackcat-f8c08d00-exit without --force-scan now reports the same 411 String rows that
  --force-scan produced, and still 0 location and 0 str rows (see the limitation below).
- W3: det-2e52494e, det-cb408d45 and det-cd27a31e stay refused: no /rustc/ path in any of their regions,
  confirmed region by region by ferric.diag.Regions --hits.
- W4: maps may still report 0 on every wild sample; the exit-hold capture point precedes any table being
  built, which is a capture-protocol limit, not a recogniser limit.

Known limitation NOT addressed here (candidate D-023, to be measured separately): validate_location and
validate_str require the target pointer to land in RODATA, so on a binary whose constants are merged into
the text segment every &str and panic Location is rejected. That is why BlackCat yields String rows but no
str or location rows. Widening the accepted target kinds can change control numbers, so it needs its own
before-and-after measurement rather than riding along with this fix.
## Addendum 2026-10-18 (Session 95): D-023, &str and Location from a merged-text executable
Written before the host run. Nothing above is redefined. This is the measured round D-022's addendum
deferred: D-022 said widening the accepted &str/Location target "can change control numbers, so it needs
its own before-and-after measurement rather than riding along." Here is that measurement, pre-registered.

Cause (restated): after D-022 let det-blackcat-f8c08d00-exit and det-45b8678f-exit be scanned, their String
objects and trait-object vtables were recovered but their &str and panic-Location rows stayed at 0, because
validate_str and validate_location require the target bytes in RODATA and on these binaries the literals are
physically inside the r-x text segment (det-1cbbf108-exit keeps its constants in rodata, so it was never
affected).

Change (strings 0.4.2): Regions gains merged_text, set by scan_process from detect_rustc's rodata-vs-text
hit split (text hits > 0 and rodata hits == 0, and the executable identified). Only when it is set does
Regions.str_target_ok admit the executable's own EXEC pages as a literal target, and Regions.str_scan_rows
add those pages to the header-quadword scan. Libraries' code is never admitted. String headers are still
sought only in heap/stack/data (String data lives on the heap), so String recovery is untouched; maps,
vtables and tokio do not use these paths at all. The compiler pseudo-row prints "merged-text layout" when
the flag is set.

Why no control can move (the safety argument, to be confirmed, not assumed):
- All 82 control binaries keep .rodata in a separate r-- segment, so their compiler paths are in RODATA:
  rodata_hits > 0, hence merged_text is False and both widened paths are inert. The behaviour is then
  byte-for-byte the 0.4.1 behaviour.
- The UPX control is the one to watch: its unpacked constants are ANONYMOUS read-only memory, which
  classify_vma labels RODATA (not EXEC), so rodata_hits > 0 and merged_text stays False. musl is static but
  keeps a separate rodata segment, so likewise.
- The unit test tests/test_merged_text_str.py pins the ordinary-layout case: merged_text False gives the old
  admissibility test and scans no exe text.

Predictions for the host run:
- E1 (controls): every strings control figure bit-identical to Session 92 C1 (String 455/455 and 402/402,
  Location 24/24 and 20/20, &str 76/76 and 72/72, templates 63/63 and 51/52), and no control's compiler row
  prints "merged-text layout". The other four plugins are untouched by construction. Any deviation stops the
  submission until explained.
- E2 (merged-text wild samples, observations not recall): det-blackcat-f8c08d00-exit and det-45b8678f-exit
  report merged-text in their compiler row and gain panic-Location rows (Rust binaries carry many), and
  possibly &str rows, where 0.4.1 reported none. Their String counts are unchanged (411 on f8c08d00) and
  their vtables unchanged (292 and 300). Report the measured &str and Location counts.
- E3 (non-merged wild sample): det-1cbbf108-exit unchanged (rodata_hits > 0 -> merged_text False); strings
  total stays 476, &str and Location as before.
- E4 (non-Rust wild samples): still refused by the gate; unchanged.

Trust note for the read-out: panic Location is strongly constrained (target ends ".rs", NUL rules per
version, line/col in range), so Location rows from text are as trustworthy as from rodata. A &str row from
text is a (ptr,len) pair whose pointer lands in text at a printable UTF-8 run of exactly len bytes; this is
weaker, so a sample of the &str rows on f8c08d00 should be eyeballed before any &str count is quoted, and
only Location is treated as a firm recovery in the write-up until then.
