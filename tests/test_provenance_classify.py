#!/usr/bin/env python3
# NOTE: lives outside plugins/ on purpose: Volatility imports every .py under -p as a plugin module.
"""Unit tests for ferric.provenance.classify — pure-function tests, no memory image needed.
Run:  python3 tests/test_provenance_classify.py   (needs volatility3 importable)
Strings below are the shapes observed in the lab corpus (NOTEBOOK sessions 18-37); the
author name is a placeholder, not a lab account.
"""
import os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
from ferric.provenance import PATTERN, KNOWN_COMMITS, classify, version_for, iter_pattern_offsets  # noqa: E402

H199 = b"b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"
H171 = b"8ede3aae28fe6e4d52b38157d7bfe0d3bceef225"
fails = 0

def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    if not cond: fails += 1

def hits(blob):
    """Emulate the plugin: the same two-pass window iterator, then classify with 192 B of lookbehind."""
    out = []
    for o in iter_pattern_offsets(lambda off, n: blob[off:off + n], 0, len(blob)):
        out += classify(blob[o:o + 512], blob[max(0, o - 192):o])
    return out

# 1. compiler tier: std panic Location path, as emitted by the shipped std
blob = b"\x00/rustc/" + H199 + b"/library/core/src/panicking.rs\x00"
r = hits(blob)
check("compiler: one hit", len(r) == 1 and r[0][0] == "compiler")
check("compiler: commit extracted", r[0][1] == H199.decode())
check("compiler: version lookup", version_for(r[0][1], {}) == "1.99.0")
check("compiler: unknown commit is labelled unknown, not guessed",
      version_for("0" * 40, {}).startswith("unknown"))
check("compiler: --commit-map override wins", version_for("0" * 40, {"0" * 40: "9.9.9"}) == "9.9.9")

# 2. several occurrences count separately (the measured 45 / 97 are occurrence counts)
blob = b"".join(b"/rustc/" + H199 + b"/library/std/src/x%d.rs\x00" % i for i in range(45))
check("compiler: 45 occurrences -> 45 hits", len(hits(blob)) == 45)

# 3. no cross-version confusion: 1.71 hash never classified as 1.99
blob = b"/rustc/" + H171 + b"/library/alloc/src/vec/mod.rs\x00"
check("compiler: 1.71 commit maps to 1.71.0", version_for(hits(blob)[0][1], {}) == "1.71.0")

# 4. dependency tier under a home dir -> dependency AND author records
blob = (b"\x00/home/devuser/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
        b"tokio-1.53.2/src/runtime/task/mod.rs\x00")
r = hits(blob)
tiers = sorted(t for t, _, _ in r)
check("dependency+author from one registry path", tiers == ["author", "dependency"])
check("dependency: crate-version exact", ("dependency", "tokio-1.53.2") in [(t, e) for t, e, _ in r])
check("author: username recovered from the home path of a registry string", ("author", "devuser") in [(t, e) for t, e, _ in r])

# 5. remapped home (--remap-path-prefix $HOME=/x): dependency survives, author gone
blob = b"\x00/x/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hashbrown-0.15.2/src/raw/mod.rs\x00"
r = hits(blob)
check("remap: dependency survives", [(t, e) for t, e, _ in r] == [("dependency", "hashbrown-0.15.2")])

# 6. hyphenated crate names and pre-release versions
blob = b"\x00.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-macros-2.4.0/src/lib.rs\x00"
check("dependency: hyphenated crate", [(t, e) for t, e, _ in hits(blob)] == [("dependency", "tokio-macros-2.4.0")])
blob = b"\x00.cargo/registry/src/index.crates.io-aaaa/zerocopy-0.8.0-alpha.1/src/lib.rs\x00"
check("dependency: pre-release version", [(t, e) for t, e, _ in hits(blob)] == [("dependency", "zerocopy-0.8.0-alpha.1")])

# 7. toolchain tier
blob = b"\x00/home/devuser/.rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/io/mod.rs\x00"
r = hits(blob)
check("toolchain: name carries version", ("toolchain", "1.99.0-x86_64-unknown-linux-gnu") in [(t, e) for t, e, _ in r])
check("toolchain path also yields author", ("author", "devuser") in [(t, e) for t, e, _ in r])

# 8. author tier requires a Rust marker: shell environment strings must NOT count
blob = b"HOME=/home/devuser\x00PWD=/home/devuser/Desktop/notes\x00SHELL=/bin/bash\x00"
check("author: plain env paths rejected (negative control)", hits(blob) == [])
blob = b"\x00/home/devuser/proj/src/main.rs\x00"
check("author: absolute .rs source accepted", [(t, e) for t, e, _ in hits(blob)] == [("author", "devuser")])
blob = b"\x00C:\\Users\\devuser\\proj\\target\\release\\build\\x.rs\x00"
check("author: Windows path accepted", [(t, e) for t, e, _ in hits(blob)] == [("author", "devuser")])

# 8b. (0.3.2) the environment block of ANY process started from a shell with rustup carries PATH entries
# like /home/u/.cargo/bin; that is not an author path (measured on the C++ and Go negative controls)
blob = b"PATH=/home/devuser/.npm/bin:/home/devuser/.cargo/bin:/usr/local/bin:/usr/bin\x00"
check("author: ~/.cargo/bin inside a PATH list rejected (negative control)", hits(blob) == [])
blob = b"\x00/home/devuser/.cargo/bin/cargo\x00"
check("author: the cargo tool path alone is not a source path", hits(blob) == [])
blob = b"\x00/home/devuser/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.219/src/lib.rs\x00"
check("author: a registry source path still counts", ("author", "devuser") in [(t, e) for t, e, _ in hits(blob)])
blob = b"\x00/home/devuser/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/x.rs\x00"
check("author: a toolchain source path still counts", ("author", "devuser") in [(t, e) for t, e, _ in hits(blob)])

# 9. lookbehind must not cross a NUL into an unrelated earlier string
blob = b"/home/other/x\x00.cargo/registry/src/index.crates.io-aaaa/serde-1.0.219/src/lib.rs\x00"
r = hits(blob)
check("lookbehind stops at NUL (no false author)", [(t, e) for t, e, _ in r] == [("dependency", "serde-1.0.219")])

# 10. junk / non-Rust binaries: nothing
blob = os.urandom(65536).replace(b"/rustc/", b"xxxxxxx")
check("random bytes: no hits", hits(blob) == [])
blob = b"/usr/lib/go/src/runtime/panic.go\x00GOROOT=/usr/lib/go\x00"
check("Go runtime paths: no hits", hits(blob) == [])

# 11. std vendored dependency paths (/rust/deps/<crate>-<ver>/), hypothesis form
blob = b"\x00/rust/deps/hashbrown-0.15.2/src/raw/mod.rs\x00"
check("std-dep: hashbrown version from /rust/deps/", [(t, e) for t, e, _ in hits(blob)] == [("std-dep", "hashbrown-0.15.2")])

# 11b. REGRESSION (session 42): a registry path immediately followed by a /rustc/ path, no terminator.
# One combined greedy regex swallowed the compiler hit; independent passes must find all three records.
blob = (b"\x00/home/devuser/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.2/src/runtime/task/mod.rs"
        b"/rustc/" + H171 + b"/library/core/src/panicking.rssrc/main.rs\x00")
r = sorted((t, e) for t, e, _ in hits(blob))
check("regression: compiler hit not swallowed by preceding home path", ("compiler", H171.decode()) in r)
check("regression: dependency still found", ("dependency", "tokio-1.53.2") in r)
check("regression: author still found (once per record source)", ("author", "devuser") in r)
check("regression: no duplicate dependency from nested emission", r.count(("dependency", "tokio-1.53.2")) == 1)

# 11c. older-toolchain std-dep form (/cargo/registry/, the Rust CI cargo home) — hypothesis form
blob = b"\x00/cargo/registry/src/index.crates.io-6f17d22bba15001f/hashbrown-0.14.0/src/raw/mod.rs\x00"
check("std-dep: /cargo/registry form classified as std-dep, not dependency",
      [(t, e) for t, e, _ in hits(blob)] == [("std-dep", "hashbrown-0.14.0")])

# 12. window iterator: every occurrence exactly once, wherever it falls
PAT = b"/rustc/" + H199 + b"/library/"
def mem_with(offsets, size):
    buf = bytearray(size)
    for o in offsets: buf[o:o + len(PAT)] = PAT
    return bytes(buf)
W, OV = 4096 * 4, 512                       # small window/overlap to exercise boundaries
size = W * 3 + 1000
offs = [0, 100, 4096 - 20,                  # start, inside, straddling a page boundary
        W - 30,                             # straddling the first window boundary (owned by window 0)
        W + 100,                            # just inside window 1
        2 * W - OV + 3,                     # inside window 1's overlap zone -> owned by window 2
        size - len(PAT)]                    # last bytes of the region (occurrences >= 56 B apart)
mem = mem_with(offs, size)
rd = lambda o, n: mem[o:o + n]
got = sorted(iter_pattern_offsets(rd, 0, size, pattern=PATTERN, window=W, overlap=OV))
check("window iterator: finds every occurrence exactly once", got == sorted(offs))
base = 0x7f0000000000                                      # absolute offsets, non-zero start
rd2 = lambda o, n: mem[o - base:o - base + n]
got = sorted(iter_pattern_offsets(rd2, base, base + size, pattern=PATTERN, window=W, overlap=OV))
check("window iterator: absolute offsets correct", got == sorted(base + o for o in offs))
got = list(iter_pattern_offsets(rd, 0, 200, pattern=PATTERN, window=W, overlap=OV))
check("window iterator: region shorter than one window", got == [0, 100])
got = list(iter_pattern_offsets(lambda o, n: b"\x00" * n, 0, W * 5, pattern=PATTERN, window=W, overlap=OV))
check("window iterator: empty memory -> no hits", got == [])

# 13. table sanity
check("all KNOWN_COMMITS are 40-hex", all(re.fullmatch(r"[0-9a-f]{40}", k) for k in KNOWN_COMMITS))

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)
