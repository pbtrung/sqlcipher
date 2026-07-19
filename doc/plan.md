# Implementation plan: leancrypto crypto backend

This document records the implementation plan followed to replace SQLCipher's
AES-256-CBC/HMAC-SHA512/PBKDF2 crypto stack with a single leancrypto-based
provider (Ascon-Keccak-512 AEAD + HKDF-SHA3-512). See `doc/crypto.md` for the
resulting design (algorithms, blob format, derivation, known limitations).
This file is the step-by-step build log/checklist; treat `doc/crypto.md` as
the source of truth for the final cryptographic design.

## Scope

- leancrypto becomes the **only** crypto provider — OpenSSL, LibTomCrypt, and
  CommonCrypto providers are removed, not just disabled.
- **Linux only.** No Windows/macOS build path is maintained.
- leancrypto is vendored as a git submodule and built from source (never
  linked against a system package), so the build stays self-contained and
  leaves a path open to retarget to other platforms (e.g. WASM/Emscripten)
  later without depending on a system-installed library.
- The on-disk format and keying model both change in a backward-incompatible
  way; there is no migration path from AES-256 SQLCipher databases.

## Steps

1. **Docs first** — `doc/plan.md` (this file) and `doc/crypto.md` (crypto
   design spec) written and committed before any code changes.
2. **Vendor leancrypto** — add it as a git submodule at
   `third_party/leancrypto`, pinned to a tagged release, with `.gitmodules`.
3. **Build integration** — add a Meson-driven static-library build step to
   `main.mk` for `third_party/leancrypto`, with all unneeded leancrypto
   subsystems disabled (see `doc/crypto.md` "Build"), producing
   `libleancrypto.a` and wiring its headers/link flags into the
   `libsqlite3`/`sqlite3`/`testfixture` build.
4. **New provider** — `src/crypto_leancrypto.c`, implementing the provider
   vtable using leancrypto's Ascon-Keccak AEAD API (`lc_ak_alloc_taglen`,
   `lc_aead_setkey`, `lc_aead_encrypt`, `lc_aead_decrypt`, hash =
   `lc_sha3_512`) and HKDF API (`lc_hkdf_extract`, `lc_hkdf_expand`, hash =
   `lc_sha3_512`).
5. **Core orchestration rewrite** — `src/sqlcipher.h` / `src/sqlcipher.c`:
   - Extend the `sqlcipher_provider` vtable for a combined AEAD
     encrypt/decrypt call (key, nonce, AAD in, tag in/out) and for HKDF
     (distinct from the old PBKDF2-shaped `kdf()`); remove the old
     `cipher()`/`hmac()`/`kdf()` fields since no other provider needs them.
   - `SQLCIPHER_CRYPTO_LEANCRYPTO` becomes the sole, always-on dispatch path.
   - File header grows from the historic 16-byte raw KDF salt to the 68-byte
     `magic || version || salt` header described in `doc/crypto.md`.
   - `sqlcipher_page_cipher()` rewritten to do one AEAD call per page (see
     "Per-page key/nonce derivation" in `doc/crypto.md`) instead of a
     block-cipher call plus a separate HMAC call.
   - Key derivation rewritten to HKDF-Extract/Expand (twice, for key and
     nonce) in place of PBKDF2 (+ the old "fast" second KDF pass for the HMAC
     key, which no longer exists as a separate concept).
   - `CIPHER_MAX_IV_SZ` / `CIPHER_MAX_KEY_SZ` and the reserve-size
     calculation updated for 64/64/64 sizing; a ≥256-byte raw master key is
     enforced at key-set time.
   - Pragmas that only made sense for PBKDF2/HMAC-CBC (`cipher_kdf_iter`,
     `cipher_hmac_algorithm`, `cipher_kdf_algorithm`, `cipher_compatibility`
     legacy presets, `cipher_use_hmac`, etc.) are removed or turned into
     clear no-ops/errors, following the precedent already set by the
     deprecated read-only `PRAGMA cipher`.
6. **Delete old providers** — remove `src/crypto_openssl.c`,
   `src/crypto_libtomcrypt.c`, `src/crypto_cc.c` and their build rules in
   `main.mk`/`Makefile.msc`; update `README.md`'s build recipe.
7. **Test suite update** — adapt `test/sqlcipher-*.test` to drop
   assertions tied to removed pragmas/algorithms, and add coverage for:
   valid-key round-trip, undersized-key rejection, tamper detection,
   per-page salt uniqueness, magic/version header presence, and rekeying.
   Update `tool/crypto-speedtest.tcl` for the new provider.
8. **Full test pass** — build `testfixture`, run the full sqlcipher test
   set (plus `veryquick.test`), and fix issues until everything passes.
9. **Finalize docs** — reconcile `doc/crypto.md`/`doc/plan.md` with any
   deviations found during implementation; add a `CHANGELOG.md` entry.

## Post-implementation hardening (found during the "full test pass" step)

Running the full `veryquick.test` regression suite (not just the sqlcipher-
specific files) surfaced three real, low-probability issues that unit-level
testing didn't catch. Each was root-caused with a reproducer (ASAN, gdb, or
a baseline comparison) before being fixed in `src/crypto_leancrypto.c` /
`test/tester.tcl`:

1. **AEAD/HKDF stack-macro memory corruption** (real bug, fixed). Running
   `ext/fts5/test/fts5aa.test` repeatedly under AddressSanitizer (with
   `-DSQLCIPHER_OMIT_MALLOC` to let ASAN see raw allocations) reproduced a
   global-buffer-overflow inside leancrypto's `lc_aead_zero()`, corrupting
   memory near unrelated leancrypto globals -- but only when reached
   through SQLite's real, deep pager/journal call stack, never in a
   shallow standalone stress-test loop calling the same leancrypto APIs
   thousands of times. The common factor: `lc_aead_encrypt`/`decrypt` used
   leancrypto's `LC_AK_CTX_ON_STACK_TAGLEN()` stack-allocation macro, and
   `lc_hkdf()` internally uses the equivalent `LC_HKDF_CTX_ON_STACK()`.
   Fixed by switching both to leancrypto's heap-allocating equivalents
   (`lc_ak_alloc_taglen`/`lc_aead_zero_free`, `lc_hkdf_alloc`/
   `lc_hkdf_extract`/`lc_hkdf_expand`/`lc_hkdf_zero_free`) -- one
   malloc/free pair per page encrypt/decrypt/derive call, which is an
   acceptable cost for eliminating a confirmed memory-safety bug.
2. **Startup deadlock calling `sqlite3_randomness()` from the codec**
   (real bug, fixed). After switching the original `random()`
   implementation from leancrypto's `lc_seeded_rng`/xdrbg (itself found,
   via the same ASAN investigation, to use the same class of buggy
   stack-macro internally, with genuinely global/shared DRNG state making
   it worse) to SQLite's own `sqlite3_randomness()`, `testfixture` hung on
   every single startup. Root-caused with gdb (attach-on-launch, since
   ptrace-attach to an already-running process was blocked in this
   sandbox): `sqlcipher_extra_init()` -- which unconditionally calls
   `provider->random()` once at registration time to seed its own internal
   secure-wipe PRNG -- was calling `sqlite3_randomness()`, whose first-ever
   call needs `sqlite3_vfs_find()`, which deadlocks on a mutex that isn't
   yet safe to acquire from inside SQLite's own
   `sqlite3_initialize()`/`SQLITE_EXTRA_INIT` call chain. Fixed by using
   the `getrandom(2)` Linux syscall directly (`<sys/random.h>`) instead --
   it needs neither leancrypto's DRNG state nor any SQLite-internal
   machinery, sidestepping both this and issue #1 entirely. `PRAGMA
   cipher_add_random` became a no-op as a result (`getrandom()` has no
   concept of caller-supplied entropy to mix in), matching the precedent
   of the historic CommonCrypto provider, which had no such hook either.
3. **`tester.tcl` sqlite3-wrapper broke multi-process tests** (real bug,
   fixed). `ext/fts5/test/fts5multiclient.test` (and similar
   multi-connection tests using `lock_common.tcl`'s
   `do_multiclient_test`/`launch_testfixture`) spawn a *separate child
   `testfixture` process* and copy the current interpreter's `sqlite3`
   proc body (`[info body sqlite3]`) verbatim into that child's script, to
   reuse the exact same codec-key-injection behavior there. The historic
   `-key {xyzzy}` was a self-contained literal, safe to copy anywhere. The
   updated version's `-key [sqlcipher_test_key]` called a proc that only
   exists in interpreters that sourced `tester.tcl` -- the child process
   doesn't, so it failed with "invalid command name". Fixed by inlining
   the same fixed key as a literal (`x'[string repeat 01 256]'`, using
   only the always-available `string` builtin) directly in the wrapper
   body again, matching the original literal-value pattern exactly.

None of these were caught by the sqlcipher-specific test files alone
(`test/sqlcipher.test`'s 136 tests passed cleanly throughout) -- they only
surfaced by running the full, broader SQLite regression suite
(`test/veryquick.test`), which is why that step matters even for a
change scoped to the codec.

### A fourth issue investigated and NOT fixed (pre-existing, unrelated)

`ext/fts5/test/fts5aa.test` test 14.2 (200 iterations of `BEGIN; CREATE
TABLE; ROLLBACK;` inside a live FTS5 MATCH cursor, with FTS5's internal
`pgsz` set to 32) fails intermittently with "database disk image is
malformed", roughly 1 run in 15-60. This was investigated at length
(AddressSanitizer showed no memory-safety error for these particular
failures; debug-level codec logging showed the AEAD decrypt succeeding
cleanly, meaning the corruption is not a crypto/auth failure; a targeted
experiment shrinking the AEAD tag to 16 bytes, matching the previous
scheme's exact reserve-size arithmetic, did not eliminate it). The
decisive test: running the *identical* reproducer 60 times against the
unmodified pre-migration AES-256-CBC/HMAC-SHA512/OpenSSL baseline (via a
git worktree at the commit before this migration started) also failed at
a similar rate. This confirms it is a latent SQLite/pager/FTS5 interaction
issue under this specific adversarial access pattern that predates the
leancrypto migration and is independent of which crypto provider is used
-- it is not fixed here, and is recorded in `doc/crypto.md`'s "Known
limitations" so it isn't mistaken for a crypto regression in the future.

## WASM build (built as a follow-up; see wasm/README.md for the full writeup)

The hypothesis recorded here originally ("leancrypto's `disable-asm` option
is the natural starting point for a future Emscripten cross-build") was
followed through and built: `tool/build-wasm.sh` compiles the SQLCipher
amalgamation and the *entire* vendored leancrypto submodule into a single
WASM module (`wasm/sqlcipher.{js,wasm}`), exporting both SQLite/
SQLCipher's `sqlite3_*` API and leancrypto's own `lc_*` API (via
`-Wl,--whole-archive`/`-s EXPORT_ALL=1`), following the scope and structure
of the reference [secbits/leancrypto](https://github.com/pbtrung/secbits/tree/main/leancrypto)
WASM build. Verified end to end under Node.js (`wasm/test-roundtrip.mjs`):
database round-trip, wrong/undersized key rejection, and leancrypto's raw
AEAD/HKDF API all work correctly compiled to WASM.

Two real, previously-unknown portability issues surfaced and were fixed
along the way (neither specific to this project's narrow native-build
option set — both are general facts about compiling this code for WASM):

1. **A per-page-salt RNG gap.** `src/crypto_leancrypto.c`'s
   `sqlcipher_leancrypto_random()` called the raw `getrandom(2)` Linux
   syscall directly (see the "Post-implementation hardening" section
   above for why), which does not exist under Emscripten. Fixed with an
   `#ifdef __EMSCRIPTEN__` branch using Emscripten's `getentropy()` libc
   shim instead (backed by the browser's `crypto.getRandomValues()`/
   Node's `crypto.randomFillSync()`), chunked to ≤256 bytes per POSIX's
   cap — the native Linux `getrandom()` path is untouched.
   `src/crypto_leancrypto_rng_wasm.c` was also vendored (adapted from the
   reference build's own `seeded_rng_wasm.c`), supplying the low-level
   entropy symbols leancrypto's own `drng/src/seeded_rng.c` expects on
   platforms with no OS-specific backend -- defensively, since this
   project's leancrypto configuration (both native and, originally, WASM)
   never compiled `seeded_rng.c` in at all (no DRNG option was enabled);
   see point 3 below for why the WASM build's options changed.
2. **A genuine, pre-existing WASM-compilation bug in `src/sqlcipher.c`**,
   unrelated to leancrypto or this migration: its non-Windows/non-Apple
   cleanup-registration path placed a function pointer directly into a
   `section(".fini_array")` variable, which crashes the LLVM wasm32
   backend outright ("`.fini_array` sections are unsupported") since
   Emscripten's object format has no real ELF `.fini_array` semantics.
   Fixed with an `__EMSCRIPTEN__` branch using
   `__attribute__((destructor))` instead (already the pattern used for
   the ASan-on-Apple case in the same `#if` chain).
3. **leancrypto's own `meson.build`, unmodified, does not cross-compile
   cleanly for wasm32 as-is**: it unconditionally probes
   `cc.has_argument('-flto')`/`'-ffat-lto-objects'` and adds them if the
   probe returns true, which it incorrectly does for `emcc` (these flags
   fail at actual wasm32 compile time: "unsupported option ... for
   target wasm32-unknown-emscripten"). Fixed by generating a thin
   compiler-wrapper script around `emcc` that filters those flags (plus
   `-fcf-protection=*`/`-mbranch-protection=*`) before invoking the real
   `emcc` -- entirely in `tool/build-wasm.sh`'s own tooling, so the
   pinned, vendored submodule's `meson.build` stays untouched. Separately,
   reusing the *native* build's narrow Ascon-Keccak/SHA3/HKDF-only Meson
   option set for WASM failed to link (`undefined symbol: lc_rng_zero`
   from HKDF's RNG-support code, `undefined symbol: lc_aes` from the
   generic symmetric-cipher dispatcher -- both real symbols only compiled
   in when some DRNG/AES option is enabled, and `-Wl,--whole-archive`
   pulls in every object regardless of whether this project's own code
   calls it). Resolved by keeping leancrypto's *default* (mostly
   "enabled") option set for the WASM build specifically, which both
   supplies those symbols for free and gives the requested full leancrypto
   API surface as a side effect -- see `tool/build-wasm.sh` and
   `wasm/README.md` for the exact option list.

## Verification

- `make testfixture` builds cleanly with no OpenSSL/LibTomCrypt/CommonCrypto
  references left anywhere in the tree.
- `./testfixture test/sqlcipher.test` and all `test/sqlcipher-*.test` files
  pass.
- Manual round-trip: open a fresh DB with a valid ≥256-byte key, write data,
  close, reopen with the same key, read it back; wrong/undersized keys fail
  cleanly; a flipped byte in an on-disk page fails to decrypt/authenticate.
- `git submodule status` shows `third_party/leancrypto` pinned and clean; a
  fresh `git clone --recurse-submodules` plus build works with no system
  leancrypto package installed.
