# SQLCipher + leancrypto, compiled to WebAssembly

This directory holds an **additive, standalone** WASM build of SQLCipher:
the full SQLCipher amalgamation (with its leancrypto-based
Ascon-Keccak-512/HKDF-SHA3-512 codec, see `doc/crypto.md`) and the entire
vendored `third_party/leancrypto` submodule, compiled together into one
Emscripten module.

This is **not** the same thing as `ext/wasm/` — that directory is upstream
SQLite's own, much larger multi-variant WASM/JS-glue build (OO1 API, Worker
threads, OPFS storage, ESM/bundler/node variants, ...) for *vanilla* SQLite,
with no codec/encryption awareness at all. This build is deliberately
smaller in scope: one module, one JS file, exporting the raw C API directly
(both SQLite/SQLCipher's `sqlite3_*` functions and leancrypto's own `lc_*`
functions), with no JS-side object/OO wrapper. It does not touch or replace
the native Linux build in `main.mk`.

## Prerequisites

- **Emscripten**. This build uses whatever `emcc`/`emar`/`emranlib` it can
  find: first `$EMCC`/`$EMAR`/`$EMRANLIB` env vars, then `$PATH`, then the
  system emscripten package path (`/usr/lib/emscripten`, as installed by
  the `emscripten` package on Arch/CachyOS). Any reasonably recent version
  should work; this was built and verified against emscripten 6.0.3.
- **Meson** (already required for the native build's leancrypto integration
  — see `main.mk`).
- **Node.js**, to run the verification script (`wasm/test-roundtrip.mjs`).
  Not required just to build the module.
- The `third_party/leancrypto` git submodule checked out
  (`git submodule update --init --recursive`).

## Building

```
$ tool/build-wasm.sh
```

This:

1. Resolves the Emscripten toolchain and generates a small compiler
   wrapper around `emcc` that filters `-flto=auto`/`-ffat-lto-objects`/
   `-fcf-protection=*`/`-mbranch-protection=*` — Meson's compiler-argument
   probing (`cc.has_argument()`) in leancrypto's *unmodified* `meson.build`
   incorrectly reports these as supported for the `wasm32-unknown-emscripten`
   target (they fail at actual compile time), and filtering them in a
   wrapper avoids ever having to patch the pinned, vendored submodule. The
   wrapper also unconditionally adds `-msimd128` to every compile (both
   leancrypto's own build and the final link below) — see "Performance"
   below.
2. Builds leancrypto for `wasm32` via Meson + a generated cross-file
   (`third_party/wasm-cross.ini`, from `third_party/wasm-cross.ini.in`),
   into `third_party/leancrypto/build-wasm/`. Unlike the *native* Linux
   build (which narrows leancrypto down to only Ascon-Keccak/SHA3/HKDF —
   see `LEANCRYPTO_MESON_OPTS` in `main.mk`), this build keeps leancrypto's
   *default* option set (all PQC algorithms, all AES modes, all KDFs/DRNGs)
   so that the full leancrypto public API ends up in the final module —
   only `disable-asm`, `efi`, `apps`, `tests`, and the GPLv2-licensed
   X.509/PKCS7/PKCS8 parser/generator options are turned off (license and
   portability reasons, matching the native build's own rationale).
3. Regenerates the SQLCipher amalgamation (`sqlite3.c`/`sqlite3.h`) by
   reusing the existing `autosetup`/`main.mk` machinery in a scratch build
   directory (`wasm/.gen/`) — it does not reimplement amalgamation
   generation.
4. Links `sqlite3.c` + `src/crypto_leancrypto.c` +
   `src/crypto_leancrypto_rng_wasm.c` + `wasm/leancrypto_wasm_api.c`
   against the wasm32 `libleancrypto.a` with `-Wl,--whole-archive` and
   `-s EXPORT_ALL=1`/`-Wl,--export-all`, so every public C symbol from
   *both* SQLite/SQLCipher and leancrypto ends up exported from the same
   module — matching the scope of the reference
   [secbits/leancrypto](https://github.com/pbtrung/secbits/tree/main/leancrypto)
   WASM build this was adapted from.

Output: `wasm/sqlcipher.js` + `wasm/sqlcipher.wasm` — checked in directly
(not gitignored), so the module is usable without a local Emscripten
toolchain. Re-run `tool/build-wasm.sh` and commit the results after any
change to the codec, `wasm/leancrypto_wasm_api.c`, or the leancrypto
version/options.

## Performance

See `doc/crypto.md`'s "Performance" section for the full explanation of why
this project's Ascon-Keccak/SHA3 crypto suite can't reproduce SQLCipher
Commercial's "~4x faster" AES-NI claim (this codec doesn't use AES, and
there's no equivalent fixed-function CPU instruction for Keccak-p[1600]).
For WASM specifically: leancrypto's own hand-written AVX2/AVX512/NEON asm
is x86_64/ARM assembler and cannot target `wasm32` at all, so
`disable-asm=true` is kept for this build (a correctness requirement, not a
missed optimization). The WASM-appropriate equivalent is `-msimd128`,
letting LLVM's auto-vectorizer target WASM's 128-bit SIMD instruction set
when compiling leancrypto's portable C Keccak implementation. Measured with
the same methodology as the native benchmark (20,000 iterations of
`lc_wasm_aead_encrypt`/`_decrypt` over 4096-byte pages, under Node.js on
this development machine):

| | without `-msimd128` | with `-msimd128` |
|---|---|---|
| AEAD encrypt | 209.3 MB/s (19.57 µs/page) | 210.2 MB/s (19.48 µs/page) |
| AEAD decrypt | 199.5 MB/s (20.53 µs/page) | 201.3 MB/s (20.35 µs/page) |
| HKDF-SHA3-512 | 4.78 µs/op | 4.70 µs/op |

Unlike the native AVX2 case, this is not a measurable win — LLVM's
auto-vectorizer doesn't effectively vectorize Keccak's bit-interleaved
permutation without explicit SIMD intrinsics (which leancrypto's portable C
implementation doesn't use). `-msimd128` is kept anyway since it's a
zero-cost, zero-risk flag (every WASM runtime that can load this module
already supports WASM SIMD, finalized since 2021) and it keeps this build's
compiler flags in the same spirit as the native one, but it should not be
represented as a real performance improvement for this build.

## Verifying

```
$ node wasm/test-roundtrip.mjs
```

Exercises both exported APIs end to end:

- **SQLite/SQLCipher**: opens a database with a valid raw 256-byte key
  (`x'...512 hex chars...'`), creates a table, inserts rows, closes,
  reopens with the same key, reads the rows back, and checks
  `PRAGMA cipher_provider`/`PRAGMA cipher` report `leancrypto`/
  `ascon-keccak-512`. Also confirms a wrong key and an undersized key are
  both rejected.
- **leancrypto's raw API** (via `leancrypto_wasm_api.c`'s thin wrappers):
  an AEAD encrypt/decrypt round trip, tamper detection (a flipped
  ciphertext byte fails to decrypt), and HKDF-SHA3-512 determinism.

## Using the module

`wasm/sqlcipher.js` is built with `-s MODULARIZE=1 -s EXPORT_NAME=Sqlite3Wasm`,
so it's a factory function returning a promise:

```js
import Sqlite3Wasm from './sqlcipher.js';
const Module = await Sqlite3Wasm();
```

Every public SQLite/SQLCipher function is available as `Module._sqlite3_*`
(e.g. `Module._sqlite3_open`, `Module._sqlite3_key`, `Module._sqlite3_exec`),
and every public leancrypto function as `Module._lc_*` (e.g.
`Module._lc_hkdf_alloc`, `Module._lc_aead_encrypt`, plus this project's own
higher-level wrappers `Module._lc_wasm_aead_encrypt`/`_decrypt`/
`_hkdf_sha3_512`/`_key_size`/`_nonce_size`/`_tag_size` from
`leancrypto_wasm_api.c`). String/byte-buffer marshaling uses the standard
Emscripten runtime helpers (`_malloc`/`_free`, `stringToUTF8`/`UTF8ToString`,
`getValue`/`setValue`) — see `wasm/test-roundtrip.mjs` for worked examples
of both APIs.

## Known limitations

- **No persistent storage backend.** This build relies on Emscripten's
  default in-memory MEMFS for file I/O — databases exist only for the
  lifetime of the loaded module instance (comparable to `:memory:`, just
  backed by a real file path within that instance). There is no OPFS/IDBFS
  integration (that's a substantial part of what makes `ext/wasm/`'s own
  build so much larger) — a real persistent, browser-usable storage layer
  is a natural follow-up but is out of scope here.
- **Verified under Node.js only.** Not yet tested in an actual browser
  environment.
- **No JS-side OO wrapper.** Callers use the raw exported C functions
  directly (see above), not a higher-level JS API like `ext/wasm/`'s OO1
  bindings.
- Everything in `doc/crypto.md`'s "Known limitations" (Linux/Emscripten
  only, no migration path from AES-256 SQLCipher databases, AAD does not
  bind the SQLite page number, etc.) applies equally here.
