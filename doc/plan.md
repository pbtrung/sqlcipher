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

## Notes on WASM (future work, out of scope now)

leancrypto's Meson build has a `disable-asm` option that compiles only
portable C (no architecture-specific assembly), which is the natural
starting point for a future Emscripten cross-build via a custom Meson
cross-file. This has not been validated as part of this work (scope is
Linux-only); it is recorded here so a future WASM port has a documented
starting hypothesis rather than starting from zero.

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
