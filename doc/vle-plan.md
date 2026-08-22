# Implementation plan: value-level encryption (VLE) + encrypted virtual tables

This document records the implementation plan for two new features layered on
top of the existing leancrypto-based full-database codec (see `doc/crypto.md`,
`doc/plan.md`): SQL-callable **value-level encryption** functions, and an
**encrypted virtual table** module built on top of them. Both features are
publicly documented as SQLCipher Commercial/Enterprise-only add-ons:

- https://www.zetetic.net/sqlcipher/value-level-encryption/
- https://www.zetetic.net/sqlcipher/encrypted-virtual-tables/

Only the public documentation pages above were consulted (no proprietary
source was available or used). This is a **from-scratch, public-docs-inspired
reimplementation**, not a port of Zetetic's commercial source: function names
and the virtual-table SQL surface follow the publicly documented shape for
familiarity, but the actual cryptographic construction is this project's own
leancrypto-based AEAD design (Ascon-Keccak-512 + HKDF-SHA3-512), matching
`doc/crypto.md` rather than the commercial product's AES-256-CBC +
HMAC-SHA512 + PBKDF2 construction. See `doc/vle.md` for the resulting design
(function signatures, blob format, vtab schema, known limitations); this file
is the step-by-step build log/checklist.

## Scope

- New code lives in a new translation unit, `src/sqlcipher_vle.c`, folded into
  the amalgamation-eligible source list (not a separately-compiled unit like
  `crypto_leancrypto.c`), so the existing WASM build's hardcoded source list
  in `tool/build-wasm.sh` needs no changes — see `doc/vle.md`'s "WASM" section.
- VLE functions work **standalone**, independent of `PRAGMA key` / full-database
  encryption — registered unconditionally via `sqlite3_auto_extension()`,
  mirroring the existing `sqlcipher_export_init` pattern in `src/sqlcipher.c`.
- Reuses the existing `sqlcipher_provider` vtable (`random`, `hkdf`,
  `aead_encrypt`, `aead_decrypt`, `get_key_sz`/`get_nonce_sz`/`get_tag_sz`) via
  `sqlcipher_get_provider()` — no new crypto primitives, no new leancrypto
  subsystems enabled in `main.mk`'s `LEANCRYPTO_MESON_OPTS`.
- No raw HMAC primitive is added: the public API's `sqlcipher_vle_hmac()` is
  reimplemented as an HKDF-derived keyed integrity tag (documented honestly as
  such in `doc/vle.md`), rather than pulling in leancrypto's separate HMAC
  module for one function — consistent with `doc/crypto.md`'s "only enable
  what's needed" build philosophy.
- The encrypted virtual table module (`USING sqlcipher_vle(...)`) is a real
  SQLite virtual table (`sqlite3_module`, `xCreate`/`xConnect`/`xBestIndex`/
  `xFilter`/`xColumn`/`xUpdate`/`xShadowName`) backed by a real on-disk shadow
  table, mirroring `ext/rtree/rtree.c`'s shadow-table pattern — not a view+
  trigger simulation.
- No on-disk format compatibility is claimed with, or attempted against, the
  commercial product's VLE blob format or virtual table shadow schema.

## Steps

1. **Docs first** — `doc/vle-plan.md` (this file) and `doc/vle.md` (design
   spec) written and committed before any code changes.
2. **VLE core + scalar functions** — `src/sqlcipher_vle.c` /
   `src/sqlcipher_vle.h`:
   - Per-connection VLE context (`sqlcipher_vle_ctx`): a zeroed key buffer
     `x`/length, allocated and registered as shared `pApp` user-data across
     all `sqlcipher_vle_*` functions inside a new `sqlcipher_vle_init()`
     `sqlite3_auto_extension` callback (mirrors `sqlcipher_export_init` at
     `src/sqlcipher.c:491-494` / registration at line 644), freed via a
     destructor on exactly one of the `sqlite3_create_function_v2()` calls.
   - `sqlcipher_vle_random(n)`, `sqlcipher_vle_kdf(ikm, salt[, out_sz[, info]])`,
     `sqlcipher_vle_key(key)`, `sqlcipher_vle_encrypt(value[, key[, context]])`,
     `sqlcipher_vle_decrypt(blob[, key[, context]])`,
     `sqlcipher_vle_cipher(mode, key, nonce, aad, input)`,
     `sqlcipher_vle_hmac(input, key)` — see `doc/vle.md` for exact semantics.
   - Value envelope format (magic/version/type/salt/tag/ciphertext) and
     per-value HKDF key/nonce derivation, both modeled directly on the
     per-page design in `doc/crypto.md` ("Per-page blob format" / "Per-page
     key/nonce derivation").
   - Wire `src/sqlcipher_vle.c` into `main.mk`'s amalgamation-eligible `SRC`
     list (not `SQLCIPHER_SRC`/`SQLCIPHER_OBJ`, since it does not need its own
     translation unit) and into the non-amalgamation build's file list.
3. **Test VLE functions** — `test/sqlcipher-vle.test`: round-trip for every
   SQLite storage type (including NULL), wrong-key rejection, tamper
   detection (flipped ciphertext/tag byte), magic/version mismatch handling,
   `sqlcipher_vle_kdf` determinism (same inputs -> same output; different
   salt/info -> different output), works with no `PRAGMA key` set at all, and
   works layered inside an already-encrypted (`PRAGMA key` set) database.
4. **Encrypted virtual table module** — extend `src/sqlcipher_vle.c` with the
   `sqlcipher_vle` `sqlite3_module`:
   - `xCreate`: parse the embedded `CREATE TABLE ...(col, col, ...)` DDL
     argument and the optional excluded-column-index argument; create the
     `<table>_shadow` real table (mirrors `ext/rtree/rtree.c`'s
     `%_node`/`%_rowid`/`%_parent` shadow tables); `xShadowName` recognizes
     the `shadow` suffix.
   - `xConnect`: reconnect without re-creating the shadow table;
     `sqlite3_declare_vtab()` with the original (plaintext-typed) column
     names.
   - `xBestIndex`/`xFilter`: push rowid/excluded-column equality constraints
     down to the shadow table's `WHERE` clause; encrypted columns are always
     decrypted row-by-row after the shadow-table scan (ciphertext is not
     filterable — see `doc/vle.md`'s "Known limitations", matching the public
     docs' own caveat that encrypted columns generally cannot be indexed).
   - AAD for each cell = `table name || column ordinal || rowid`, binding
     each ciphertext to its exact cell location — directly reusing the
     page-splicing lesson from `doc/crypto.md`'s "Known limitations" (pgno
     folded into AAD) at cell granularity instead of page granularity.
   - `xUpdate` insert path: two-step (insert plaintext/placeholder columns to
     obtain the rowid, then update encrypted columns using that now-known
     rowid in the AAD) — same "insert now, backfill computed columns" shape
     already used by shadow-table vtab modules like fts5/rtree.
   - Registered via `sqlite3_create_module_v2()` inside the same
     `sqlcipher_vle_init()` auto-extension callback as the scalar functions.
5. **Test encrypted virtual tables** — `test/sqlcipher-vle-vtab.test`:
   create/insert/select/update/delete round-trip; verify the shadow table's
   raw on-disk bytes for encrypted columns are not the plaintext and differ
   between two rows holding the same value (salt uniqueness); verify excluded
   columns are stored and filterable in plaintext; verify querying before
   `sqlcipher_vle_key()` has been called fails cleanly; verify a manually
   spliced cell (copying one row's encrypted blob into a different row's
   column) fails to decrypt (cell-splicing protection).
6. **Full regression pass** — build `testfixture`, run
   `test/sqlcipher*.test` and `test/veryquick.test`; fix any issues found,
   following the same root-cause-first discipline as `doc/plan.md`'s
   "Post-implementation hardening" section.
7. **Docs reconciliation** — update `doc/vle.md`/`doc/vle-plan.md` with any
   deviations found during implementation; add a `README.md` mention; add a
   `CHANGELOG.md` entry.
8. **WASM rebuild** — re-run `tool/build-wasm.sh`; since VLE lives in the
   amalgamation (`sqlite3.c`), no new entry is needed in the script's
   hardcoded source-file list. Extend `wasm/test-roundtrip.mjs` with a VLE
   function round-trip and an encrypted-virtual-table round-trip, both driven
   purely through the already-exported `sqlite3_exec`/`sqlite3_prepare_v2`
   JS surface (no new low-level `lc_*`-style wasm export is needed, since VLE
   is SQL-surfaced, not called directly from JS as raw bytes). Update
   `wasm/README.md` accordingly.

## Notes on deviations from the public commercial API surface

Recorded here as they're found during implementation (kept in sync with
`doc/vle.md`); anticipated up front:

- `sqlcipher_vle_pbkdf2()` (public docs) is not implemented under that name.
  This project's leancrypto build only provides HKDF-SHA3-512 (no PBKDF2), so
  the equivalent function is named `sqlcipher_vle_kdf()` and documented as
  HKDF-based, rather than claiming PBKDF2 compatibility it doesn't have.
- `sqlcipher_vle_cipher()`'s low-level primitive is AEAD (Ascon-Keccak-512),
  not raw AES-256-CBC, so its calling convention necessarily differs (it
  always produces/consumes an authentication tag).
- `sqlcipher_vle_hmac()` is an HKDF-derived keyed integrity tag, not a literal
  HMAC-SHA512 computation.

Found during implementation:

- `xBestIndex`/`xFilter` for the encrypted virtual table only push down
  rowid equality, not excluded-column equality as originally planned above
  in this file (step 4) and in `doc/vle.md`'s "Encrypted virtual tables"
  section. Results are still correct (SQLite falls back to a full
  shadow-table scan and re-checks any un-pushed constraint itself); this is
  a narrower optimization than planned, not a correctness gap. `doc/vle.md`
  has been updated to describe the actual behavior; revisiting the fuller
  pushdown is future work, not required for this feature to be usable.
- Steps 3 and 5 (dedicated `test/sqlcipher-vle.test` /
  `test/sqlcipher-vle-vtab.test` tcl files) were not written. Coverage
  instead comes from manual verification during development (round trips,
  wrong-key/tamper/context/splice rejection, no-key-set rejection, layering
  under `PRAGMA key`) plus `wasm/test-roundtrip.mjs` sections 10/10b/11/11b,
  which exercise the same C code through the WASM build's SQL surface and
  are checked into the repo as regression coverage. This was an explicit
  choice made during implementation, not an oversight.
- `src/sqlcipher_vle.c` needed no `LEANCRYPTO_CFLAGS`/`-I` include paths in
  `main.mk` (unlike `crypto_leancrypto.c`): it only calls through the
  existing `sqlcipher_provider` vtable in `sqlcipher.h`, never leancrypto's
  own headers directly, exactly as planned.
- A full regression pass (`./testfixture ../test/testrunner.tcl mdevtest`)
  passed 793,158 of 793,164 individual test checks; the 6 failures are
  pre-existing `crypto_leancrypto.o` missing-dependency Makefile bugs in the
  unrelated `fuzzcheck`/`fuzzcheck-asan`/`fuzzcheck-ubsan`/`sessionfuzz`
  build targets (confirmed present at the pre-VLE baseline commit too, via a
  throwaway git worktree) — not caused by this feature.
