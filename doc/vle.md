# Value-level encryption (VLE) and encrypted virtual tables

## Status

This is a from-scratch reimplementation of two features publicly documented
as SQLCipher Commercial/Enterprise-only add-ons:

- https://www.zetetic.net/sqlcipher/value-level-encryption/
- https://www.zetetic.net/sqlcipher/encrypted-virtual-tables/

Only the public documentation was consulted; no proprietary/commercial source
was available or used. Function names and the virtual-table SQL surface
follow the publicly documented shape for familiarity. The cryptographic
construction underneath is entirely this project's own: it reuses the
leancrypto-based AEAD codec design from `doc/crypto.md` (Ascon-Keccak-512 +
HKDF-SHA3-512) rather than the commercial product's AES-256-CBC +
HMAC-SHA512 + PBKDF2 design. See `doc/vle-plan.md` for the build log and any
recorded deviations from the public API surface.

Both features are implemented in `src/sqlcipher_vle.c`, work independently of
`PRAGMA key`/full-database encryption (they are registered unconditionally on
every connection), and can also be layered on top of an already-encrypted
database.

## Per-connection key state

`sqlcipher_vle_key(key)` stores one raw key (BLOB, or `x'...'`/hex TEXT) as
persistent state on the calling `sqlite3*` connection, used as the default key
by `sqlcipher_vle_encrypt()`/`_decrypt()` when no explicit key argument is
given. It is zeroed (`sqlcipher_memset`) before being overwritten or on
connection close. There is no key storage across connections/processes and no
key-derivation-from-the-main-codec-key path — VLE keys are entirely
independent of any `PRAGMA key` in effect on the same connection.

- `VLE_MIN_KEY_SZ` = 32 bytes, `VLE_MAX_KEY_SZ` = 8192 bytes.
- Unlike the main per-database codec key (`CIPHER_MIN_KEY_SZ` = 256 bytes,
  see `doc/crypto.md`), VLE keys are meant for lighter, per-value/per-column
  use — often the direct output of `sqlcipher_vle_kdf()`, or an
  application-managed 256-bit symmetric key — so the floor is set at 32 bytes
  (256 bits), a conventional symmetric-key security level, rather than
  reusing the full-database key's much larger floor. The 8192-byte ceiling
  exists for the same reason as the main key's ceiling: HKDF-Extract accepts
  arbitrary-length input key material, so the cap is purely to keep an
  accidentally huge key from becoming a per-value performance foot-gun, not a
  cryptographic requirement.
- Keys outside this range are rejected immediately with `sqlite3_result_error`
  and no state is changed.

## SQL functions

All functions are registered on every connection via `sqlite3_auto_extension`,
independent of `PRAGMA key`.

### `sqlcipher_vle_random(n)` -> BLOB

Returns `n` cryptographically random bytes from the active `sqlcipher_provider`'s
`random()` call (leancrypto backend: `getrandom(2)`/`getentropy()`, see
`doc/crypto.md`). `n` must be in `1..65536`.

### `sqlcipher_vle_kdf(ikm, salt[, out_sz[, info]])` -> BLOB

Derives `out_sz` bytes (default 32, max 4096) of key material from `ikm` via
`HKDF-Extract-SHA3-512(salt, ikm)` followed by `HKDF-Expand-SHA3-512(PRK, info,
out_sz)`, using the provider's `hkdf()` call. `info` defaults to empty.
Deterministic: identical `(ikm, salt, out_sz, info)` always produces identical
output; changing `salt` or `info` changes the output.

This is the equivalent of the public API's `sqlcipher_vle_pbkdf2()` — named
`_kdf` instead of `_pbkdf2` because this project's leancrypto build provides
HKDF-SHA3-512, not PBKDF2, and the name should not imply a primitive that
isn't actually used.

### `sqlcipher_vle_key(key)` -> INTEGER (1)

Sets the calling connection's persistent VLE key (see "Per-connection key
state" above). Accepts a BLOB or hex `TEXT` (`x'...'`, decoded the same way
`PRAGMA key` decodes hex-blob-format keys). Errors (and leaves any existing
key untouched) if the decoded length is outside `VLE_MIN_KEY_SZ..VLE_MAX_KEY_SZ`.

### `sqlcipher_vle_encrypt(value[, key[, context]])` -> BLOB

Encrypts `value` (any SQLite storage type, including `NULL`) using `key` if
given, else the connection's persistent VLE key (error if neither is
available). `context` (BLOB/TEXT, default empty) is additional data folded
into the AEAD's AAD for domain separation — e.g. the encrypted virtual table
module uses this to bind a ciphertext to its exact table/column/rowid (see
"Encrypted virtual tables" below); ad hoc callers can use it the same way to
bind a value to a column name, a row id, or any other context that should
cause decryption to fail if the ciphertext is moved elsewhere.

### `sqlcipher_vle_decrypt(blob[, key[, context]])` -> original value

Inverse of `sqlcipher_vle_encrypt()`. `context` must match what was passed to
`sqlcipher_vle_encrypt()` (both feed the same bytes into the AAD). Fails with
`sqlite3_result_error` on: malformed envelope (too short / bad magic/version),
wrong key, wrong `context`, or a corrupted ciphertext/tag — all indistinguishable
failure modes, by design, matching the "corrupted vs. wrong key" ambiguity
already accepted for the main per-page codec (`doc/crypto.md`).

### `sqlcipher_vle_cipher(mode, key, nonce, aad, input)` -> BLOB

Low-level, single AEAD call with no envelope/type-preservation, for advanced
callers who want to manage the nonce and framing themselves:

- `mode = 1` (encrypt): `input` is plaintext; returns `ciphertext || tag`
  (tag is the provider's fixed tag size, 64 bytes, appended at the end).
- `mode = 0` (decrypt): `input` must be `ciphertext || tag` in that same
  layout; returns plaintext, or errors on authentication failure.

This differs from the public API's `sqlcipher_vle_cipher()` (raw AES-256-CBC
block encrypt/decrypt, no authentication) because the underlying primitive
here is AEAD, which structurally always produces/consumes a tag — there is no
"CBC without a MAC" mode to expose. `key` and `nonce` must be exactly the
provider's key/nonce sizes (64 bytes each).

### `sqlcipher_vle_hmac(input, key)` -> BLOB (64 bytes)

Returns `HKDF-Expand-SHA3-512(HKDF-Extract-SHA3-512(salt = "sqlcipher-vle-hmac-v1",
ikm = key), info = input, L = 64)` — a deterministic, keyed integrity tag over
`input`, usable the same way a MAC is (two parties who agree on `key` can
recompute and compare this value to detect tampering). This is **not** a
literal HMAC-SHA512 computation: this project's leancrypto build enables only
AEAD (Ascon-Keccak), SHA3, and HKDF (see `doc/crypto.md`'s "Build" section) and
deliberately does not add leancrypto's separate HMAC module just to back one
function with the literal primitive its name suggests in the public API.

## Value envelope format

Modeled directly on the per-page format in `doc/crypto.md` ("Per-page blob
format"), at value granularity instead of page granularity:

```
magic (2 bytes)     0x56 0x4C ("VL")
version (2 bytes)   0x01 0x00
type (1 byte)       1=INTEGER 2=FLOAT 3=TEXT 4=BLOB 5=NULL
salt (64 bytes)     random per value, fresh on every encrypt, HKDF salt input
tag (64 bytes)      Ascon-Keccak-512 authentication tag
ciphertext (var)    AEAD ciphertext of the serialized value (0 bytes for NULL)
```

Serialization before encryption: INTEGER as 8-byte big-endian `sqlite3_value_int64`;
FLOAT as the 8 raw bytes of `sqlite3_value_double`; TEXT/BLOB as their raw
bytes (length is implicit from the envelope's total length minus the fixed
header); NULL as zero bytes. Deserialization on decrypt reverses this and
calls the matching `sqlite3_result_*`.

Additional Data passed to the AEAD call:

```
AD = magic (2) || version (2) || type (1) || context (var, caller-supplied, default empty)
```

## Per-value key/nonce derivation

Given a key `K` (32-8192 bytes) and the value's fresh random 64-byte `salt`,
identical in structure to the per-page derivation in `doc/crypto.md`:

```
PRK        = HKDF-Extract-SHA3-512(salt = salt, ikm = K)
value_key   = HKDF-Expand-SHA3-512(PRK, info = "sqlcipher-vle-key-v1",   L = 64)
value_nonce = HKDF-Expand-SHA3-512(PRK, info = "sqlcipher-vle-nonce-v1", L = 64)
```

## Encrypted virtual tables

```sql
CREATE VIRTUAL TABLE app_secrets USING sqlcipher_vle(
  CREATE TABLE IF NOT EXISTS app_secrets(id, name, secret),
  '1'   -- optional: comma-separated 1-based column ordinals excluded from encryption
);
SELECT sqlcipher_vle_key('...');   -- required before any DML/query on the table
INSERT INTO app_secrets VALUES (1, 'api-key', 'super-secret-value');
SELECT name, secret FROM app_secrets WHERE id = 1;
```

- A real `sqlite3_module` (`xCreate`/`xConnect`/`xBestIndex`/`xFilter`/
  `xColumn`/`xUpdate`/`xShadowName`), not a view/trigger simulation — modeled
  on `ext/rtree/rtree.c`'s shadow-table pattern.
- Backing storage is a real table, `<name>_shadow`, with the same column
  count as the declared virtual table. Columns not listed in the excluded-
  column-ordinal argument are stored as VLE-encrypted `BLOB`s (the envelope
  format above); excluded columns are stored as-is (plaintext), for columns
  the application wants to filter/index directly (e.g. a lookup key).
- Each encrypted cell's AAD `context` is `table name || column ordinal ||
  rowid`, binding the ciphertext to its exact location — a cell copied into a
  different row or column fails to decrypt. This directly reuses the
  page-splicing lesson recorded in `doc/crypto.md`'s "Known limitations"
  (folding `pgno` into the page AAD), applied at cell granularity.
- `xBestIndex`/`xFilter` push down only rowid equality (`WHERE rowid = ?` or
  `WHERE id = ?` when `id` is the `INTEGER PRIMARY KEY`) to the shadow
  table's own `WHERE` clause. This is narrower than originally planned here:
  excluded (plaintext) column equality is *not* pushed down as of the first
  implementation — every other constraint, including on excluded columns,
  falls back to a full shadow-table scan with SQLite re-checking the
  constraint itself after `xColumn` returns. This is correct (no wrong
  results) but not as optimized as it could be; a real index on the shadow
  table's excluded columns still speeds up *manual* queries run directly
  against `<table>_shadow`, just not through the virtual table's own query
  planner integration yet. Encrypted columns are never filterable at the SQL
  level regardless (each cell's ciphertext differs even for equal plaintext
  values, since the salt is fresh per cell) — matching the public API's
  documented limitation that encrypted columns generally cannot be indexed
  or filtered directly. Every query touching an encrypted column decrypts it
  row-by-row after the shadow-table scan.
- `xUpdate`'s insert path is two-step: insert the row with excluded columns
  set and encrypted columns temporarily `NULL`, to obtain the assigned
  rowid, then `UPDATE` the shadow row's encrypted columns using that rowid in
  the AAD — the same "insert now, backfill" shape used by other shadow-table
  vtab modules (fts5, rtree) for columns whose stored value depends on the
  row's own identity.
- Querying or modifying the table before `sqlcipher_vle_key()` has been
  called on the connection fails cleanly with `sqlite3_result_error`, before
  any shadow-table access is attempted.

## Known limitations

- Encrypted columns cannot be indexed or used in `WHERE`/`JOIN` predicates
  pushed to SQLite's query planner. This matches the public commercial
  feature's own documented limitation, not a shortcut taken here.
- As implemented, only `rowid` equality is actually pushed down through
  `xBestIndex`/`xFilter` — excluded (plaintext) column equality is *not*
  pushed down yet, despite that being the original plan (see "Encrypted
  virtual tables" above). Queries filtering on an excluded column still
  return correct results (SQLite falls back to a full shadow-table scan and
  re-checks the constraint itself), just without index acceleration through
  the virtual table layer.
- No support for `ALTER TABLE` on an encrypted virtual table (adding/removing
  columns, changing the excluded-column list) — a table's encrypted/excluded
  column layout is fixed at `CREATE VIRTUAL TABLE` time. Migrating requires
  creating a new table and copying data through `sqlcipher_vle_decrypt()`/
  `_encrypt()` at the SQL level.
- Same same-cell-rollback caveat as the per-page codec (`doc/crypto.md`):
  binding a cell's AAD to `table || column || rowid` prevents moving a cell's
  ciphertext to a *different* location, but does not by itself prevent
  replaying an *old* ciphertext back into its *own* original location — that
  requires a whole-database freshness mechanism, which neither this codec nor
  the per-page codec provides.
- No PBKDF2/password-stretching path — `sqlcipher_vle_kdf()` is HKDF-based
  (see "Deviations" in `doc/vle-plan.md`). Applications needing
  password-based key derivation with deliberate work-factor stretching should
  do so before calling `sqlcipher_vle_key()`, using their own KDF of choice.
- Not evaluated against, and makes no claim of interoperability with, the
  commercial product's on-disk VLE blob format or virtual table schema.
