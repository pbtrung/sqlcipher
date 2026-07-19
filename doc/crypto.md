# SQLCipher crypto backend: leancrypto (Ascon-Keccak-512 + HKDF-SHA3-512)

## Status

This build of SQLCipher uses a single, non-optional crypto provider built from
[leancrypto](https://github.com/smuellerDD/leancrypto), vendored as a git
submodule at `third_party/leancrypto` and compiled from source. There is no
OpenSSL / LibTomCrypt / CommonCrypto backend, no runtime backend selection,
and no build-time switch to select a different backend. This build targets
**Linux only**.

This is a breaking change to both the on-disk file format and the keying
model of earlier SQLCipher (AES-256-CBC + HMAC-SHA512 + PBKDF2). There is no
automatic migration path from an AES-256 SQLCipher database to this format.

## Algorithms

| Purpose | Primitive |
|---|---|
| AEAD cipher | leancrypto Ascon-Keccak, 512-bit variant (`lc_ascon_keccak`, `hash = lc_sha3_512`) |
| KDF | HKDF-SHA3-512 (`lc_hkdf`, `hash = lc_sha3_512`) |
| Key size | 64 bytes |
| Nonce size | 64 bytes |
| Tag size | 64 bytes |
| Master key (user-supplied) | ≥ 256 random bytes, supplied raw (no passphrase stretching) |
| Per-page salt randomness | `getrandom(2)` Linux syscall, called directly (not via leancrypto) |

### Ascon-Keccak is not standard Ascon

leancrypto implements NIST-standard Ascon-128/128a (16-byte key/nonce/tag)
*and*, separately, a leancrypto-original construction it calls **Ascon-Keccak**:
Ascon's AEAD sponge structure with the Ascon permutation replaced by
Keccak-p[1600,24] (the SHA-3 permutation). With a 64-byte key, Ascon-Keccak
uses SHA3-512 internally and accepts a caller-selected nonce and tag length in
the range 16–64 bytes. This is the only leancrypto primitive that reaches a
64-byte key/nonce/tag, so it is what this project means whenever it says
"Ascon-Keccak 64/64/64". It is **not interoperable with, and shares no test
vectors with, standard NIST Ascon.**

## Key provisioning

The application must supply exactly one raw high-entropy master key, at least
256 bytes long, from its own configuration (e.g. `PRAGMA key = x'...'` with a
512+ hex-character blob, or the equivalent `sqlite3_key()` call). There is:

- no passphrase-based key derivation (no PBKDF2, no password stretching),
- no minimum-entropy checking beyond a length check (≥ 256 bytes) — the
  application is responsible for generating this key from a real CSPRNG,
- no key storage or caching beyond what SQLCipher already does in memory for
  an open connection.

Keys shorter than 256 bytes are rejected at `PRAGMA key` time with an error.

## Per-page blob format

SQLite requires random access to individual, independently-writable pages, so
the "blob" in this design is **one SQLite page**, not the whole database
file. Every time a page is written, a fresh random 64-byte salt is generated
for that page.

```
ciphertext (var)    page_size - reserve_size bytes
magic (2 bytes)     0x54 0x58 ("TX")
version (2 bytes)   major.minor, e.g. 0x01 0x00 = v1.0
salt (64 bytes)     random per page, fresh on every write, HKDF input salt
tag (64 bytes)      Ascon-Keccak authentication tag
```

`magic`, `version`, `salt`, and `tag` all live in the page's *reserve* region
(the same trailing bytes SQLite already reserves per page for the codec,
exactly as IV+HMAC did in the previous AES design) —
`reserve_size = magic(2) + version(2) + salt(64) + tag(64) = 132` bytes, with
no block-size rounding (Ascon-Keccak has no block-alignment requirement).
This layout is identical for **every** page, including page 1 — there is no
special per-database salt storage and no *leading* plaintext prefix at the
start of the file (see "Why there is no on-disk plaintext header" below;
that section is about avoiding a prefix at the *start* of page 1 specifically
— it does not apply to the reserve region, which was always fully opaque to
SQLite's own page-1 parsing regardless of what the codec puts there).

`magic` and `version` are written fresh from the fixed `CIPHER_MAGIC_0/1`/
`CIPHER_VERSION_MAJOR/MINOR` compile-time constants on every encrypt, and
read back and checked against those same constants on every decrypt (a page
whose on-disk magic/version don't match is rejected outright, before an AEAD
call is even attempted) — the same way `salt` is generated fresh on encrypt
and read back on decrypt.

Additional Data (AD) passed to the AEAD call:

```
AD = magic (2) || version (2) || salt (64)   -> 68 bytes total
```

### Why there is no on-disk plaintext header

Page 1 of every SQLite database has a 100-byte header that includes not just
a fixed magic string (bytes 0-15) but real, per-database mutable state:
schema cookie, `user_version`, freelist bookkeeping, autovacuum/incremental-
vacuum tracking, default page cache size, text encoding, and `application_id`
all live at fixed offsets between byte 16 and byte 99. The *original*
AES-256 SQLCipher design got away with a 16-byte plaintext prefix (holding
the database-wide KDF salt) precisely because 16 bytes exactly matches the
length of SQLite's own fixed magic string and nothing else — bytes 16-99
were always part of the normally-encrypted page content.

An earlier version of this design tried to widen that prefix to 68 bytes to
carry `magic||version||salt` in the clear at the start of the file. That
silently swallows real database state (schema cookie, `user_version`, etc.)
into the "never encrypted, reconstructed with defaults on read" region —
concretely, `PRAGMA user_version` stopped surviving a reopen when this was
tested, which is an unacceptable correctness regression, not a cosmetic one.

Because this design derives a fresh, independent key and nonce for **every**
page from an already-high-entropy master key (see below) rather than
deriving a single database-wide key from a database-wide salt, there is no
cryptographic bootstrapping problem that requires any salt to be readable
before decryption can begin: page 1's own magic, version, salt, and tag live
in page 1's own reserve region exactly like any other page's, which is
already stored in the clear (as it must be, to make decryption possible at
all) without requiring a separate leading plaintext prefix. Page 1 is
therefore encrypted uniformly with every other page, with no special-cased
plaintext region, no reconstructed
"fake" header fields, and no data loss.

## Per-page key/nonce derivation

Given the master key `K` (≥256 bytes, supplied by the application) and a
page's fresh random 64-byte `salt`:

```
PRK        = HKDF-Extract-SHA3-512(salt = salt, ikm = K)
page_key   = HKDF-Expand-SHA3-512(PRK, info = "sqlcipher-leancrypto-key-v1",   L = 64)
page_nonce = HKDF-Expand-SHA3-512(PRK, info = "sqlcipher-leancrypto-nonce-v1", L = 64)
```

`page_key` and `page_nonce` are then used as the Ascon-Keccak-512 key and
nonce respectively, with the AEAD call over the page's plaintext and the
68-byte AD above, producing the ciphertext and 64-byte tag stored in the
blob. Deriving the key and nonce from independent `info` labels (rather than
reusing the salt bytes directly as the nonce) avoids using one random value
for two different cryptographic roles.

On decrypt, the salt is read back out of the stored page, the same
derivation is repeated, and the AEAD decrypt call both recovers the plaintext
and verifies the tag; any mismatch (wrong key, corrupted page, wrong salt) is
a hard authentication failure.

## Known limitations

- **The Additional Data does not include the SQLite page number.** Per the
  exact format specified for this project, `AD = magic || version || salt`
  only. Because each page's AEAD key is already unique (freshly derived from
  a random salt on every write), an attacker who can read and write the raw
  database file could copy one page's entire on-disk blob (`salt ||
  ciphertext || tag`) onto a different page's slot, and it would still
  decrypt and authenticate successfully there — SQLCipher's prior
  HMAC-over-(ciphertext ‖ IV ‖ page-number) design prevented exactly this
  class of page-reordering/splicing attack. This design intentionally omits
  that binding to match the specified format; it is documented here as a
  known, accepted tradeoff rather than an oversight. A future revision could
  add the page number to the AD (and to the HKDF `info` strings) to close
  this gap without changing the on-disk field layout.
- No migration path from AES-256 SQLCipher databases.
- Linux-only for the native build; no Windows/macOS build path is provided
  or supported. There is also an Emscripten/WASM build (`tool/build-wasm.sh`,
  see `wasm/README.md`) that compiles the same codec + leancrypto to a
  WASM module and has been verified end to end under Node.js; it has no
  persistent storage backend (Emscripten's in-memory MEMFS only) and has
  not been tested in an actual browser.
- **Rare, pre-existing FTS5 test flakiness under heavy statement-journal
  churn, unrelated to this migration.** `ext/fts5/test/fts5aa.test`'s test
  14.2 (200 iterations of `BEGIN; CREATE TABLE; ROLLBACK;` inside a live
  FTS5 MATCH cursor, with a tiny FTS5-internal `pgsz`) fails with "database
  disk image is malformed" roughly 1 time in 15-60 runs. This was
  investigated in depth (see `doc/plan.md`) and confirmed, by running the
  identical test 60+ times against the unmodified pre-migration AES-256/
  OpenSSL baseline, to fail at a similar (in one comparison, higher) rate
  there too — it is a latent SQLite/pager/FTS5 interaction issue that
  predates this migration and is independent of which crypto provider is
  in use. It is not fixed as part of this work; flagged here for anyone
  investigating similar-looking failures in the future so they don't
  mistake it for a crypto regression.

## Build

leancrypto is vendored as a git submodule at `third_party/leancrypto` and
built from source as a static library (`libleancrypto.a`) via its own Meson
build, invoked from `main.mk`. Only the subsystems needed here are enabled:
Ascon-Keccak AEAD, SHA3, and HKDF. Everything else (ML-KEM, ML-DSA, SLH-DSA,
BIKE, HQC, Curve25519/Curve448, the ASN.1/X.509/PKCS7/PKCS8 parsers — which
are GPLv2-licensed and must stay disabled to keep the vendored tree fully
permissive/BSD-compatible —, Rust bindings, EFI support, the `apps`/`tests`
targets, and the `drng`/entropy-source subsystem, since per-page salts are
generated via a direct `getrandom(2)` syscall rather than leancrypto's own
RNG — see `doc/plan.md`'s "Post-implementation hardening" section for why)
is disabled at `meson setup` time. There is no dependency on a
system-installed leancrypto package.
