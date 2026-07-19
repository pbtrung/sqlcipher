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
magic (2 bytes)     0x54 0x58  ("TX")
version (2 bytes)   major . minor, e.g. 0x01 0x00 = v1.0
salt (64 bytes)     random per page, fresh on every write, HKDF input salt
ciphertext (var)    page_size - reserve_size bytes
tag (64 bytes)      Ascon-Keccak authentication tag
```

Additional Data (AD) passed to the AEAD call:

```
AD = magic (2) || version (2) || salt (64)   -> 68 bytes total
```

The first page of the database file carries this same `magic || version ||
salt` as its plaintext prefix (68 bytes, replacing the historic 16-byte raw
KDF-salt prefix used by AES-256 SQLCipher) so that the file format is
self-describing. Every subsequent page reserves `salt(64) + tag(64) = 128`
bytes at the end of the page for its own header/tag (the "reserve" region);
there is no separate HMAC region and no block-size rounding (Ascon-Keccak has
no block-alignment requirement).

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
- Linux-only; no Windows/macOS build path is provided or supported.
- No WASM/Emscripten build has been validated for the vendored leancrypto
  submodule (see `doc/plan.md` for notes on a possible future path via
  Meson cross-files).

## Build

leancrypto is vendored as a git submodule at `third_party/leancrypto` and
built from source as a static library (`libleancrypto.a`) via its own Meson
build, invoked from `main.mk`. Only the subsystems needed here are enabled:
Ascon-Keccak AEAD, SHA3, and HKDF. Everything else (ML-KEM, ML-DSA, SLH-DSA,
BIKE, HQC, Curve25519/Curve448, the ASN.1/X.509/PKCS7/PKCS8 parsers — which
are GPLv2-licensed and must stay disabled to keep the vendored tree fully
permissive/BSD-compatible —, Rust bindings, EFI support, the `apps` and
`tests` targets, and the `drng`/entropy-source subsystem, since this project
never generates keys internally) is disabled at `meson setup` time. There is
no dependency on a system-installed leancrypto package.
