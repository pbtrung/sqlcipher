/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/*
** This is the leancrypto-based crypto provider: Ascon-Keccak-512 AEAD
** (64-byte key/nonce/tag) keyed via HKDF-SHA3-512. See doc/crypto.md
** for the full cryptographic design (blob format, AAD, derivation).
** leancrypto is vendored as a git submodule (third_party/leancrypto)
** and built from source; this is the only crypto provider in this
** build (Linux only).
*/
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_LEANCRYPTO
#include "sqliteInt.h"
#include "sqlcipher.h"
#include "lc_ascon_keccak.h" /* amalgamator: dontcache */
#include "lc_hkdf.h" /* amalgamator: dontcache */
#include <errno.h> /* amalgamator: dontcache */
#ifdef __EMSCRIPTEN__
#include <unistd.h> /* amalgamator: dontcache */
#else
#include <sys/random.h> /* amalgamator: dontcache */
#endif

#define LEANCRYPTO_KEY_SZ 64
#define LEANCRYPTO_NONCE_SZ 64
#define LEANCRYPTO_TAG_SZ 64

static const char* sqlcipher_leancrypto_get_provider_name(void *ctx) {
  return "leancrypto";
}

static const char* sqlcipher_leancrypto_get_provider_version(void *ctx) {
  return "leancrypto 1.8.0";
}

static int sqlcipher_leancrypto_ctx_init(void **ctx) {
  return SQLITE_OK;
}

static int sqlcipher_leancrypto_ctx_free(void **ctx) {
  return SQLITE_OK;
}

static int sqlcipher_leancrypto_fips_status(void *ctx) {
  return 0;
}

/* generate a defined number of random bytes for per-page salts, via the
** getrandom(2) Linux syscall directly (this build is Linux-only, see
** doc/crypto.md).
**
** Two other sources were tried and rejected before this one:
**
** - leancrypto's own lc_rng_generate(lc_seeded_rng, ...) (xdrbg): found,
**   via a reproducible AddressSanitizer global-buffer-overflow only
**   reachable deep inside SQLite's real pager/journal call stack (never in
**   a shallow standalone stress test), to corrupt memory near leancrypto's
**   own xdrbg256 global state -- its internal xdrbg implementation uses
**   the same class of stack-allocation macro that lc_aead_zero()/lc_hkdf()
**   were also found to misbehave with (see
**   sqlcipher_leancrypto_aead_encrypt/decrypt and sqlcipher_leancrypto_hkdf
**   above), compounded by xdrbg's DRNG state being global/shared rather
**   than per-call.
** - SQLite's own sqlite3_randomness(): deadlocks the very first time it's
**   called if that first call happens from within sqlcipher_extra_init()
**   (which this codec's core unconditionally does once at registration, to
**   seed its own internal secure-wipe PRNG -- see the
**   default_provider->random() calls in sqlcipher_extra_init()). That
**   first call needs sqlite3_vfs_find(), which needs a mutex that isn't
**   yet safe to acquire from inside SQLite's own sqlite3_initialize() ->
**   SQLITE_EXTRA_INIT call chain -- confirmed via gdb: the hang is
**   sqlite3_vfs_find() -> sqlite3_mutex_enter() blocking forever.
**
** getrandom() needs no leancrypto state and no SQLite VFS/mutex machinery,
** sidestepping both issues entirely; nothing about the per-page salt
** requires it to come from either leancrypto or SQLite's own PRNG. See
** doc/crypto.md and doc/plan.md for the full investigation notes.
**
** Under Emscripten/WASM (see wasm/README.md) there is no getrandom(2)
** syscall at all, so this uses Emscripten's built-in getentropy() libc
** shim instead (itself backed by the browser's crypto.getRandomValues()
** or Node's crypto.randomFillSync()) -- the same entropy source used by
** the reference secbits/leancrypto seeded_rng_wasm.c this project's own
** src/crypto_leancrypto_rng_wasm.c is adapted from. getentropy() is
** capped at 256 bytes per POSIX, hence the chunking loop. The native
** Linux getrandom() path above is untouched by this. */
#ifdef __EMSCRIPTEN__
static int sqlcipher_leancrypto_random(void *ctx, void *buffer, int length) {
  unsigned char *out = (unsigned char *)buffer;
  int remaining = length;

  while(remaining > 0) {
    int chunk = remaining > 256 ? 256 : remaining;
    if(getentropy(out, (size_t)chunk) != 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_random: getentropy() failed, errno=%d", errno);
      return SQLITE_ERROR;
    }
    out += chunk;
    remaining -= chunk;
  }
  return SQLITE_OK;
}
#else
static int sqlcipher_leancrypto_random(void *ctx, void *buffer, int length) {
  unsigned char *out = (unsigned char *)buffer;
  int remaining = length;

  while(remaining > 0) {
    ssize_t rc = getrandom(out, (size_t)remaining, 0);
    if(rc < 0) {
      if(errno == EINTR) continue;
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_random: getrandom() failed, errno=%d", errno);
      return SQLITE_ERROR;
    }
    out += rc;
    remaining -= (int)rc;
  }
  return SQLITE_OK;
}
#endif

/* getrandom(2) draws directly from the kernel CSPRNG and has no concept of
** caller-supplied additional entropy to mix in, so PRAGMA cipher_add_random
** is a no-op for this provider, matching the precedent of the historic
** CommonCrypto provider (which also had no add-entropy hook). */
static int sqlcipher_leancrypto_add_random(void *ctx, const void *buffer, int length) {
  return SQLITE_OK;
}

/* HKDF-SHA3-512 (RFC 5869 extract-then-expand).
**
** Note: this uses leancrypto's heap-allocating lc_hkdf_alloc()/
** lc_hkdf_zero_free() plus the separate extract/expand calls, rather than
** the one-shot lc_hkdf() convenience function. lc_hkdf() is internally
** implemented via the LC_HKDF_CTX_ON_STACK() stack-allocation macro, the
** same family of macro that lc_aead_zero() was found (via a reproducible
** AddressSanitizer global-buffer-overflow, only when called from deep
** inside SQLite's real call stack) to misbehave with -- see
** sqlcipher_leancrypto_aead_encrypt/decrypt above and the migration's
** test-pass notes. Heap allocation avoids the same class of risk here. */
static int sqlcipher_leancrypto_hkdf(
  void *ctx,
  const unsigned char *ikm, int ikm_sz,
  const unsigned char *salt, int salt_sz,
  const unsigned char *info, int info_sz,
  int key_sz, unsigned char *key
) {
  struct lc_hkdf_ctx *hkdf_ctx = NULL;
  int rc;

  if((rc = lc_hkdf_alloc(lc_sha3_512, &hkdf_ctx)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_hkdf: lc_hkdf_alloc() returned %d", rc);
    return SQLITE_ERROR;
  }

  rc = lc_hkdf_extract(hkdf_ctx, ikm, (size_t)ikm_sz, salt, (size_t)salt_sz);
  if(rc == 0) {
    rc = lc_hkdf_expand(hkdf_ctx, info, (size_t)info_sz, key, (size_t)key_sz);
  }
  lc_hkdf_zero_free(hkdf_ctx);

  if(rc != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_hkdf: extract/expand returned %d", rc);
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

/*
** Note: these use leancrypto's heap-allocating lc_ak_alloc_taglen()/
** lc_aead_zero_free() rather than the LC_AK_CTX_ON_STACK_TAGLEN() stack-
** allocation macro. The stack macro was found, via a reproducible
** AddressSanitizer global-buffer-overflow inside lc_aead_zero() (corrupting
** memory near unrelated leancrypto globals), to misbehave when invoked from
** deep inside SQLite's real call stack (pager/journal/VDBE frames) even
** though a shallow standalone stress-test loop never reproduced it -- see
** the migration's test-pass notes. Heap allocation avoids whatever stack
** layout/alignment assumption the macro was violating, at the cost of one
** malloc/free pair per page encrypt/decrypt call.
*/
static int sqlcipher_leancrypto_aead_encrypt(
  void *ctx,
  const unsigned char *key, int key_sz,
  const unsigned char *nonce, int nonce_sz,
  const unsigned char *aad, int aad_sz,
  const unsigned char *in, int in_sz,
  unsigned char *out,
  unsigned char *tag, int tag_sz
) {
  int rc;
  struct lc_aead_ctx *aead_ctx = NULL;

  if((rc = lc_ak_alloc_taglen(lc_sha3_512, (uint8_t)tag_sz, &aead_ctx)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_encrypt: lc_ak_alloc_taglen() returned %d", rc);
    return SQLITE_ERROR;
  }

  if((rc = lc_aead_setkey(aead_ctx, key, (size_t)key_sz, nonce, (size_t)nonce_sz)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_encrypt: lc_aead_setkey() returned %d", rc);
    lc_aead_zero_free(aead_ctx);
    return SQLITE_ERROR;
  }

  rc = lc_aead_encrypt(aead_ctx, in, out, (size_t)in_sz, aad, (size_t)aad_sz, tag, (size_t)tag_sz);
  lc_aead_zero_free(aead_ctx);
  if(rc < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_encrypt: lc_aead_encrypt() returned %d", rc);
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static int sqlcipher_leancrypto_aead_decrypt(
  void *ctx,
  const unsigned char *key, int key_sz,
  const unsigned char *nonce, int nonce_sz,
  const unsigned char *aad, int aad_sz,
  const unsigned char *in, int in_sz,
  unsigned char *out,
  const unsigned char *tag, int tag_sz
) {
  int rc;
  struct lc_aead_ctx *aead_ctx = NULL;

  if((rc = lc_ak_alloc_taglen(lc_sha3_512, (uint8_t)tag_sz, &aead_ctx)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_decrypt: lc_ak_alloc_taglen() returned %d", rc);
    return SQLITE_ERROR;
  }

  if((rc = lc_aead_setkey(aead_ctx, key, (size_t)key_sz, nonce, (size_t)nonce_sz)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_decrypt: lc_aead_setkey() returned %d", rc);
    lc_aead_zero_free(aead_ctx);
    return SQLITE_ERROR;
  }

  rc = lc_aead_decrypt(aead_ctx, in, out, (size_t)in_sz, aad, (size_t)aad_sz, tag, (size_t)tag_sz);
  lc_aead_zero_free(aead_ctx);
  if(rc < 0) {
    /* -EBADMSG (authentication failure) is the expected/common case for a
    ** wrong key or corrupted/tampered page; log at a lower severity than
    ** other errors would warrant. */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_decrypt: lc_aead_decrypt() returned %d", rc);
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static const char* sqlcipher_leancrypto_get_cipher(void *ctx) {
  return "ascon-keccak-512";
}

static int sqlcipher_leancrypto_get_key_sz(void *ctx) {
  return LEANCRYPTO_KEY_SZ;
}

static int sqlcipher_leancrypto_get_nonce_sz(void *ctx) {
  return LEANCRYPTO_NONCE_SZ;
}

static int sqlcipher_leancrypto_get_tag_sz(void *ctx) {
  return LEANCRYPTO_TAG_SZ;
}

int sqlcipher_leancrypto_setup(sqlcipher_provider *p) {
  p->init = NULL;
  p->shutdown = NULL;
  p->get_provider_name = sqlcipher_leancrypto_get_provider_name;
  p->random = sqlcipher_leancrypto_random;
  p->add_random = sqlcipher_leancrypto_add_random;
  p->hkdf = sqlcipher_leancrypto_hkdf;
  p->aead_encrypt = sqlcipher_leancrypto_aead_encrypt;
  p->aead_decrypt = sqlcipher_leancrypto_aead_decrypt;
  p->get_cipher = sqlcipher_leancrypto_get_cipher;
  p->get_key_sz = sqlcipher_leancrypto_get_key_sz;
  p->get_nonce_sz = sqlcipher_leancrypto_get_nonce_sz;
  p->get_tag_sz = sqlcipher_leancrypto_get_tag_sz;
  p->ctx_init = sqlcipher_leancrypto_ctx_init;
  p->ctx_free = sqlcipher_leancrypto_ctx_free;
  p->fips_status = sqlcipher_leancrypto_fips_status;
  p->get_provider_version = sqlcipher_leancrypto_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
