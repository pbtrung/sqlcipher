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
#include "lc_rng.h" /* amalgamator: dontcache */

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

/* generate a defined number of random bytes using leancrypto's seeded,
** OS-entropy-backed DRNG (lc_seeded_rng); reseeding is handled
** automatically and transparently by leancrypto. */
static int sqlcipher_leancrypto_random(void *ctx, void *buffer, int length) {
  if(lc_rng_generate(lc_seeded_rng, NULL, 0, (unsigned char *)buffer, (size_t)length) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_random: lc_rng_generate() failed");
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

/* mix caller-supplied entropy into the seeded DRNG's state */
static int sqlcipher_leancrypto_add_random(void *ctx, const void *buffer, int length) {
  if(lc_rng_seed(lc_seeded_rng, (const unsigned char *)buffer, (size_t)length, NULL, 0) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_add_random: lc_rng_seed() failed");
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

/* HKDF-SHA3-512 (RFC 5869 extract-then-expand) in a single call */
static int sqlcipher_leancrypto_hkdf(
  void *ctx,
  const unsigned char *ikm, int ikm_sz,
  const unsigned char *salt, int salt_sz,
  const unsigned char *info, int info_sz,
  int key_sz, unsigned char *key
) {
  if(lc_hkdf(lc_sha3_512, ikm, (size_t)ikm_sz, salt, (size_t)salt_sz,
             info, (size_t)info_sz, key, (size_t)key_sz) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_hkdf: lc_hkdf() failed");
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

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
  LC_AK_CTX_ON_STACK_TAGLEN(aead_ctx, lc_sha3_512, (uint8_t)tag_sz);

  if((rc = lc_aead_setkey(aead_ctx, key, (size_t)key_sz, nonce, (size_t)nonce_sz)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_encrypt: lc_aead_setkey() returned %d", rc);
    lc_aead_zero(aead_ctx);
    return SQLITE_ERROR;
  }

  rc = lc_aead_encrypt(aead_ctx, in, out, (size_t)in_sz, aad, (size_t)aad_sz, tag, (size_t)tag_sz);
  lc_aead_zero(aead_ctx);
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
  LC_AK_CTX_ON_STACK_TAGLEN(aead_ctx, lc_sha3_512, (uint8_t)tag_sz);

  if((rc = lc_aead_setkey(aead_ctx, key, (size_t)key_sz, nonce, (size_t)nonce_sz)) < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "sqlcipher_leancrypto_aead_decrypt: lc_aead_setkey() returned %d", rc);
    lc_aead_zero(aead_ctx);
    return SQLITE_ERROR;
  }

  rc = lc_aead_decrypt(aead_ctx, in, out, (size_t)in_sz, aad, (size_t)aad_sz, tag, (size_t)tag_sz);
  lc_aead_zero(aead_ctx);
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
