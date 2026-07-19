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
** Thin, byte-buffer-oriented WASM wrapper around the vendored leancrypto
** submodule's Ascon-Keccak-512 AEAD and HKDF-SHA3-512 API -- the same two
** primitives src/crypto_leancrypto.c uses for the SQLCipher codec (see
** doc/crypto.md). Exported (see tool/build-wasm.sh's EXPORTED_FUNCTIONS)
** alongside the SQLite/SQLCipher C API in the same WASM module, so JS
** callers can do raw AEAD/HKDF operations directly, independent of
** opening a database -- e.g. to encrypt/decrypt arbitrary blobs client
** side, matching how the reference secbits/leancrypto WASM build is used.
**
** These wrappers deliberately hide leancrypto's opaque "struct lc_hash *"/
** "struct lc_aead_ctx *" pointers behind plain byte buffers + lengths, and
** hardcode SHA3-512 (the only hash this project's leancrypto build
** compiles in -- see LEANCRYPTO_MESON_OPTS in main.mk), since that's the
** only configuration actually linkable into this WASM module anyway.
** Same heap-allocating API pattern (lc_ak_alloc_taglen/lc_aead_zero_free,
** lc_hkdf_alloc/lc_hkdf_zero_free) as src/crypto_leancrypto.c, for the
** same reason: avoids a confirmed AddressSanitizer bug in leancrypto's
** LC_AK_CTX_ON_STACK_TAGLEN()/LC_HKDF_CTX_ON_STACK() stack macros.
*/
#include <emscripten.h>
#include "lc_ascon_keccak.h"
#include "lc_hkdf.h"

/*
** AEAD encrypt: key/nonce/tag lengths are each 16-64 bytes (Ascon-Keccak-512
** accepts a caller-selected length in that range once keylen == 64; see
** doc/crypto.md). Returns 0 on success, a negative leancrypto error code
** otherwise. `out` must be at least `data_len` bytes; `tag_out` at least
** `tag_len` bytes.
*/
EMSCRIPTEN_KEEPALIVE
int lc_wasm_aead_encrypt(
  const unsigned char *key, int key_len,
  const unsigned char *nonce, int nonce_len,
  const unsigned char *aad, int aad_len,
  const unsigned char *in, int data_len,
  unsigned char *out,
  unsigned char *tag_out, int tag_len
) {
  struct lc_aead_ctx *ctx = NULL;
  int rc;

  if((rc = lc_ak_alloc_taglen(lc_sha3_512, (uint8_t)tag_len, &ctx)) < 0) {
    return rc;
  }
  if((rc = lc_aead_setkey(ctx, key, (size_t)key_len, nonce, (size_t)nonce_len)) < 0) {
    lc_aead_zero_free(ctx);
    return rc;
  }
  rc = lc_aead_encrypt(ctx, in, out, (size_t)data_len, aad, (size_t)aad_len, tag_out, (size_t)tag_len);
  lc_aead_zero_free(ctx);
  return rc < 0 ? rc : 0;
}

/*
** AEAD decrypt + verify. Returns 0 on successful authentication, a
** negative leancrypto error code otherwise (-EBADMSG for a tag mismatch,
** i.e. wrong key or tampered/corrupted data).
*/
EMSCRIPTEN_KEEPALIVE
int lc_wasm_aead_decrypt(
  const unsigned char *key, int key_len,
  const unsigned char *nonce, int nonce_len,
  const unsigned char *aad, int aad_len,
  const unsigned char *in, int data_len,
  unsigned char *out,
  const unsigned char *tag, int tag_len
) {
  struct lc_aead_ctx *ctx = NULL;
  int rc;

  if((rc = lc_ak_alloc_taglen(lc_sha3_512, (uint8_t)tag_len, &ctx)) < 0) {
    return rc;
  }
  if((rc = lc_aead_setkey(ctx, key, (size_t)key_len, nonce, (size_t)nonce_len)) < 0) {
    lc_aead_zero_free(ctx);
    return rc;
  }
  rc = lc_aead_decrypt(ctx, in, out, (size_t)data_len, aad, (size_t)aad_len, tag, (size_t)tag_len);
  lc_aead_zero_free(ctx);
  return rc < 0 ? rc : 0;
}

/*
** HKDF-SHA3-512 (RFC 5869 extract-then-expand) in one call, matching
** sqlcipher_leancrypto_hkdf() in src/crypto_leancrypto.c. `out_len` may be
** any length HKDF-Expand supports (up to 255 * the hash's output size).
** Returns 0 on success, a negative leancrypto error code otherwise.
*/
EMSCRIPTEN_KEEPALIVE
int lc_wasm_hkdf_sha3_512(
  const unsigned char *ikm, int ikm_len,
  const unsigned char *salt, int salt_len,
  const unsigned char *info, int info_len,
  unsigned char *out, int out_len
) {
  struct lc_hkdf_ctx *ctx = NULL;
  int rc;

  if((rc = lc_hkdf_alloc(lc_sha3_512, &ctx)) < 0) {
    return rc;
  }
  rc = lc_hkdf_extract(ctx, ikm, (size_t)ikm_len, salt, (size_t)salt_len);
  if(rc == 0) {
    rc = lc_hkdf_expand(ctx, info, (size_t)info_len, out, (size_t)out_len);
  }
  lc_hkdf_zero_free(ctx);
  return rc;
}

/* Fixed sizes this build's Ascon-Keccak-512/HKDF-SHA3-512 configuration
** uses (see doc/crypto.md) -- exposed so JS callers don't have to
** hardcode/duplicate these constants. */
EMSCRIPTEN_KEEPALIVE
int lc_wasm_key_size(void) { return 64; }

EMSCRIPTEN_KEEPALIVE
int lc_wasm_nonce_size(void) { return 64; }

EMSCRIPTEN_KEEPALIVE
int lc_wasm_tag_size(void) { return 64; }
