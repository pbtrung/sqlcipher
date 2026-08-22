/*
** SQLCipher
**
** Value-level encryption (VLE) and encrypted virtual tables.
**
** From-scratch reimplementation of two features publicly documented as
** SQLCipher Commercial/Enterprise-only add-ons:
**
**   https://www.zetetic.net/sqlcipher/value-level-encryption/
**   https://www.zetetic.net/sqlcipher/encrypted-virtual-tables/
**
** Only the public documentation was consulted; no proprietary/commercial
** source was available or used. Function names and the virtual-table SQL
** surface follow the publicly documented shape for familiarity, but the
** cryptographic construction underneath reuses this project's own
** leancrypto-based AEAD codec design (see doc/crypto.md and
** src/crypto_leancrypto.c: Ascon-Keccak-512 AEAD keyed via HKDF-SHA3-512)
** rather than the commercial product's AES-256-CBC + HMAC-SHA512 + PBKDF2
** design. See doc/vle.md for the full design (envelope format, function
** semantics, vtab schema) and doc/vle-plan.md for the build log and any
** recorded deviations from the public API surface.
*/
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#include "sqliteInt.h"
#include "sqlcipher.h"
#include <string.h>
#include <ctype.h>

#define SQLCIPHER_VLE_MIN_KEY_SZ 128
#define SQLCIPHER_VLE_MAX_KEY_SZ 8192
#define SQLCIPHER_VLE_SALT_SZ 64

#define SQLCIPHER_VLE_MAGIC0 0x56 /* 'V' */
#define SQLCIPHER_VLE_MAGIC1 0x4C /* 'L' */
#define SQLCIPHER_VLE_VER0 0x01
#define SQLCIPHER_VLE_VER1 0x00

#define SQLCIPHER_VLE_TYPE_INTEGER 1
#define SQLCIPHER_VLE_TYPE_FLOAT   2
#define SQLCIPHER_VLE_TYPE_TEXT    3
#define SQLCIPHER_VLE_TYPE_BLOB    4
#define SQLCIPHER_VLE_TYPE_NULL    5

/* Per-connection VLE state: the persistent key set by sqlcipher_vle_key(),
** shared as user-data across every sqlcipher_vle_* function and the
** sqlcipher_vle virtual table module registered on one sqlite3* connection.
** Allocated fresh in sqlcipher_vle_init() (an auto-extension callback that
** runs once per new connection) and freed exactly once, via the virtual
** table module's xDestroy callback, in sqlcipher_vle_ctx_destroy(). */
typedef struct sqlcipher_vle_ctx {
  sqlcipher_provider *provider;
  void *provider_ctx;
  unsigned char *key;
  int key_sz;
} sqlcipher_vle_ctx;

typedef struct sqlcipher_vle_vtab {
  sqlite3_vtab base;
  sqlite3 *db;
  sqlcipher_vle_ctx *vctx;
  char *zTabName;
  char *zShadowName;
  int nCol;
  char **azCol;
  unsigned char *abExcluded; /* nCol bytes: 1 = plaintext passthrough, 0 = encrypted */
} sqlcipher_vle_vtab;

typedef struct sqlcipher_vle_cursor {
  sqlite3_vtab_cursor base;
  sqlite3_stmt *pStmt;
  int eof;
} sqlcipher_vle_cursor;

/*
** sqlite3_vmprintf()-based incremental string builder: appends the
** formatted piece to zIn, freeing zIn, and returns the new string (or NULL
** on OOM, after freeing zIn). Used to build comma-separated column lists
** without juggling manual buffer growth.
*/
static char *sqlcipher_vle_append(char *zIn, const char *zFmt, ...){
  va_list ap;
  char *zPiece;
  char *zOut;
  va_start(ap, zFmt);
  zPiece = sqlite3_vmprintf(zFmt, ap);
  va_end(ap);
  if( !zPiece ){
    sqlite3_free(zIn);
    return 0;
  }
  if( !zIn ) return zPiece;
  zOut = sqlite3_mprintf("%s%s", zIn, zPiece);
  sqlite3_free(zIn);
  sqlite3_free(zPiece);
  return zOut;
}

/*
**************************** value envelope core ****************************
** Modeled directly on the per-page format in doc/crypto.md, at value
** granularity instead of page granularity:
**
**   magic (2 bytes)     0x56 0x4C ("VL")
**   version (2 bytes)   0x01 0x00
**   type (1 byte)       1=INTEGER 2=FLOAT 3=TEXT 4=BLOB 5=NULL
**   salt (64 bytes)     random per value, fresh on every encrypt
**   tag (var)           provider's AEAD tag (leancrypto: 64 bytes)
**   ciphertext (var)    AEAD ciphertext of the serialized value
**
** AD = magic(2) || version(2) || type(1) || context(var, caller-supplied)
**
** Per-value key/nonce derivation (identical in structure to doc/crypto.md's
** "Per-page key/nonce derivation", using this feature's own info labels):
**
**   PRK        = HKDF-Extract-SHA3-512(salt, K)
**   value_key   = HKDF-Expand-SHA3-512(PRK, "sqlcipher-vle-key-v1")
**   value_nonce = HKDF-Expand-SHA3-512(PRK, "sqlcipher-vle-nonce-v1")
*/

static void sqlcipher_vle_serialize_value(
  sqlite3_value *pVal,
  int *pType,
  const unsigned char **pPayload,
  int *pPayloadSz,
  unsigned char *scratch8 /* caller-owned 8-byte scratch buffer for INTEGER/FLOAT */
){
  switch( sqlite3_value_type(pVal) ){
    case SQLITE_INTEGER: {
      sqlite3_int64 v = sqlite3_value_int64(pVal);
      int i;
      for(i=0; i<8; i++) scratch8[7-i] = (unsigned char)((v >> (8*i)) & 0xFF);
      *pType = SQLCIPHER_VLE_TYPE_INTEGER; *pPayload = scratch8; *pPayloadSz = 8;
      break;
    }
    case SQLITE_FLOAT: {
      double d = sqlite3_value_double(pVal);
      memcpy(scratch8, &d, 8);
      *pType = SQLCIPHER_VLE_TYPE_FLOAT; *pPayload = scratch8; *pPayloadSz = 8;
      break;
    }
    case SQLITE_TEXT:
      *pType = SQLCIPHER_VLE_TYPE_TEXT;
      *pPayload = sqlite3_value_text(pVal);
      *pPayloadSz = sqlite3_value_bytes(pVal);
      break;
    case SQLITE_BLOB:
      *pType = SQLCIPHER_VLE_TYPE_BLOB;
      *pPayload = sqlite3_value_blob(pVal);
      *pPayloadSz = sqlite3_value_bytes(pVal);
      break;
    default:
      *pType = SQLCIPHER_VLE_TYPE_NULL;
      *pPayload = 0; *pPayloadSz = 0;
      break;
  }
}

static void sqlcipher_vle_set_result(
  sqlite3_context *ctx,
  int type,
  const unsigned char *payload,
  int payload_sz
){
  switch( type ){
    case SQLCIPHER_VLE_TYPE_INTEGER: {
      sqlite3_int64 v = 0; int i;
      if( payload_sz!=8 ){
        sqlite3_result_error(ctx, "sqlcipher_vle: malformed integer payload in envelope", -1);
        return;
      }
      for(i=0;i<8;i++) v = (v<<8) | payload[i];
      sqlite3_result_int64(ctx, v);
      break;
    }
    case SQLCIPHER_VLE_TYPE_FLOAT: {
      double d;
      if( payload_sz!=8 ){
        sqlite3_result_error(ctx, "sqlcipher_vle: malformed float payload in envelope", -1);
        return;
      }
      memcpy(&d, payload, 8);
      sqlite3_result_double(ctx, d);
      break;
    }
    case SQLCIPHER_VLE_TYPE_TEXT:
      sqlite3_result_text(ctx, (const char*)payload, payload_sz, SQLITE_TRANSIENT);
      break;
    case SQLCIPHER_VLE_TYPE_BLOB:
      sqlite3_result_blob(ctx, payload, payload_sz, SQLITE_TRANSIENT);
      break;
    case SQLCIPHER_VLE_TYPE_NULL:
      sqlite3_result_null(ctx);
      break;
    default:
      sqlite3_result_error(ctx, "sqlcipher_vle: unrecognized value type in envelope", -1);
      break;
  }
}

/* Encrypts one serialized value into a freshly sqlite3_malloc'd envelope.
** On success returns SQLITE_OK, sets *out and *out_sz (caller sqlite3_free()s *out).
** On failure returns a non-OK code and sets *errmsg (sqlite3_mprintf'd,
** caller sqlite3_free()s); *out is left unset. */
static int sqlcipher_vle_encrypt_core(
  sqlcipher_vle_ctx *vctx,
  const unsigned char *key, int key_sz,
  const unsigned char *context, int context_sz,
  int type,
  const unsigned char *payload, int payload_sz,
  unsigned char **out, int *out_sz,
  char **errmsg
){
  sqlcipher_provider *p = vctx->provider;
  int nonce_sz = p->get_nonce_sz(vctx->provider_ctx);
  int pkey_sz  = p->get_key_sz(vctx->provider_ctx);
  int tag_sz   = p->get_tag_sz(vctx->provider_ctx);
  int ad_sz = 5 + context_sz;
  int env_sz = 5 + SQLCIPHER_VLE_SALT_SZ + tag_sz + payload_sz;
  unsigned char *ad = 0, *value_key = 0, *value_nonce = 0, *env = 0;
  int rc = SQLITE_OK;

  ad = sqlite3_malloc(ad_sz>0 ? ad_sz : 1);
  value_key = sqlite3_malloc(pkey_sz);
  value_nonce = sqlite3_malloc(nonce_sz);
  env = sqlite3_malloc(env_sz>0 ? env_sz : 1);
  if( !ad || !value_key || !value_nonce || !env ){
    rc = SQLITE_NOMEM;
    goto done;
  }

  env[0] = SQLCIPHER_VLE_MAGIC0; env[1] = SQLCIPHER_VLE_MAGIC1;
  env[2] = SQLCIPHER_VLE_VER0;   env[3] = SQLCIPHER_VLE_VER1;
  env[4] = (unsigned char)type;

  if( p->random(vctx->provider_ctx, env+5, SQLCIPHER_VLE_SALT_SZ)!=SQLITE_OK ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: failed to generate a random salt");
    rc = SQLITE_ERROR; goto done;
  }

  if( p->hkdf(vctx->provider_ctx, key, key_sz, env+5, SQLCIPHER_VLE_SALT_SZ,
        (const unsigned char*)"sqlcipher-vle-key-v1", (int)(sizeof("sqlcipher-vle-key-v1")-1), pkey_sz, value_key,
        (const unsigned char*)"sqlcipher-vle-nonce-v1", (int)(sizeof("sqlcipher-vle-nonce-v1")-1), nonce_sz, value_nonce)!=SQLITE_OK ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: key/nonce derivation failed");
    rc = SQLITE_ERROR; goto done;
  }

  memcpy(ad, env, 5);
  if( context_sz>0 ) memcpy(ad+5, context, context_sz);

  {
    unsigned char *tag = env + 5 + SQLCIPHER_VLE_SALT_SZ;
    unsigned char *ciphertext = tag + tag_sz;
    if( p->aead_encrypt(vctx->provider_ctx, value_key, pkey_sz, value_nonce, nonce_sz,
          ad, ad_sz, payload, payload_sz, ciphertext, tag, tag_sz)!=SQLITE_OK ){
      *errmsg = sqlite3_mprintf("sqlcipher_vle: encryption failed");
      rc = SQLITE_ERROR; goto done;
    }
  }

  *out = env; *out_sz = env_sz;
  env = 0;

done:
  if( value_key ){ sqlcipher_memset(value_key, 0, pkey_sz); sqlite3_free(value_key); }
  if( value_nonce ){ sqlcipher_memset(value_nonce, 0, nonce_sz); sqlite3_free(value_nonce); }
  sqlite3_free(ad);
  sqlite3_free(env);
  return rc;
}

/* Inverse of sqlcipher_vle_encrypt_core(). On success returns SQLITE_OK and
** sets *type_out plus a freshly sqlite3_malloc'd *out and *out_sz payload
** (caller frees). On failure returns a non-OK code and sets *errmsg. */
static int sqlcipher_vle_decrypt_core(
  sqlcipher_vle_ctx *vctx,
  const unsigned char *key, int key_sz,
  const unsigned char *context, int context_sz,
  const unsigned char *envelope, int envelope_sz,
  int *type_out,
  unsigned char **out, int *out_sz,
  char **errmsg
){
  sqlcipher_provider *p = vctx->provider;
  int nonce_sz = p->get_nonce_sz(vctx->provider_ctx);
  int pkey_sz  = p->get_key_sz(vctx->provider_ctx);
  int tag_sz   = p->get_tag_sz(vctx->provider_ctx);
  int fixed_hdr = 5 + SQLCIPHER_VLE_SALT_SZ + tag_sz;
  int ciphertext_sz;
  const unsigned char *salt, *tag, *ciphertext;
  unsigned char *ad = 0, *value_key = 0, *value_nonce = 0, *plaintext = 0;
  int ad_sz = 5 + context_sz;
  int rc = SQLITE_OK;
  int type;

  if( envelope_sz < fixed_hdr ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: envelope too short to be valid");
    return SQLITE_ERROR;
  }
  if( envelope[0]!=SQLCIPHER_VLE_MAGIC0 || envelope[1]!=SQLCIPHER_VLE_MAGIC1 ||
      envelope[2]!=SQLCIPHER_VLE_VER0   || envelope[3]!=SQLCIPHER_VLE_VER1 ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: unrecognized envelope magic/version");
    return SQLITE_ERROR;
  }
  type = envelope[4];
  if( type<SQLCIPHER_VLE_TYPE_INTEGER || type>SQLCIPHER_VLE_TYPE_NULL ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: unrecognized value type in envelope");
    return SQLITE_ERROR;
  }
  salt = envelope + 5;
  tag = salt + SQLCIPHER_VLE_SALT_SZ;
  ciphertext = tag + tag_sz;
  ciphertext_sz = envelope_sz - fixed_hdr;

  ad = sqlite3_malloc(ad_sz>0 ? ad_sz : 1);
  value_key = sqlite3_malloc(pkey_sz);
  value_nonce = sqlite3_malloc(nonce_sz);
  plaintext = sqlite3_malloc(ciphertext_sz>0 ? ciphertext_sz : 1);
  if( !ad || !value_key || !value_nonce || !plaintext ){ rc = SQLITE_NOMEM; goto done; }

  memcpy(ad, envelope, 5);
  if( context_sz>0 ) memcpy(ad+5, context, context_sz);

  if( p->hkdf(vctx->provider_ctx, key, key_sz, salt, SQLCIPHER_VLE_SALT_SZ,
        (const unsigned char*)"sqlcipher-vle-key-v1", (int)(sizeof("sqlcipher-vle-key-v1")-1), pkey_sz, value_key,
        (const unsigned char*)"sqlcipher-vle-nonce-v1", (int)(sizeof("sqlcipher-vle-nonce-v1")-1), nonce_sz, value_nonce)!=SQLITE_OK ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: key/nonce derivation failed");
    rc = SQLITE_ERROR; goto done;
  }

  if( p->aead_decrypt(vctx->provider_ctx, value_key, pkey_sz, value_nonce, nonce_sz,
        ad, ad_sz, ciphertext, ciphertext_sz, plaintext, tag, tag_sz)!=SQLITE_OK ){
    *errmsg = sqlite3_mprintf("sqlcipher_vle: authentication failed (wrong key, wrong context, or corrupted data)");
    rc = SQLITE_ERROR; goto done;
  }

  *type_out = type;
  *out = plaintext; *out_sz = ciphertext_sz;
  plaintext = 0;

done:
  if( value_key ){ sqlcipher_memset(value_key, 0, pkey_sz); sqlite3_free(value_key); }
  if( value_nonce ){ sqlcipher_memset(value_nonce, 0, nonce_sz); sqlite3_free(value_nonce); }
  sqlite3_free(ad);
  sqlite3_free(plaintext);
  return rc;
}

/**************************** small parsing helpers ****************************/

static int sqlcipher_vle_hex2int(char c){
  return (c>='0'&&c<='9') ? c-'0' : (c>='a'&&c<='f') ? c-'a'+10 : (c>='A'&&c<='F') ? c-'A'+10 : -1;
}

/* Decodes a key argument: a BLOB is copied as-is; a TEXT value must be
** hex-blob format x'...' (same convention as PRAGMA key, but implemented
** independently here rather than depending on sqlcipher.c's static helpers,
** since this file must also build as its own translation unit in a
** non-amalgamation build). On success returns SQLITE_OK and a freshly
** sqlite3_malloc'd *out and *out_sz (caller frees). On failure returns a
** non-OK code and sets *errmsg. */
static int sqlcipher_vle_decode_key_arg(
  sqlite3_value *pVal,
  unsigned char **out, int *out_sz,
  char **errmsg
){
  if( sqlite3_value_type(pVal)==SQLITE_BLOB ){
    int sz = sqlite3_value_bytes(pVal);
    unsigned char *buf = sqlite3_malloc(sz>0 ? sz : 1);
    if( !buf ) return SQLITE_NOMEM;
    if( sz>0 ) memcpy(buf, sqlite3_value_blob(pVal), sz);
    *out = buf; *out_sz = sz;
    return SQLITE_OK;
  }
  if( sqlite3_value_type(pVal)==SQLITE_TEXT ){
    const unsigned char *z = sqlite3_value_text(pVal);
    int n = sqlite3_value_bytes(pVal);
    int i;
    if( n>=3 && (z[0]=='x'||z[0]=='X') && z[1]=='\'' && z[n-1]=='\'' && ((n-3)%2)==0 ){
      int hexok = 1;
      for(i=2; i<n-1; i++){
        if( sqlcipher_vle_hex2int((char)z[i])<0 ){ hexok = 0; break; }
      }
      if( hexok ){
        int raw_sz = (n-3)/2;
        unsigned char *buf = sqlite3_malloc(raw_sz>0 ? raw_sz : 1);
        if( !buf ) return SQLITE_NOMEM;
        for(i=0; i<raw_sz; i++){
          buf[i] = (unsigned char)((sqlcipher_vle_hex2int((char)z[2+2*i])<<4) | sqlcipher_vle_hex2int((char)z[3+2*i]));
        }
        *out = buf; *out_sz = raw_sz;
        return SQLITE_OK;
      }
    }
    *errmsg = sqlite3_mprintf("sqlcipher_vle_key: TEXT key must be hex-blob format x'...'");
    return SQLITE_ERROR;
  }
  *errmsg = sqlite3_mprintf("sqlcipher_vle_key: key must be a BLOB or hex TEXT (x'...')");
  return SQLITE_ERROR;
}

/**************************** SQL scalar functions ****************************/

static void sqlcipher_vle_random_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  sqlite3_int64 n = sqlite3_value_int64(argv[0]);
  unsigned char *buf;
  if( n<1 || n>65536 ){
    sqlite3_result_error(ctx, "sqlcipher_vle_random: n must be between 1 and 65536", -1);
    return;
  }
  buf = sqlite3_malloc((int)n);
  if( !buf ){ sqlite3_result_error_nomem(ctx); return; }
  if( vctx->provider->random(vctx->provider_ctx, buf, (int)n)!=SQLITE_OK ){
    sqlite3_free(buf);
    sqlite3_result_error(ctx, "sqlcipher_vle_random: random generation failed", -1);
    return;
  }
  sqlite3_result_blob(ctx, buf, (int)n, sqlite3_free);
}

/* sqlcipher_vle_kdf(ikm, salt[, out_sz[, info]]) -> BLOB
** HKDF-Extract-SHA3-512(salt, ikm) followed by HKDF-Expand-SHA3-512(PRK, info, out_sz).
** The provider's hkdf() always produces two outputs sharing one PRK; the
** second output here is a discarded scratch value with a fixed, unexposed
** info label -- see doc/vle.md. */
static void sqlcipher_vle_kdf_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  const unsigned char *ikm = sqlite3_value_blob(argv[0]);
  int ikm_sz = sqlite3_value_bytes(argv[0]);
  const unsigned char *salt = sqlite3_value_blob(argv[1]);
  int salt_sz = sqlite3_value_bytes(argv[1]);
  sqlite3_int64 out_sz = argc>2 && sqlite3_value_type(argv[2])!=SQLITE_NULL ? sqlite3_value_int64(argv[2]) : 32;
  const unsigned char *info = argc>3 && sqlite3_value_type(argv[3])!=SQLITE_NULL ? sqlite3_value_blob(argv[3]) : 0;
  int info_sz = argc>3 && sqlite3_value_type(argv[3])!=SQLITE_NULL ? sqlite3_value_bytes(argv[3]) : 0;
  int scratch_sz = vctx->provider->get_key_sz(vctx->provider_ctx);
  unsigned char *out, *scratch;

  if( out_sz<1 || out_sz>4096 ){
    sqlite3_result_error(ctx, "sqlcipher_vle_kdf: out_sz must be between 1 and 4096", -1);
    return;
  }
  out = sqlite3_malloc((int)out_sz);
  scratch = sqlite3_malloc(scratch_sz);
  if( !out || !scratch ){ sqlite3_free(out); sqlite3_free(scratch); sqlite3_result_error_nomem(ctx); return; }

  if( vctx->provider->hkdf(vctx->provider_ctx, ikm, ikm_sz, salt, salt_sz,
        info, info_sz, (int)out_sz, out,
        (const unsigned char*)"sqlcipher-vle-kdf-scratch-v1", (int)(sizeof("sqlcipher-vle-kdf-scratch-v1")-1), scratch_sz, scratch)!=SQLITE_OK ){
    sqlite3_free(out); sqlite3_free(scratch);
    sqlite3_result_error(ctx, "sqlcipher_vle_kdf: derivation failed", -1);
    return;
  }
  sqlcipher_memset(scratch, 0, scratch_sz);
  sqlite3_free(scratch);
  sqlite3_result_blob(ctx, out, (int)out_sz, sqlite3_free);
}

static void sqlcipher_vle_key_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  unsigned char *key = 0; int key_sz = 0; char *errmsg = 0;
  int rc = sqlcipher_vle_decode_key_arg(argv[0], &key, &key_sz, &errmsg);
  if( rc!=SQLITE_OK ){
    sqlite3_result_error(ctx, errmsg ? errmsg : "sqlcipher_vle_key: invalid key", -1);
    sqlite3_free(errmsg);
    return;
  }
  if( key_sz<SQLCIPHER_VLE_MIN_KEY_SZ || key_sz>SQLCIPHER_VLE_MAX_KEY_SZ ){
    sqlite3_free(key);
    sqlite3_result_error(ctx, "sqlcipher_vle_key: key length out of range (128-8192 bytes)", -1);
    return;
  }
  if( vctx->key ){
    sqlcipher_memset(vctx->key, 0, vctx->key_sz);
    sqlite3_free(vctx->key);
  }
  vctx->key = key; vctx->key_sz = key_sz;
  sqlite3_result_int(ctx, 1);
}

static void sqlcipher_vle_encrypt_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  const unsigned char *key = 0; int key_sz = 0;
  const unsigned char *context = 0; int context_sz = 0;
  unsigned char scratch8[8];
  int type; const unsigned char *payload; int payload_sz;
  unsigned char *out = 0; int out_sz = 0; char *errmsg = 0;
  int rc;

  if( argc>=2 && sqlite3_value_type(argv[1])!=SQLITE_NULL ){
    key = sqlite3_value_blob(argv[1]); key_sz = sqlite3_value_bytes(argv[1]);
  }else{
    key = vctx->key; key_sz = vctx->key_sz;
  }
  if( !key || key_sz<SQLCIPHER_VLE_MIN_KEY_SZ || key_sz>SQLCIPHER_VLE_MAX_KEY_SZ ){
    sqlite3_result_error(ctx, "sqlcipher_vle_encrypt: no valid key (call sqlcipher_vle_key() first, or pass one explicitly)", -1);
    return;
  }
  if( argc>=3 && sqlite3_value_type(argv[2])!=SQLITE_NULL ){
    context = sqlite3_value_blob(argv[2]); context_sz = sqlite3_value_bytes(argv[2]);
  }

  sqlcipher_vle_serialize_value(argv[0], &type, &payload, &payload_sz, scratch8);

  rc = sqlcipher_vle_encrypt_core(vctx, key, key_sz, context, context_sz, type, payload, payload_sz, &out, &out_sz, &errmsg);
  if( rc!=SQLITE_OK ){
    sqlite3_result_error(ctx, errmsg ? errmsg : "sqlcipher_vle_encrypt: encryption failed", -1);
    sqlite3_free(errmsg);
    return;
  }
  sqlite3_result_blob(ctx, out, out_sz, sqlite3_free);
}

static void sqlcipher_vle_decrypt_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  const unsigned char *key = 0; int key_sz = 0;
  const unsigned char *context = 0; int context_sz = 0;
  const unsigned char *envelope; int envelope_sz;
  unsigned char *payload = 0; int payload_sz = 0; int type = 0;
  char *errmsg = 0; int rc;

  if( sqlite3_value_type(argv[0])==SQLITE_NULL ){ sqlite3_result_null(ctx); return; }
  envelope = sqlite3_value_blob(argv[0]);
  envelope_sz = sqlite3_value_bytes(argv[0]);

  if( argc>=2 && sqlite3_value_type(argv[1])!=SQLITE_NULL ){
    key = sqlite3_value_blob(argv[1]); key_sz = sqlite3_value_bytes(argv[1]);
  }else{
    key = vctx->key; key_sz = vctx->key_sz;
  }
  if( !key || key_sz<SQLCIPHER_VLE_MIN_KEY_SZ || key_sz>SQLCIPHER_VLE_MAX_KEY_SZ ){
    sqlite3_result_error(ctx, "sqlcipher_vle_decrypt: no valid key (call sqlcipher_vle_key() first, or pass one explicitly)", -1);
    return;
  }
  if( argc>=3 && sqlite3_value_type(argv[2])!=SQLITE_NULL ){
    context = sqlite3_value_blob(argv[2]); context_sz = sqlite3_value_bytes(argv[2]);
  }

  rc = sqlcipher_vle_decrypt_core(vctx, key, key_sz, context, context_sz, envelope, envelope_sz, &type, &payload, &payload_sz, &errmsg);
  if( rc!=SQLITE_OK ){
    sqlite3_result_error(ctx, errmsg ? errmsg : "sqlcipher_vle_decrypt: decryption failed", -1);
    sqlite3_free(errmsg);
    return;
  }
  sqlcipher_vle_set_result(ctx, type, payload, payload_sz);
  sqlite3_free(payload);
}

/* sqlcipher_vle_cipher(mode, key, nonce, aad, input) -> BLOB
** Low-level, single AEAD call with no envelope/type-preservation. mode=1
** encrypts (input is plaintext; returns ciphertext||tag); mode=0 decrypts
** (input must be ciphertext||tag; returns plaintext, or errors on
** authentication failure). key/nonce must be exactly the provider's
** key/nonce sizes. */
static void sqlcipher_vle_cipher_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  sqlcipher_provider *p = vctx->provider;
  int mode = sqlite3_value_int(argv[0]);
  const unsigned char *key = sqlite3_value_blob(argv[1]); int key_sz = sqlite3_value_bytes(argv[1]);
  const unsigned char *nonce = sqlite3_value_blob(argv[2]); int nonce_sz = sqlite3_value_bytes(argv[2]);
  const unsigned char *aad = sqlite3_value_type(argv[3])==SQLITE_NULL ? 0 : sqlite3_value_blob(argv[3]);
  int aad_sz = sqlite3_value_type(argv[3])==SQLITE_NULL ? 0 : sqlite3_value_bytes(argv[3]);
  const unsigned char *input = sqlite3_value_blob(argv[4]); int input_sz = sqlite3_value_bytes(argv[4]);
  int want_key_sz = p->get_key_sz(vctx->provider_ctx);
  int want_nonce_sz = p->get_nonce_sz(vctx->provider_ctx);
  int tag_sz = p->get_tag_sz(vctx->provider_ctx);

  if( key_sz!=want_key_sz ){
    sqlite3_result_error(ctx, "sqlcipher_vle_cipher: key must be exactly the provider's key size", -1);
    return;
  }
  if( nonce_sz!=want_nonce_sz ){
    sqlite3_result_error(ctx, "sqlcipher_vle_cipher: nonce must be exactly the provider's nonce size", -1);
    return;
  }

  if( mode==1 ){
    int out_sz = input_sz + tag_sz;
    unsigned char *out = sqlite3_malloc(out_sz>0 ? out_sz : 1);
    if( !out ){ sqlite3_result_error_nomem(ctx); return; }
    if( p->aead_encrypt(vctx->provider_ctx, key, key_sz, nonce, nonce_sz, aad, aad_sz, input, input_sz, out, out+input_sz, tag_sz)!=SQLITE_OK ){
      sqlite3_free(out);
      sqlite3_result_error(ctx, "sqlcipher_vle_cipher: encryption failed", -1);
      return;
    }
    sqlite3_result_blob(ctx, out, out_sz, sqlite3_free);
  }else if( mode==0 ){
    int ct_sz = input_sz - tag_sz;
    unsigned char *out;
    if( ct_sz<0 ){
      sqlite3_result_error(ctx, "sqlcipher_vle_cipher: input shorter than the provider's tag size", -1);
      return;
    }
    out = sqlite3_malloc(ct_sz>0 ? ct_sz : 1);
    if( !out ){ sqlite3_result_error_nomem(ctx); return; }
    if( p->aead_decrypt(vctx->provider_ctx, key, key_sz, nonce, nonce_sz, aad, aad_sz, input, ct_sz, out, input+ct_sz, tag_sz)!=SQLITE_OK ){
      sqlite3_free(out);
      sqlite3_result_error(ctx, "sqlcipher_vle_cipher: authentication failed", -1);
      return;
    }
    sqlite3_result_blob(ctx, out, ct_sz, sqlite3_free);
  }else{
    sqlite3_result_error(ctx, "sqlcipher_vle_cipher: mode must be 0 (decrypt) or 1 (encrypt)", -1);
  }
}

/* sqlcipher_vle_hmac(input, key) -> BLOB (provider key size, 64 bytes for leancrypto)
** A deterministic, keyed integrity tag: HKDF-Expand-SHA3-512(HKDF-Extract-SHA3-512(
** salt="sqlcipher-vle-hmac-v1", ikm=key), info=input). Not a literal HMAC-SHA512
** computation -- see doc/vle.md's "Deviations". */
static void sqlcipher_vle_hmac_func(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)sqlite3_user_data(ctx);
  sqlcipher_provider *p = vctx->provider;
  const unsigned char *input = sqlite3_value_blob(argv[0]); int input_sz = sqlite3_value_bytes(argv[0]);
  const unsigned char *key = sqlite3_value_blob(argv[1]); int key_sz = sqlite3_value_bytes(argv[1]);
  int pkey_sz = p->get_key_sz(vctx->provider_ctx);
  static const unsigned char salt[] = "sqlcipher-vle-hmac-v1";
  unsigned char *out, *scratch;

  if( key_sz<1 ){
    sqlite3_result_error(ctx, "sqlcipher_vle_hmac: key must not be empty", -1);
    return;
  }
  out = sqlite3_malloc(pkey_sz);
  scratch = sqlite3_malloc(pkey_sz);
  if( !out || !scratch ){ sqlite3_free(out); sqlite3_free(scratch); sqlite3_result_error_nomem(ctx); return; }

  if( p->hkdf(vctx->provider_ctx, key, key_sz, salt, (int)(sizeof(salt)-1),
        input, input_sz, pkey_sz, out,
        (const unsigned char*)"sqlcipher-vle-hmac-scratch-v1", (int)(sizeof("sqlcipher-vle-hmac-scratch-v1")-1), pkey_sz, scratch)!=SQLITE_OK ){
    sqlite3_free(out); sqlite3_free(scratch);
    sqlite3_result_error(ctx, "sqlcipher_vle_hmac: derivation failed", -1);
    return;
  }
  sqlcipher_memset(scratch, 0, pkey_sz);
  sqlite3_free(scratch);
  sqlite3_result_blob(ctx, out, pkey_sz, sqlite3_free);
}

/**************************** encrypted virtual table ****************************/

static void sqlcipher_vle_free_cols(char **azCol, int nCol){
  int i;
  if( !azCol ) return;
  for(i=0; i<nCol; i++) sqlite3_free(azCol[i]);
  sqlite3_free(azCol);
}

static void sqlcipher_vle_vtab_free(sqlcipher_vle_vtab *p){
  if( !p ) return;
  sqlcipher_vle_free_cols(p->azCol, p->nCol);
  sqlite3_free(p->abExcluded);
  sqlite3_free(p->zTabName);
  sqlite3_free(p->zShadowName);
  sqlite3_free(p);
}

static int sqlcipher_vle_is_ident_char(char c){
  return (c=='_') || (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9');
}

/* Extracts column names from a `CREATE TABLE ...(col1 [type...], col2, ...)`
** argument: finds the first '(' and the last ')' in zArg, splits the
** substring between them on top-level commas (tracking paren depth so a
** nested column constraint like CHECK(...) doesn't split), and takes each
** piece's leading identifier as the column name (ignoring any trailing
** type/constraint text). This is an intentionally minimal parser -- quoted
** identifiers are not supported; see doc/vle.md's "Known limitations". */
static int sqlcipher_vle_parse_columns(const char *zArg, char ***pazCol, int *pnCol, char **pzErr){
  int n = (int)strlen(zArg);
  int lp = -1, rp = -1;
  int i, depth;
  char **azCol = 0;
  int nCol = 0;
  int start;

  for(i=0; i<n; i++){ if( zArg[i]=='(' ){ lp = i; break; } }
  for(i=n-1; i>=0; i--){ if( zArg[i]==')' ){ rp = i; break; } }
  if( lp<0 || rp<0 || rp<=lp ){
    *pzErr = sqlite3_mprintf("sqlcipher_vle: expected a column list in parentheses, e.g. CREATE TABLE t(col1, col2)");
    return SQLITE_ERROR;
  }

  start = lp + 1;
  depth = 0;
  for(i=start; i<=rp; i++){
    char c = (i<rp) ? zArg[i] : ',';
    if( c=='(' ){ depth++; }
    else if( c==')' ){ depth--; }
    else if( c==',' && depth==0 ){
      int s = start, e = i;
      char *zName;
      int ident_start, ident_end;
      while( s<e && isspace((unsigned char)zArg[s]) ) s++;
      ident_start = s;
      while( s<e && sqlcipher_vle_is_ident_char(zArg[s]) ) s++;
      ident_end = s;
      if( ident_end<=ident_start ){
        sqlcipher_vle_free_cols(azCol, nCol);
        *pzErr = sqlite3_mprintf("sqlcipher_vle: could not parse a column name near position %d", ident_start);
        return SQLITE_ERROR;
      }
      zName = sqlite3_malloc(ident_end - ident_start + 1);
      if( !zName ){ sqlcipher_vle_free_cols(azCol, nCol); return SQLITE_NOMEM; }
      memcpy(zName, zArg+ident_start, ident_end-ident_start);
      zName[ident_end-ident_start] = 0;
      {
        char **azNew = sqlite3_realloc(azCol, sizeof(char*) * (nCol+1));
        if( !azNew ){ sqlite3_free(zName); sqlcipher_vle_free_cols(azCol, nCol); return SQLITE_NOMEM; }
        azCol = azNew;
        azCol[nCol++] = zName;
      }
      start = i + 1;
    }
  }
  if( nCol==0 ){
    *pzErr = sqlite3_mprintf("sqlcipher_vle: no columns found in column list");
    return SQLITE_ERROR;
  }
  *pazCol = azCol; *pnCol = nCol;
  return SQLITE_OK;
}

static char *sqlcipher_vle_dequote(const char *z){
  int n = (int)strlen(z);
  char q;
  char *zOut;
  int i, j;
  if( n>=2 && ((z[0]=='\'' && z[n-1]=='\'') || (z[0]=='"' && z[n-1]=='"')) ){
    q = z[0];
    zOut = sqlite3_malloc(n);
    if( !zOut ) return 0;
    j = 0;
    for(i=1; i<n-1; i++){
      if( z[i]==q && i+1<n-1 && z[i+1]==q ){ zOut[j++] = q; i++; }
      else zOut[j++] = z[i];
    }
    zOut[j] = 0;
    return zOut;
  }
  return sqlite3_mprintf("%s", z);
}

/* Parses a comma-separated list of 1-based column ordinals (optionally
** quoted, e.g. '1,3') and marks the corresponding entries of abExcluded
** (nCol bytes, pre-zeroed by the caller). */
static int sqlcipher_vle_parse_excluded(const char *zArg, int nCol, unsigned char *abExcluded, char **pzErr){
  char *zDeq = sqlcipher_vle_dequote(zArg);
  const char *p;
  int rc = SQLITE_OK;
  if( !zDeq ) return SQLITE_NOMEM;
  p = zDeq;
  while( *p ){
    while( *p==' ' || *p==',' ) p++;
    if( !*p ) break;
    if( !(*p>='0' && *p<='9') ){
      *pzErr = sqlite3_mprintf("sqlcipher_vle: excluded-column list must be comma-separated 1-based column numbers");
      rc = SQLITE_ERROR; break;
    }
    {
      long v = 0;
      while( *p>='0' && *p<='9' ){ v = v*10 + (*p - '0'); p++; }
      if( v<1 || v>nCol ){
        *pzErr = sqlite3_mprintf("sqlcipher_vle: excluded column ordinal %ld out of range (1-%d)", v, nCol);
        rc = SQLITE_ERROR; break;
      }
      abExcluded[v-1] = 1;
    }
  }
  sqlite3_free(zDeq);
  return rc;
}

/* Cell AAD context = table name || 0x00 || 4-byte big-endian column ordinal
** || 8-byte big-endian rowid, binding each ciphertext to its exact
** location: a cell copied into a different row or column fails to
** decrypt -- see doc/vle.md's "Encrypted virtual tables". */
static int sqlcipher_vle_build_cell_context(const char *zTab, int iCol, sqlite3_int64 rowid, unsigned char **out, int *out_sz){
  int nTab = (int)strlen(zTab);
  int sz = nTab + 1 + 4 + 8;
  unsigned char *buf = sqlite3_malloc(sz);
  int i;
  if( !buf ) return SQLITE_NOMEM;
  memcpy(buf, zTab, nTab);
  buf[nTab] = 0;
  for(i=0;i<4;i++) buf[nTab+1+i] = (unsigned char)((iCol >> (8*(3-i))) & 0xFF);
  for(i=0;i<8;i++) buf[nTab+5+i] = (unsigned char)((rowid >> (8*(7-i))) & 0xFF);
  *out = buf; *out_sz = sz;
  return SQLITE_OK;
}

static int sqlcipher_vle_connect_create(
  sqlite3 *db, void *pAux, int argc, const char *const *argv,
  sqlite3_vtab **ppVtab, char **pzErr, int isCreate
){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)pAux;
  sqlcipher_vle_vtab *pNew;
  char **azCol = 0; int nCol = 0;
  unsigned char *abExcluded = 0;
  char *zDeclare;
  int rc;
  int i;

  if( argc<4 ){
    *pzErr = sqlite3_mprintf("sqlcipher_vle: expected a CREATE TABLE(...) column definition argument");
    return SQLITE_ERROR;
  }

  rc = sqlcipher_vle_parse_columns(argv[3], &azCol, &nCol, pzErr);
  if( rc!=SQLITE_OK ) return rc;

  abExcluded = sqlite3_malloc(nCol>0 ? nCol : 1);
  if( !abExcluded ){ sqlcipher_vle_free_cols(azCol, nCol); return SQLITE_NOMEM; }
  memset(abExcluded, 0, nCol);
  if( argc>=5 ){
    rc = sqlcipher_vle_parse_excluded(argv[4], nCol, abExcluded, pzErr);
    if( rc!=SQLITE_OK ){ sqlcipher_vle_free_cols(azCol, nCol); sqlite3_free(abExcluded); return rc; }
  }

  pNew = sqlite3_malloc(sizeof(*pNew));
  if( !pNew ){ sqlcipher_vle_free_cols(azCol, nCol); sqlite3_free(abExcluded); return SQLITE_NOMEM; }
  memset(pNew, 0, sizeof(*pNew));
  pNew->db = db;
  pNew->vctx = vctx;
  pNew->nCol = nCol;
  pNew->azCol = azCol;
  pNew->abExcluded = abExcluded;
  pNew->zTabName = sqlite3_mprintf("%s", argv[2]);
  pNew->zShadowName = sqlite3_mprintf("%s_shadow", argv[2]);
  if( !pNew->zTabName || !pNew->zShadowName ){
    sqlcipher_vle_vtab_free(pNew);
    return SQLITE_NOMEM;
  }

  zDeclare = sqlite3_mprintf("%s", argv[3]);
  if( !zDeclare ){ sqlcipher_vle_vtab_free(pNew); return SQLITE_NOMEM; }
  rc = sqlite3_declare_vtab(db, zDeclare);
  sqlite3_free(zDeclare);
  if( rc!=SQLITE_OK ){
    *pzErr = sqlite3_mprintf("sqlcipher_vle: failed to declare virtual table schema: %s", sqlite3_errmsg(db));
    sqlcipher_vle_vtab_free(pNew);
    return rc;
  }

  if( isCreate ){
    char *zCols = 0;
    char *zShadowSql;
    for(i=0; i<nCol; i++){
      zCols = sqlcipher_vle_append(zCols, "%s\"%w\"%s", i>0 ? ", " : "", azCol[i], abExcluded[i] ? "" : " BLOB");
      if( !zCols ){ sqlcipher_vle_vtab_free(pNew); return SQLITE_NOMEM; }
    }
    zShadowSql = sqlite3_mprintf("CREATE TABLE IF NOT EXISTS \"%w\"(%s)", pNew->zShadowName, zCols);
    sqlite3_free(zCols);
    if( !zShadowSql ){ sqlcipher_vle_vtab_free(pNew); return SQLITE_NOMEM; }
    rc = sqlite3_exec(db, zShadowSql, 0, 0, pzErr);
    sqlite3_free(zShadowSql);
    if( rc!=SQLITE_OK ){ sqlcipher_vle_vtab_free(pNew); return rc; }
  }

  *ppVtab = &pNew->base;
  return SQLITE_OK;
}

static int sqlcipher_vle_x_create(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab, char **pzErr){
  return sqlcipher_vle_connect_create(db, pAux, argc, argv, ppVtab, pzErr, 1);
}
static int sqlcipher_vle_x_connect(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab, char **pzErr){
  return sqlcipher_vle_connect_create(db, pAux, argc, argv, ppVtab, pzErr, 0);
}

static int sqlcipher_vle_x_disconnect(sqlite3_vtab *pVtab){
  sqlcipher_vle_vtab_free((sqlcipher_vle_vtab*)pVtab);
  return SQLITE_OK;
}

static int sqlcipher_vle_x_destroy(sqlite3_vtab *pVtab){
  sqlcipher_vle_vtab *p = (sqlcipher_vle_vtab*)pVtab;
  char *zSql = sqlite3_mprintf("DROP TABLE IF EXISTS \"%w\"", p->zShadowName);
  int rc = SQLITE_OK;
  if( zSql ){
    rc = sqlite3_exec(p->db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }
  sqlcipher_vle_vtab_free(p);
  return rc;
}

/* Pushes down only rowid equality (idxNum=1); every other constraint is left
** unusable so SQLite falls back to a full scan and re-checks it itself --
** correct, though not as fully optimized as the public commercial feature's
** documented excluded-column pushdown; see doc/vle.md's "Known limitations". */
static int sqlcipher_vle_x_best_index(sqlite3_vtab *pVtab, sqlite3_index_info *pIdx){
  int i;
  int rowidTerm = -1;
  for(i=0; i<pIdx->nConstraint; i++){
    const struct sqlite3_index_constraint *pCons = &pIdx->aConstraint[i];
    if( !pCons->usable ) continue;
    if( pCons->iColumn==-1 && pCons->op==SQLITE_INDEX_CONSTRAINT_EQ ){
      rowidTerm = i;
      break;
    }
  }
  if( rowidTerm>=0 ){
    pIdx->aConstraintUsage[rowidTerm].argvIndex = 1;
    pIdx->aConstraintUsage[rowidTerm].omit = 1;
    pIdx->idxNum = 1;
    pIdx->estimatedCost = 1.0;
    pIdx->estimatedRows = 1;
  }else{
    pIdx->idxNum = 0;
    pIdx->estimatedCost = 1000000.0;
    pIdx->estimatedRows = 1000000;
  }
  return SQLITE_OK;
}

static int sqlcipher_vle_x_open(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor){
  sqlcipher_vle_cursor *pCur = sqlite3_malloc(sizeof(*pCur));
  if( !pCur ) return SQLITE_NOMEM;
  memset(pCur, 0, sizeof(*pCur));
  pCur->base.pVtab = pVtab;
  *ppCursor = &pCur->base;
  return SQLITE_OK;
}

static int sqlcipher_vle_x_close(sqlite3_vtab_cursor *cur){
  sqlcipher_vle_cursor *pCur = (sqlcipher_vle_cursor*)cur;
  if( pCur->pStmt ) sqlite3_finalize(pCur->pStmt);
  sqlite3_free(pCur);
  return SQLITE_OK;
}

static int sqlcipher_vle_x_filter(sqlite3_vtab_cursor *cur, int idxNum, const char *idxStr, int argc, sqlite3_value **argv){
  sqlcipher_vle_cursor *pCur = (sqlcipher_vle_cursor*)cur;
  sqlcipher_vle_vtab *pTab = (sqlcipher_vle_vtab*)cur->pVtab;
  char *zCols = 0, *zSql;
  int i, rc;

  if( pCur->pStmt ){ sqlite3_finalize(pCur->pStmt); pCur->pStmt = 0; }
  for(i=0; i<pTab->nCol; i++){
    zCols = sqlcipher_vle_append(zCols, "%s\"%w\"", i>0 ? ", " : "", pTab->azCol[i]);
    if( !zCols ) return SQLITE_NOMEM;
  }

  if( idxNum==1 && argc>=1 ){
    zSql = sqlite3_mprintf("SELECT rowid, %s FROM \"%w\" WHERE rowid = ?1", zCols, pTab->zShadowName);
  }else{
    zSql = sqlite3_mprintf("SELECT rowid, %s FROM \"%w\"", zCols, pTab->zShadowName);
  }
  sqlite3_free(zCols);
  if( !zSql ) return SQLITE_NOMEM;

  rc = sqlite3_prepare_v2(pTab->db, zSql, -1, &pCur->pStmt, 0);
  sqlite3_free(zSql);
  if( rc!=SQLITE_OK ){
    pTab->base.zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
    return rc;
  }
  if( idxNum==1 && argc>=1 ){
    sqlite3_bind_value(pCur->pStmt, 1, argv[0]);
  }
  rc = sqlite3_step(pCur->pStmt);
  if( rc==SQLITE_ROW ){ pCur->eof = 0; }
  else if( rc==SQLITE_DONE ){ pCur->eof = 1; }
  else{
    pTab->base.zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
    return rc;
  }
  return SQLITE_OK;
}

static int sqlcipher_vle_x_next(sqlite3_vtab_cursor *cur){
  sqlcipher_vle_cursor *pCur = (sqlcipher_vle_cursor*)cur;
  int rc = sqlite3_step(pCur->pStmt);
  if( rc==SQLITE_ROW ){ pCur->eof = 0; }
  else if( rc==SQLITE_DONE ){ pCur->eof = 1; }
  else{
    cur->pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(((sqlcipher_vle_vtab*)cur->pVtab)->db));
    return rc;
  }
  return SQLITE_OK;
}

static int sqlcipher_vle_x_eof(sqlite3_vtab_cursor *cur){
  return ((sqlcipher_vle_cursor*)cur)->eof;
}

static int sqlcipher_vle_x_rowid(sqlite3_vtab_cursor *cur, sqlite3_int64 *pRowid){
  sqlcipher_vle_cursor *pCur = (sqlcipher_vle_cursor*)cur;
  *pRowid = sqlite3_column_int64(pCur->pStmt, 0);
  return SQLITE_OK;
}

static int sqlcipher_vle_x_column(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int i){
  sqlcipher_vle_cursor *pCur = (sqlcipher_vle_cursor*)cur;
  sqlcipher_vle_vtab *pTab = (sqlcipher_vle_vtab*)cur->pVtab;
  int colIdx = i + 1; /* offset for the leading rowid column in the SELECT */

  if( pTab->abExcluded[i] ){
    sqlite3_result_value(ctx, sqlite3_column_value(pCur->pStmt, colIdx));
    return SQLITE_OK;
  }else{
    const unsigned char *envelope;
    int envelope_sz;
    unsigned char *context; int context_sz;
    sqlite3_int64 rowid;
    int type; unsigned char *payload; int payload_sz; char *errmsg = 0;
    int rc;

    if( sqlite3_column_type(pCur->pStmt, colIdx)==SQLITE_NULL ){
      sqlite3_result_null(ctx);
      return SQLITE_OK;
    }
    if( !pTab->vctx->key ){
      sqlite3_result_error(ctx, "sqlcipher_vle: no key set (call sqlcipher_vle_key() first)", -1);
      return SQLITE_ERROR;
    }

    envelope = sqlite3_column_blob(pCur->pStmt, colIdx);
    envelope_sz = sqlite3_column_bytes(pCur->pStmt, colIdx);
    rowid = sqlite3_column_int64(pCur->pStmt, 0);

    rc = sqlcipher_vle_build_cell_context(pTab->zTabName, i, rowid, &context, &context_sz);
    if( rc!=SQLITE_OK ){ sqlite3_result_error_nomem(ctx); return SQLITE_ERROR; }

    rc = sqlcipher_vle_decrypt_core(pTab->vctx, pTab->vctx->key, pTab->vctx->key_sz, context, context_sz, envelope, envelope_sz, &type, &payload, &payload_sz, &errmsg);
    sqlite3_free(context);
    if( rc!=SQLITE_OK ){
      sqlite3_result_error(ctx, errmsg ? errmsg : "sqlcipher_vle: decryption failed", -1);
      sqlite3_free(errmsg);
      return SQLITE_ERROR;
    }
    sqlcipher_vle_set_result(ctx, type, payload, payload_sz);
    sqlite3_free(payload);
    return SQLITE_OK;
  }
}

/* Encrypts one column's value for the given rowid and issues
** UPDATE shadow SET col=? WHERE rowid=? -- the backfill half of xUpdate's
** two-step INSERT path (see doc/vle.md). */
static int sqlcipher_vle_encrypt_and_store(sqlcipher_vle_vtab *pTab, int iCol, sqlite3_int64 rowid, sqlite3_value *pVal){
  unsigned char *context = 0; int context_sz = 0;
  int type; const unsigned char *payload; int payload_sz; unsigned char scratch8[8];
  unsigned char *blob = 0; int blob_sz = 0; char *errmsg = 0;
  char *zSql; sqlite3_stmt *pStmt; int rc;

  sqlcipher_vle_serialize_value(pVal, &type, &payload, &payload_sz, scratch8);
  rc = sqlcipher_vle_build_cell_context(pTab->zTabName, iCol, rowid, &context, &context_sz);
  if( rc!=SQLITE_OK ) return rc;
  rc = sqlcipher_vle_encrypt_core(pTab->vctx, pTab->vctx->key, pTab->vctx->key_sz, context, context_sz, type, payload, payload_sz, &blob, &blob_sz, &errmsg);
  sqlite3_free(context);
  if( rc!=SQLITE_OK ){ pTab->base.zErrMsg = errmsg; return rc; }

  zSql = sqlite3_mprintf("UPDATE \"%w\" SET \"%w\" = ?1 WHERE rowid = ?2", pTab->zShadowName, pTab->azCol[iCol]);
  if( !zSql ){ sqlite3_free(blob); return SQLITE_NOMEM; }
  rc = sqlite3_prepare_v2(pTab->db, zSql, -1, &pStmt, 0);
  sqlite3_free(zSql);
  if( rc!=SQLITE_OK ){
    sqlite3_free(blob);
    pTab->base.zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
    return rc;
  }
  sqlite3_bind_blob(pStmt, 1, blob, blob_sz, sqlite3_free);
  sqlite3_bind_int64(pStmt, 2, rowid);
  rc = sqlite3_step(pStmt);
  rc = (rc==SQLITE_DONE) ? SQLITE_OK : rc;
  if( rc!=SQLITE_OK ) pTab->base.zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
  sqlite3_finalize(pStmt);
  return rc;
}

static int sqlcipher_vle_x_update(sqlite3_vtab *pVtab, int argc, sqlite3_value **argv, sqlite3_int64 *pRowid){
  sqlcipher_vle_vtab *pTab = (sqlcipher_vle_vtab*)pVtab;
  int rc;

  if( argc==1 ){
    /* DELETE */
    char *zSql = sqlite3_mprintf("DELETE FROM \"%w\" WHERE rowid = ?1", pTab->zShadowName);
    sqlite3_stmt *pStmt;
    if( !zSql ) return SQLITE_NOMEM;
    rc = sqlite3_prepare_v2(pTab->db, zSql, -1, &pStmt, 0);
    sqlite3_free(zSql);
    if( rc!=SQLITE_OK ){ pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db)); return rc; }
    sqlite3_bind_value(pStmt, 1, argv[0]);
    rc = sqlite3_step(pStmt);
    rc = (rc==SQLITE_DONE) ? SQLITE_OK : rc;
    if( rc!=SQLITE_OK ) pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
    sqlite3_finalize(pStmt);
    return rc;
  }

  if( !pTab->vctx->key ){
    pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: no key set (call sqlcipher_vle_key() first)");
    return SQLITE_ERROR;
  }

  if( sqlite3_value_type(argv[0])==SQLITE_NULL ){
    /* INSERT: two-step -- placeholder insert, then backfill encrypted columns
    ** once the (possibly auto-assigned) rowid is known. */
    sqlite3_int64 rowid;
    char *zCols = 0, *zVals = 0, *zSql;
    sqlite3_stmt *pStmt;
    int i;
    int haveRowid = sqlite3_value_type(argv[1])!=SQLITE_NULL;

    for(i=0; i<pTab->nCol; i++){
      zCols = sqlcipher_vle_append(zCols, "%s\"%w\"", i>0 ? ", " : "", pTab->azCol[i]);
      zVals = sqlcipher_vle_append(zVals, "%s?%d", i>0 ? ", " : "", i+1);
    }
    if( !zCols || !zVals ){ sqlite3_free(zCols); sqlite3_free(zVals); return SQLITE_NOMEM; }

    if( haveRowid ){
      zSql = sqlite3_mprintf("INSERT INTO \"%w\"(rowid, %s) VALUES(?%d, %s)", pTab->zShadowName, zCols, pTab->nCol+1, zVals);
    }else{
      zSql = sqlite3_mprintf("INSERT INTO \"%w\"(%s) VALUES(%s)", pTab->zShadowName, zCols, zVals);
    }
    sqlite3_free(zCols); sqlite3_free(zVals);
    if( !zSql ) return SQLITE_NOMEM;

    rc = sqlite3_prepare_v2(pTab->db, zSql, -1, &pStmt, 0);
    sqlite3_free(zSql);
    if( rc!=SQLITE_OK ){ pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db)); return rc; }

    for(i=0; i<pTab->nCol; i++){
      if( pTab->abExcluded[i] ) sqlite3_bind_value(pStmt, i+1, argv[2+i]);
      else sqlite3_bind_null(pStmt, i+1);
    }
    if( haveRowid ) sqlite3_bind_value(pStmt, pTab->nCol+1, argv[1]);

    rc = sqlite3_step(pStmt);
    sqlite3_finalize(pStmt);
    if( rc!=SQLITE_DONE ){ pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db)); return rc; }

    rowid = haveRowid ? sqlite3_value_int64(argv[1]) : sqlite3_last_insert_rowid(pTab->db);

    for(i=0; i<pTab->nCol; i++){
      if( pTab->abExcluded[i] ) continue;
      rc = sqlcipher_vle_encrypt_and_store(pTab, i, rowid, argv[2+i]);
      if( rc!=SQLITE_OK ) return rc;
    }
    *pRowid = rowid;
    return SQLITE_OK;
  }else{
    /* UPDATE: the target rowid is known upfront, so encrypted columns can be
    ** computed before issuing a single UPDATE (no backfill needed). */
    sqlite3_int64 oldRowid = sqlite3_value_int64(argv[0]);
    sqlite3_int64 newRowid = sqlite3_value_type(argv[1])==SQLITE_NULL ? oldRowid : sqlite3_value_int64(argv[1]);
    char *zSet = 0, *zSql;
    sqlite3_stmt *pStmt;
    int i;
    unsigned char **blobs; int *blobSzs;

    blobs = sqlite3_malloc(sizeof(unsigned char*) * (pTab->nCol>0 ? pTab->nCol : 1));
    blobSzs = sqlite3_malloc(sizeof(int) * (pTab->nCol>0 ? pTab->nCol : 1));
    if( !blobs || !blobSzs ){ sqlite3_free(blobs); sqlite3_free(blobSzs); return SQLITE_NOMEM; }
    memset(blobs, 0, sizeof(unsigned char*) * (pTab->nCol>0 ? pTab->nCol : 1));

    rc = SQLITE_OK;
    for(i=0; i<pTab->nCol; i++){
      zSet = sqlcipher_vle_append(zSet, "%s\"%w\" = ?%d", i>0 ? ", " : "", pTab->azCol[i], i+1);
      if( !zSet ){ rc = SQLITE_NOMEM; goto update_done; }
      if( !pTab->abExcluded[i] ){
        unsigned char *context; int context_sz; int type; const unsigned char *payload; int payload_sz;
        unsigned char scratch8[8]; char *errmsg = 0;
        sqlcipher_vle_serialize_value(argv[2+i], &type, &payload, &payload_sz, scratch8);
        rc = sqlcipher_vle_build_cell_context(pTab->zTabName, i, newRowid, &context, &context_sz);
        if( rc!=SQLITE_OK ) goto update_done;
        rc = sqlcipher_vle_encrypt_core(pTab->vctx, pTab->vctx->key, pTab->vctx->key_sz, context, context_sz, type, payload, payload_sz, &blobs[i], &blobSzs[i], &errmsg);
        sqlite3_free(context);
        if( rc!=SQLITE_OK ){ pVtab->zErrMsg = errmsg; goto update_done; }
      }
    }
    zSql = sqlite3_mprintf("UPDATE \"%w\" SET rowid = ?%d, %s WHERE rowid = ?%d", pTab->zShadowName, pTab->nCol+1, zSet, pTab->nCol+2);
    sqlite3_free(zSet); zSet = 0;
    if( !zSql ){ rc = SQLITE_NOMEM; goto update_done; }
    rc = sqlite3_prepare_v2(pTab->db, zSql, -1, &pStmt, 0);
    sqlite3_free(zSql);
    if( rc!=SQLITE_OK ){ pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db)); goto update_done; }
    for(i=0; i<pTab->nCol; i++){
      if( pTab->abExcluded[i] ) sqlite3_bind_value(pStmt, i+1, argv[2+i]);
      else sqlite3_bind_blob(pStmt, i+1, blobs[i], blobSzs[i], SQLITE_TRANSIENT);
    }
    sqlite3_bind_int64(pStmt, pTab->nCol+1, newRowid);
    sqlite3_bind_int64(pStmt, pTab->nCol+2, oldRowid);
    rc = sqlite3_step(pStmt);
    rc = (rc==SQLITE_DONE) ? SQLITE_OK : rc;
    if( rc!=SQLITE_OK ) pVtab->zErrMsg = sqlite3_mprintf("sqlcipher_vle: %s", sqlite3_errmsg(pTab->db));
    sqlite3_finalize(pStmt);
    if( rc==SQLITE_OK ) *pRowid = newRowid;

  update_done:
    for(i=0; i<pTab->nCol; i++) sqlite3_free(blobs[i]);
    sqlite3_free(blobs); sqlite3_free(blobSzs);
    return rc;
  }
}

static int sqlcipher_vle_x_shadow_name(const char *zName){
  return sqlite3_stricmp(zName, "shadow")==0;
}

static sqlite3_module sqlcipher_vle_module = {
  3,                              /* iVersion */
  sqlcipher_vle_x_create,
  sqlcipher_vle_x_connect,
  sqlcipher_vle_x_best_index,
  sqlcipher_vle_x_disconnect,
  sqlcipher_vle_x_destroy,
  sqlcipher_vle_x_open,
  sqlcipher_vle_x_close,
  sqlcipher_vle_x_filter,
  sqlcipher_vle_x_next,
  sqlcipher_vle_x_eof,
  sqlcipher_vle_x_column,
  sqlcipher_vle_x_rowid,
  sqlcipher_vle_x_update,
  0,                              /* xBegin */
  0,                              /* xSync */
  0,                              /* xCommit */
  0,                              /* xRollback */
  0,                              /* xFindFunction */
  0,                              /* xRename */
  0,                              /* xSavepoint */
  0,                              /* xRelease */
  0,                              /* xRollbackTo */
  sqlcipher_vle_x_shadow_name,
  0                               /* xIntegrity */
};

static void sqlcipher_vle_ctx_destroy(void *p){
  sqlcipher_vle_ctx *vctx = (sqlcipher_vle_ctx*)p;
  if( !vctx ) return;
  if( vctx->key ){
    sqlcipher_memset(vctx->key, 0, vctx->key_sz);
    sqlite3_free(vctx->key);
  }
  if( vctx->provider && vctx->provider->ctx_free ){
    vctx->provider->ctx_free(&vctx->provider_ctx);
  }
  sqlite3_free(vctx);
}

/* Auto-extension entry point: registered once via sqlite3_auto_extension()
** in sqlcipher_extra_init() (see src/sqlcipher.c), it runs on every new
** connection, allocating one sqlcipher_vle_ctx (holding the per-connection
** VLE key) shared as user-data across all sqlcipher_vle_* functions and the
** sqlcipher_vle virtual table module. */
int sqlcipher_vle_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi){
  sqlcipher_vle_ctx *vctx;
  sqlcipher_provider *provider = sqlcipher_get_provider();
  int rc;

  if( !provider ) return SQLITE_ERROR;

  vctx = sqlite3_malloc(sizeof(sqlcipher_vle_ctx));
  if( !vctx ) return SQLITE_NOMEM;
  memset(vctx, 0, sizeof(*vctx));
  vctx->provider = provider;
  if( (rc = provider->ctx_init(&vctx->provider_ctx))!=SQLITE_OK ){
    sqlite3_free(vctx);
    return rc;
  }

  sqlite3_create_function_v2(db, "sqlcipher_vle_random", 1, SQLITE_UTF8, vctx, sqlcipher_vle_random_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_kdf", -1, SQLITE_UTF8, vctx, sqlcipher_vle_kdf_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_key", 1, SQLITE_UTF8, vctx, sqlcipher_vle_key_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_encrypt", -1, SQLITE_UTF8, vctx, sqlcipher_vle_encrypt_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_decrypt", -1, SQLITE_UTF8, vctx, sqlcipher_vle_decrypt_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_cipher", 5, SQLITE_UTF8, vctx, sqlcipher_vle_cipher_func, 0, 0, 0);
  sqlite3_create_function_v2(db, "sqlcipher_vle_hmac", 2, SQLITE_UTF8, vctx, sqlcipher_vle_hmac_func, 0, 0, 0);

  rc = sqlite3_create_module_v2(db, "sqlcipher_vle", &sqlcipher_vle_module, vctx, sqlcipher_vle_ctx_destroy);
  if( rc!=SQLITE_OK ){
    sqlcipher_vle_ctx_destroy(vctx);
    return rc;
  }
  return SQLITE_OK;
}

#endif
/* END SQLCIPHER */
