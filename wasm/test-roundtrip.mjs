// SQLCipher WASM round-trip verification, run under Node.js.
//
// Exercises both APIs exported from wasm/sqlcipher.js (built by
// tool/build-wasm.sh): the SQLite/SQLCipher C API (sqlite3_open/key/exec/
// prepare/step/...) and leancrypto's own raw AEAD/HKDF API (via the
// wasm/leancrypto_wasm_api.c wrappers). See wasm/README.md.
//
// Usage: node wasm/test-roundtrip.mjs

import Sqlite3Wasm from './sqlcipher.js';

const SQLITE_OK = 0;
const SQLITE_ROW = 100;

let failures = 0;
function check(name, cond, detail) {
  if (cond) {
    console.log(`ok - ${name}`);
  } else {
    failures++;
    console.log(`NOT OK - ${name}${detail ? ': ' + detail : ''}`);
  }
}

function cString(Module, str) {
  const len = Module.lengthBytesUTF8(str);
  const ptr = Module._malloc(len + 1);
  Module.stringToUTF8(str, ptr, len + 1);
  return { ptr, len };
}

function hexKey(byteValue, byteCount) {
  const hex = byteValue.toString(16).padStart(2, '0');
  return "x'" + hex.repeat(byteCount) + "'";
}

function openDb(Module, filename, keyStr) {
  const ppDb = Module._malloc(4);
  const { ptr: fnPtr } = cString(Module, filename);
  const rc = Module._sqlite3_open(fnPtr, ppDb);
  const db = Module.getValue(ppDb, 'i32');
  Module._free(ppDb);
  Module._free(fnPtr);
  if (rc !== SQLITE_OK) return { db, rc };
  if (keyStr !== null) {
    const { ptr: keyPtr, len: keyLen } = cString(Module, keyStr);
    const krc = Module._sqlite3_key(db, keyPtr, keyLen);
    Module._free(keyPtr);
    if (krc !== SQLITE_OK) return { db, rc: krc };
  }
  return { db, rc: SQLITE_OK };
}

function exec(Module, db, sql) {
  const { ptr } = cString(Module, sql);
  const rc = Module._sqlite3_exec(db, ptr, 0, 0, 0);
  Module._free(ptr);
  return rc;
}

function errmsg(Module, db) {
  const p = Module._sqlite3_errmsg(db);
  return p ? Module.UTF8ToString(p) : '';
}

function queryScalarInt(Module, db, sql) {
  const ppStmt = Module._malloc(4);
  const { ptr } = cString(Module, sql);
  const rc = Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
  Module._free(ptr);
  if (rc !== SQLITE_OK) { Module._free(ppStmt); return null; }
  const stmt = Module.getValue(ppStmt, 'i32');
  Module._free(ppStmt);
  const srow = Module._sqlite3_step(stmt);
  let value = null;
  if (srow === SQLITE_ROW) value = Module._sqlite3_column_int(stmt, 0);
  Module._sqlite3_finalize(stmt);
  return value;
}

function queryScalarText(Module, db, sql) {
  const ppStmt = Module._malloc(4);
  const { ptr } = cString(Module, sql);
  const rc = Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
  Module._free(ptr);
  if (rc !== SQLITE_OK) { Module._free(ppStmt); return null; }
  const stmt = Module.getValue(ppStmt, 'i32');
  Module._free(ppStmt);
  const srow = Module._sqlite3_step(stmt);
  let value = null;
  if (srow === SQLITE_ROW) {
    const textPtr = Module._sqlite3_column_text(stmt, 0);
    value = Module.UTF8ToString(textPtr);
  }
  Module._sqlite3_finalize(stmt);
  return value;
}

function collectRows(Module, db, sql) {
  const rows = [];
  const ppStmt = Module._malloc(4);
  const { ptr } = cString(Module, sql);
  const rc = Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
  Module._free(ptr);
  if (rc !== SQLITE_OK) { Module._free(ppStmt); return rows; }
  const stmt = Module.getValue(ppStmt, 'i32');
  Module._free(ppStmt);
  while (Module._sqlite3_step(stmt) === SQLITE_ROW) {
    const a = Module._sqlite3_column_int(stmt, 0);
    const bPtr = Module._sqlite3_column_text(stmt, 1);
    rows.push([a, Module.UTF8ToString(bPtr)]);
  }
  Module._sqlite3_finalize(stmt);
  return rows;
}

function collectTextRows(Module, db, sql) {
  const rows = [];
  const ppStmt = Module._malloc(4);
  const { ptr } = cString(Module, sql);
  const rc = Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
  Module._free(ptr);
  if (rc !== SQLITE_OK) { Module._free(ppStmt); return rows; }
  const stmt = Module.getValue(ppStmt, 'i32');
  Module._free(ppStmt);
  while (Module._sqlite3_step(stmt) === SQLITE_ROW) {
    const textPtr = Module._sqlite3_column_text(stmt, 0);
    rows.push(Module.UTF8ToString(textPtr));
  }
  Module._sqlite3_finalize(stmt);
  return rows;
}

function rekey(Module, db, keyStr) {
  const { ptr, len } = cString(Module, keyStr);
  const rc = Module._sqlite3_rekey(db, ptr, len);
  Module._free(ptr);
  return rc;
}

async function main() {
  const Module = await Sqlite3Wasm();
  console.log(`# sqlite3 version: ${Module.UTF8ToString(Module._sqlite3_libversion())}`);

  const validKey = hexKey(0x42, 256); // 256 bytes, well-formed
  const shortKey = hexKey(0x11, 8);   // deliberately too short

  // ---------------------------------------------------------------------
  // 1. Round trip: create/insert, close, reopen with same key, read back
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/roundtrip.db'); } catch (e) {}

  {
    const { db, rc } = openDb(Module, '/roundtrip.db', validKey);
    check('open db with valid key', rc === SQLITE_OK, `rc=${rc}`);

    let erc = exec(Module, db, 'CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT);');
    check('create table', erc === SQLITE_OK, errmsg(Module, db));

    erc = exec(Module, db,
      "INSERT INTO t(a,b) VALUES (1,'row one'),(2,'row two'),(3,'row three');");
    check('insert rows', erc === SQLITE_OK, errmsg(Module, db));

    Module._sqlite3_close(db);
  }

  {
    const { db, rc } = openDb(Module, '/roundtrip.db', validKey);
    check('reopen with same key', rc === SQLITE_OK, `rc=${rc}`);

    const rows = collectRows(Module, db, 'SELECT a,b FROM t ORDER BY a;');
    check('round-trip row count', rows.length === 3, JSON.stringify(rows));
    check('round-trip row content', JSON.stringify(rows) ===
      JSON.stringify([[1, 'row one'], [2, 'row two'], [3, 'row three']]),
      JSON.stringify(rows));

    const provider = queryScalarText(Module, db, 'PRAGMA cipher_provider;');
    check('cipher_provider == leancrypto', provider === 'leancrypto', provider);

    const cipher = queryScalarText(Module, db, 'PRAGMA cipher;');
    check('cipher == ascon-keccak-512', cipher === 'ascon-keccak-512', cipher);

    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 2. Wrong key is rejected
  // ---------------------------------------------------------------------
  {
    const wrongKey = hexKey(0x99, 256);
    const { db } = openDb(Module, '/roundtrip.db', wrongKey);
    const n = queryScalarInt(Module, db, 'SELECT count(*) FROM t;');
    check('wrong key rejected (no readable rows)', n === null, `n=${n}`);
    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 3. Key length boundaries (256-8192 bytes, see doc/crypto.md "Key
  //    provisioning"). Out-of-range keys are rejected immediately by
  //    sqlite3_key() itself -- not deferred to first table access -- and a
  //    rejected key leaves the connection exactly as if no key had ever
  //    been supplied, so a *subsequent* statement like CREATE TABLE
  //    actually succeeds (on a plain, unencrypted connection) rather than
  //    failing.
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/shortkey.db'); } catch (e) {}
  {
    const { db, rc } = openDb(Module, '/shortkey.db', shortKey);
    check('undersized key rejected', rc !== SQLITE_OK, `rc=${rc}`);

    const erc = exec(Module, db, 'CREATE TABLE z(a); INSERT INTO z VALUES(1);');
    check('rejected key leaves connection unkeyed (plain table succeeds)',
      erc === SQLITE_OK, errmsg(Module, db));

    Module._sqlite3_close(db);
  }

  try { Module.FS.unlink('/maxkey.db'); } catch (e) {}
  {
    const maxKey = hexKey(0x07, 8192);
    const { db, rc } = openDb(Module, '/maxkey.db', maxKey);
    check('key at exact maximum (8192 bytes) accepted', rc === SQLITE_OK, `rc=${rc}`);

    const erc = exec(Module, db, 'CREATE TABLE m(a);');
    check('create table with max-size key', erc === SQLITE_OK, errmsg(Module, db));

    Module._sqlite3_close(db);
  }

  try { Module.FS.unlink('/overkey.db'); } catch (e) {}
  {
    const overKey = hexKey(0x07, 8193);
    const { db, rc } = openDb(Module, '/overkey.db', overKey);
    check('key one byte over maximum (8193 bytes) rejected', rc !== SQLITE_OK, `rc=${rc}`);
    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 4. PRAGMA rekey: an out-of-range new key is rejected before any page is
  //    rewritten (existing data/key remain fully intact, both on the same
  //    connection and after closing and reopening with the original key),
  //    and a valid rekey actually re-encrypts the database under the new
  //    key (the old key stops working, the new key reads the same data).
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/rekey.db'); } catch (e) {}
  {
    const { db } = openDb(Module, '/rekey.db', validKey);
    exec(Module, db, 'CREATE TABLE r(a); INSERT INTO r VALUES(42);');

    const badRekeyRc = rekey(Module, db, shortKey);
    check('rekey with undersized key rejected', badRekeyRc !== SQLITE_OK, `rc=${badRekeyRc}`);

    const stillThereSameConn = queryScalarInt(Module, db, 'SELECT a FROM r;');
    check('data intact after rejected rekey (same connection)',
      stillThereSameConn === 42, `a=${stillThereSameConn}`);
    Module._sqlite3_close(db);

    const { db: db2, rc: rc2 } = openDb(Module, '/rekey.db', validKey);
    check('reopen with original key after rejected rekey', rc2 === SQLITE_OK, `rc=${rc2}`);
    const stillThereReopen = queryScalarInt(Module, db2, 'SELECT a FROM r;');
    check('data intact after reopen with original key',
      stillThereReopen === 42, `a=${stillThereReopen}`);

    const newKey = hexKey(0x77, 256);
    const goodRekeyRc = rekey(Module, db2, newKey);
    check('valid rekey succeeds', goodRekeyRc === SQLITE_OK, `rc=${goodRekeyRc}`);
    Module._sqlite3_close(db2);

    const { db: db3 } = openDb(Module, '/rekey.db', validKey);
    const oldKeyRead = queryScalarInt(Module, db3, 'SELECT a FROM r;');
    check('old key no longer works after rekey', oldKeyRead === null, `a=${oldKeyRead}`);
    Module._sqlite3_close(db3);

    const { db: db4, rc: rc4 } = openDb(Module, '/rekey.db', newKey);
    check('reopen with new key after rekey', rc4 === SQLITE_OK, `rc=${rc4}`);
    const newKeyRead = queryScalarInt(Module, db4, 'SELECT a FROM r;');
    check('data intact after rekey, read with new key', newKeyRead === 42, `a=${newKeyRead}`);
    Module._sqlite3_close(db4);
  }

  // ---------------------------------------------------------------------
  // 5. On-disk v2 header layout: magic/version/pgno match doc/crypto.md's
  //    "Per-page blob format" (CIPHER_VERSION_MAJOR/MINOR = 0x02/0x00,
  //    reserve_sz = 140 bytes, with an 8-byte big-endian pgno field stored
  //    right after magic||version -- see src/sqlcipher.c
  //    sqlcipher_page_cipher). This checks the raw on-disk bytes directly,
  //    the same way test/sqlcipher-leancrypto.test's salt-offset checks do
  //    for the native build, so a wasm-specific layout regression would be
  //    caught even if it didn't happen to break the splicing test below.
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/header.db'); } catch (e) {}
  {
    const PAGE_SZ = 4096;
    const RESERVE_SZ = 140;
    const { db } = openDb(Module, '/header.db', validKey);
    exec(Module, db, 'CREATE TABLE h(a INTEGER PRIMARY KEY, b);');
    exec(Module, db, 'BEGIN;');
    for (let i = 1; i <= 20; i++) {
      exec(Module, db, `INSERT INTO h(a,b) VALUES(${i}, zeroblob(1500));`);
    }
    exec(Module, db, 'COMMIT;');
    Module._sqlite3_close(db);

    const bytes = Module.FS.readFile('/header.db');
    check('header test db has at least 3 pages', bytes.length >= 3 * PAGE_SZ, `size=${bytes.length}`);

    // reads the reserve-region header (magic||version||pgno) for a given
    // 1-indexed page number directly out of the raw file bytes
    function readHeader(pgno) {
      const pageStart = (pgno - 1) * PAGE_SZ;
      const off = pageStart + (PAGE_SZ - RESERVE_SZ);
      const magic0 = bytes[off], magic1 = bytes[off + 1];
      const verMajor = bytes[off + 2], verMinor = bytes[off + 3];
      let storedPgno = 0n;
      for (let i = 0; i < 8; i++) storedPgno = (storedPgno << 8n) | BigInt(bytes[off + 4 + i]);
      return { magic0, magic1, verMajor, verMinor, storedPgno };
    }

    for (const pgno of [1, 2, 3]) {
      const h = readHeader(pgno);
      check(`page ${pgno} magic bytes are "TX"`, h.magic0 === 0x54 && h.magic1 === 0x58,
        `0x${h.magic0.toString(16)} 0x${h.magic1.toString(16)}`);
      check(`page ${pgno} version is 0x02 0x00`, h.verMajor === 0x02 && h.verMinor === 0x00,
        `0x${h.verMajor.toString(16)} 0x${h.verMinor.toString(16)}`);
      check(`page ${pgno} on-disk pgno matches its own page number`,
        h.storedPgno === BigInt(pgno), `stored=${h.storedPgno}`);
    }
  }

  // ---------------------------------------------------------------------
  // 6. Page splicing is detected: copying one page's entire on-disk blob
  //    onto a different page's slot must fail AEAD authentication, since
  //    the AAD now binds the page number (see doc/crypto.md "Per-page
  //    blob format" and the former "Known limitations" entry this closes).
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/splice.db'); } catch (e) {}
  {
    const PAGE_SZ = 4096;
    const { db } = openDb(Module, '/splice.db', validKey);
    exec(Module, db, 'CREATE TABLE s(a INTEGER PRIMARY KEY, b);');
    exec(Module, db, 'BEGIN;');
    for (let i = 1; i <= 20; i++) {
      exec(Module, db, `INSERT INTO s(a,b) VALUES(${i}, zeroblob(1500));`);
    }
    exec(Module, db, 'COMMIT;');
    Module._sqlite3_close(db);

    const bytes = Module.FS.readFile('/splice.db');
    check('splice test db has at least 3 pages', bytes.length >= 3 * PAGE_SZ, `size=${bytes.length}`);

    // copy page 2's entire on-disk blob onto page 3's slot (0-indexed offsets)
    const page2 = bytes.slice(1 * PAGE_SZ, 2 * PAGE_SZ);
    bytes.set(page2, 2 * PAGE_SZ);
    Module.FS.writeFile('/splice.db', bytes);

    const { db: db2 } = openDb(Module, '/splice.db', validKey);
    const failRows = collectTextRows(Module, db2, 'PRAGMA cipher_integrity_check;');
    check('page splicing detected by cipher_integrity_check',
      failRows.length > 0, JSON.stringify(failRows));
    Module._sqlite3_close(db2);
  }

  // ---------------------------------------------------------------------
  // 7. Raw leancrypto API: AEAD round trip + tamper detection
  // ---------------------------------------------------------------------
  {
    const keySz = Module._lc_wasm_key_size();
    const nonceSz = Module._lc_wasm_nonce_size();
    const tagSz = Module._lc_wasm_tag_size();
    check('lc_wasm sizes are 64/64/64', keySz === 64 && nonceSz === 64 && tagSz === 64,
      `${keySz}/${nonceSz}/${tagSz}`);

    const key = Module._malloc(keySz);
    const nonce = Module._malloc(nonceSz);
    for (let i = 0; i < keySz; i++) Module.setValue(key + i, (i * 7) & 0xff, 'i8');
    for (let i = 0; i < nonceSz; i++) Module.setValue(nonce + i, (i * 3) & 0xff, 'i8');

    const aad = cString(Module, 'leancrypto-wasm-aad');
    const plaintext = cString(Module, 'hello from leancrypto wasm api');
    const dataLen = plaintext.len;
    const ciphertext = Module._malloc(dataLen);
    const tag = Module._malloc(tagSz);

    const encRc = Module._lc_wasm_aead_encrypt(
      key, keySz, nonce, nonceSz, aad.ptr, aad.len,
      plaintext.ptr, dataLen, ciphertext, tag, tagSz);
    check('lc_wasm_aead_encrypt succeeds', encRc === 0, `rc=${encRc}`);

    const decrypted = Module._malloc(dataLen);
    const decRc = Module._lc_wasm_aead_decrypt(
      key, keySz, nonce, nonceSz, aad.ptr, aad.len,
      ciphertext, dataLen, decrypted, tag, tagSz);
    check('lc_wasm_aead_decrypt succeeds', decRc === 0, `rc=${decRc}`);

    let decryptedBytes = [];
    for (let i = 0; i < dataLen; i++) decryptedBytes.push(Module.getValue(decrypted + i, 'i8') & 0xff);
    const decryptedStr = Buffer.from(decryptedBytes).toString('utf8');
    check('lc_wasm AEAD round-trip content matches',
      decryptedStr === 'hello from leancrypto wasm api', decryptedStr);

    // tamper with one ciphertext byte, confirm decrypt now fails
    const before = Module.getValue(ciphertext, 'i8');
    Module.setValue(ciphertext, (before ^ 0xff) & 0xff, 'i8');
    const tamperedDecrypted = Module._malloc(dataLen);
    const tamperRc = Module._lc_wasm_aead_decrypt(
      key, keySz, nonce, nonceSz, aad.ptr, aad.len,
      ciphertext, dataLen, tamperedDecrypted, tag, tagSz);
    check('lc_wasm_aead_decrypt detects tampering', tamperRc !== 0, `rc=${tamperRc}`);

    // ---------------------------------------------------------------------
    // 8. Raw leancrypto API: HKDF-SHA3-512
    // ---------------------------------------------------------------------
    const ikm = Module._malloc(300);
    for (let i = 0; i < 300; i++) Module.setValue(ikm + i, (i * 5 + 1) & 0xff, 'i8');
    const salt = Module._malloc(64);
    for (let i = 0; i < 64; i++) Module.setValue(salt + i, i & 0xff, 'i8');
    const info = cString(Module, 'lc-wasm-test-info');
    const out1 = Module._malloc(64);
    const out2 = Module._malloc(64);

    const hkdfRc1 = Module._lc_wasm_hkdf_sha3_512(ikm, 300, salt, 64, info.ptr, info.len, out1, 64);
    check('lc_wasm_hkdf_sha3_512 succeeds', hkdfRc1 === 0, `rc=${hkdfRc1}`);

    // same inputs must reproduce the same output deterministically
    const hkdfRc2 = Module._lc_wasm_hkdf_sha3_512(ikm, 300, salt, 64, info.ptr, info.len, out2, 64);
    check('lc_wasm_hkdf_sha3_512 succeeds (2nd call)', hkdfRc2 === 0, `rc=${hkdfRc2}`);

    let out1Bytes = [], out2Bytes = [];
    for (let i = 0; i < 64; i++) {
      out1Bytes.push(Module.getValue(out1 + i, 'i8') & 0xff);
      out2Bytes.push(Module.getValue(out2 + i, 'i8') & 0xff);
    }
    check('HKDF output is deterministic', out1Bytes.join(',') === out2Bytes.join(','));
    check('HKDF output is non-trivial (not all zero)', out1Bytes.some((b) => b !== 0));

    Module._free(key); Module._free(nonce); Module._free(aad.ptr);
    Module._free(plaintext.ptr); Module._free(ciphertext); Module._free(tag);
    Module._free(decrypted); Module._free(tamperedDecrypted);
    Module._free(ikm); Module._free(salt); Module._free(info.ptr);
    Module._free(out1); Module._free(out2);
  }

  console.log('');
  if (failures === 0) {
    console.log('ALL TESTS PASSED');
    process.exit(0);
  } else {
    console.log(`${failures} TEST(S) FAILED`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
