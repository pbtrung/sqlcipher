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
const SQLITE_DONE = 101;

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

// Prepares and steps one statement, returning {rc, stmt, msg} without
// finalizing -- used for statements expected to fail (rc is SQLITE_ROW/
// SQLITE_DONE on success, or a prepare/step error code otherwise) where the
// caller wants both the code and sqlite3_errmsg() text. Callers must
// finalize a non-zero stmt themselves.
function prepareStep(Module, db, sql) {
  const ppStmt = Module._malloc(4);
  const { ptr } = cString(Module, sql);
  const prc = Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
  Module._free(ptr);
  const stmt = Module.getValue(ppStmt, 'i32');
  Module._free(ppStmt);
  if (prc !== SQLITE_OK) return { rc: prc, stmt: 0, msg: errmsg(Module, db) };
  const rc = Module._sqlite3_step(stmt);
  return { rc, stmt, msg: errmsg(Module, db) };
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

  // ---------------------------------------------------------------------
  // 9. SQLITE_ENABLE_DBSTAT_VTAB / SQLITE_ENABLE_DBPAGE_VTAB (tool/build-wasm.sh):
  //    confirm both virtual tables actually work against an encrypted
  //    connection, not just that the module still links with them compiled
  //    in -- values are cross-checked against PRAGMA page_count/page_size
  //    and sqlite_master.rootpage rather than just "query didn't error".
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/vtab.db'); } catch (e) {}
  {
    const { db } = openDb(Module, '/vtab.db', validKey);
    exec(Module, db, 'CREATE TABLE v(a INTEGER PRIMARY KEY, b);');
    exec(Module, db, 'BEGIN;');
    for (let i = 1; i <= 20; i++) {
      exec(Module, db, `INSERT INTO v(a,b) VALUES(${i}, zeroblob(1500));`);
    }
    exec(Module, db, 'COMMIT;');

    const pageCount = queryScalarInt(Module, db, 'PRAGMA page_count;');
    const pageSize = queryScalarInt(Module, db, 'PRAGMA page_size;');
    check('vtab test db has at least 3 pages', pageCount >= 3, `page_count=${pageCount}`);

    const dbpageCount = queryScalarInt(Module, db, 'SELECT count(*) FROM sqlite_dbpage;');
    check('sqlite_dbpage row count matches PRAGMA page_count', dbpageCount === pageCount,
      `dbpage=${dbpageCount} page_count=${pageCount}`);

    const dbpageMaxPgno = queryScalarInt(Module, db, 'SELECT max(pgno) FROM sqlite_dbpage;');
    check('sqlite_dbpage max(pgno) matches PRAGMA page_count', dbpageMaxPgno === pageCount,
      `max(pgno)=${dbpageMaxPgno} page_count=${pageCount}`);

    const page1Len = queryScalarInt(Module, db, 'SELECT length(data) FROM sqlite_dbpage WHERE pgno=1;');
    check('sqlite_dbpage page 1 data length matches PRAGMA page_size', page1Len === pageSize,
      `len=${page1Len} page_size=${pageSize}`);

    const rootpage = queryScalarInt(Module, db, "SELECT rootpage FROM sqlite_master WHERE name='v';");
    const dbstatRows = queryScalarInt(Module, db,
      `SELECT count(*) FROM dbstat WHERE name='v' AND pageno=${rootpage};`);
    check('dbstat resolves table v root page', dbstatRows === 1, `rows=${dbstatRows}`);

    const dbstatPgsize = queryScalarInt(Module, db,
      `SELECT pgsize FROM dbstat WHERE name='v' AND pageno=${rootpage};`);
    check('dbstat pgsize matches PRAGMA page_size', dbstatPgsize === pageSize,
      `pgsize=${dbstatPgsize} page_size=${pageSize}`);

    const dbstatTotal = queryScalarInt(Module, db, 'SELECT count(*) FROM dbstat;');
    check('dbstat total row count is within page_count', dbstatTotal > 0 && dbstatTotal <= pageCount,
      `dbstat_total=${dbstatTotal} page_count=${pageCount}`);

    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 10. Value-level encryption (VLE, doc/vle.md): sqlcipher_vle_random/
  //     _kdf/_key/_encrypt/_decrypt/_cipher/_hmac. These are ordinary SQL
  //     functions surfaced through the already-exported sqlite3_exec/
  //     sqlite3_prepare_v2 path, so no new low-level wasm export is needed
  //     for them (see doc/vle-plan.md's "WASM" step) -- unlike section 7's
  //     raw lc_wasm_* calls, everything here goes through SQL text.
  // ---------------------------------------------------------------------
  {
    const { db, rc } = openDb(Module, ':memory:', null);
    check('open :memory: db with no key for VLE tests', rc === SQLITE_OK, `rc=${rc}`);

    const vleKey = hexKey(0x5a, 64);      // a valid 64-byte VLE key
    const vleKey2 = hexKey(0xa5, 64);     // a different valid 64-byte VLE key
    const shortVleKey = hexKey(0x11, 16); // too short (min is 32 bytes)

    const randLen = queryScalarInt(Module, db, 'SELECT length(sqlcipher_vle_random(37));');
    check('sqlcipher_vle_random returns the requested length', randLen === 37, `len=${randLen}`);

    const randDistinct = queryScalarInt(Module, db,
      'SELECT hex(sqlcipher_vle_random(32)) != hex(sqlcipher_vle_random(32));');
    check('sqlcipher_vle_random is non-deterministic', randDistinct === 1, `=${randDistinct}`);

    let st = prepareStep(Module, db, 'SELECT sqlcipher_vle_random(0);');
    check('sqlcipher_vle_random(0) is rejected', st.rc !== SQLITE_ROW, `rc=${st.rc} msg=${st.msg}`);
    if (st.stmt) Module._sqlite3_finalize(st.stmt);

    const kdfDeterministic = queryScalarInt(Module, db,
      "SELECT hex(sqlcipher_vle_kdf(x'0102030405', x'aabbccdd')) = hex(sqlcipher_vle_kdf(x'0102030405', x'aabbccdd'));");
    check('sqlcipher_vle_kdf is deterministic', kdfDeterministic === 1, `=${kdfDeterministic}`);

    const kdfSaltChanges = queryScalarInt(Module, db,
      "SELECT hex(sqlcipher_vle_kdf(x'0102030405', x'aabbccdd')) != hex(sqlcipher_vle_kdf(x'0102030405', x'eeff0011'));");
    check('sqlcipher_vle_kdf output changes with salt', kdfSaltChanges === 1, `=${kdfSaltChanges}`);

    const kdfLen = queryScalarInt(Module, db, "SELECT length(sqlcipher_vle_kdf(x'01', x'02', 16));");
    check('sqlcipher_vle_kdf honors a custom out_sz', kdfLen === 16, `len=${kdfLen}`);

    let krc = exec(Module, db, `SELECT sqlcipher_vle_key(${vleKey});`);
    check('sqlcipher_vle_key accepts a valid 64-byte key', krc === SQLITE_OK, errmsg(Module, db));

    krc = exec(Module, db, `SELECT sqlcipher_vle_key(${shortVleKey});`);
    check('sqlcipher_vle_key rejects an undersized key', krc !== SQLITE_OK, `rc=${krc}`);

    krc = exec(Module, db, `SELECT sqlcipher_vle_key(${vleKey});`);
    check('sqlcipher_vle_key still usable after a rejected key', krc === SQLITE_OK, errmsg(Module, db));

    const intOk = queryScalarInt(Module, db, 'SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt(424242)) = 424242;');
    check('VLE round trip: INTEGER', intOk === 1, `=${intOk}`);

    const floatOk = queryScalarInt(Module, db, 'SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt(3.5)) = 3.5;');
    check('VLE round trip: FLOAT', floatOk === 1, `=${floatOk}`);

    const textOk = queryScalarInt(Module, db,
      "SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('hello wasm')) = 'hello wasm';");
    check('VLE round trip: TEXT', textOk === 1, `=${textOk}`);

    const blobOk = queryScalarInt(Module, db,
      "SELECT hex(sqlcipher_vle_decrypt(sqlcipher_vle_encrypt(x'deadbeef'))) = 'DEADBEEF';");
    check('VLE round trip: BLOB', blobOk === 1, `=${blobOk}`);

    const nullOk = queryScalarText(Module, db,
      'SELECT typeof(sqlcipher_vle_decrypt(sqlcipher_vle_encrypt(NULL)));');
    check('VLE round trip: NULL', nullOk === 'null', `typeof=${nullOk}`);

    const inlineKeyOk = queryScalarInt(Module, db,
      `SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('inline', ${vleKey2}), ${vleKey2}) = 'inline';`);
    check('explicit inline key overrides the connection key', inlineKeyOk === 1, `=${inlineKeyOk}`);

    let wst = prepareStep(Module, db,
      `SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('secret', ${vleKey}), ${vleKey2});`);
    check('VLE decrypt with the wrong key fails', wst.rc !== SQLITE_ROW, `rc=${wst.rc} msg=${wst.msg}`);
    if (wst.stmt) Module._sqlite3_finalize(wst.stmt);

    const ctxOk = queryScalarInt(Module, db,
      "SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('bound', NULL, 'ctxA'), NULL, 'ctxA') = 'bound';");
    check('VLE matching context succeeds', ctxOk === 1, `=${ctxOk}`);

    let cst = prepareStep(Module, db,
      "SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('bound', NULL, 'ctxA'), NULL, 'ctxB');");
    check('VLE mismatched context fails', cst.rc !== SQLITE_ROW, `rc=${cst.rc} msg=${cst.msg}`);
    if (cst.stmt) Module._sqlite3_finalize(cst.stmt);

    let mst = prepareStep(Module, db, "SELECT sqlcipher_vle_decrypt(x'0011223344');");
    check('VLE decrypt of a malformed (too-short) envelope fails', mst.rc !== SQLITE_ROW, `rc=${mst.rc} msg=${mst.msg}`);
    if (mst.stmt) Module._sqlite3_finalize(mst.stmt);

    // tamper detection: flip the last byte of a real envelope (part of its
    // AEAD tag) and confirm decrypt now fails.
    const envHex = queryScalarText(Module, db, "SELECT hex(sqlcipher_vle_encrypt('tamper-me'));");
    const lastByte = parseInt(envHex.slice(-2), 16);
    const tamperedHex = envHex.slice(0, -2) +
      ((lastByte ^ 0xff) & 0xff).toString(16).padStart(2, '0').toUpperCase();
    let tst = prepareStep(Module, db, `SELECT sqlcipher_vle_decrypt(x'${tamperedHex}');`);
    check('VLE decrypt of a tampered envelope fails', tst.rc !== SQLITE_ROW, `rc=${tst.rc} msg=${tst.msg}`);
    if (tst.stmt) Module._sqlite3_finalize(tst.stmt);

    // no key at all: a fresh connection that never called sqlcipher_vle_key()
    const { db: freshDb } = openDb(Module, ':memory:', null);
    let nst = prepareStep(Module, freshDb, "SELECT sqlcipher_vle_encrypt('x');");
    check('VLE encrypt with no key at all fails cleanly', nst.rc !== SQLITE_ROW, `rc=${nst.rc} msg=${nst.msg}`);
    if (nst.stmt) Module._sqlite3_finalize(nst.stmt);
    Module._sqlite3_close(freshDb);

    // low-level sqlcipher_vle_cipher(): no envelope, no type preservation.
    // The WITH clause computes the key/nonce once and reuses them for both
    // the encrypt and decrypt calls.
    // compared via hex(): a BLOB result is never SQL-equal to a TEXT
    // literal regardless of content (SQLite's storage-class ordering), so
    // the comparison itself must happen on TEXT (hex-encoded) values.
    const cipherOk = queryScalarInt(Module, db,
      `WITH k AS (SELECT sqlcipher_vle_random(64) AS key, sqlcipher_vle_random(64) AS nonce)
       SELECT hex(sqlcipher_vle_cipher(0, k.key, k.nonce, NULL,
                sqlcipher_vle_cipher(1, k.key, k.nonce, NULL, 'cipher-data'))) = hex('cipher-data')
       FROM k;`);
    check('sqlcipher_vle_cipher low-level round trip', cipherOk === 1, `=${cipherOk}`);

    let sizeSt = prepareStep(Module, db, "SELECT sqlcipher_vle_cipher(1, x'00', x'00', NULL, 'x');");
    check('sqlcipher_vle_cipher rejects a wrong-sized key/nonce', sizeSt.rc !== SQLITE_ROW, `rc=${sizeSt.rc} msg=${sizeSt.msg}`);
    if (sizeSt.stmt) Module._sqlite3_finalize(sizeSt.stmt);

    const hmacLen = queryScalarInt(Module, db, "SELECT length(sqlcipher_vle_hmac('msg','key'));");
    check('sqlcipher_vle_hmac returns the provider key size (64)', hmacLen === 64, `len=${hmacLen}`);

    const hmacDeterministic = queryScalarInt(Module, db,
      "SELECT hex(sqlcipher_vle_hmac('msg','key')) = hex(sqlcipher_vle_hmac('msg','key'));");
    check('sqlcipher_vle_hmac is deterministic', hmacDeterministic === 1, `=${hmacDeterministic}`);

    const hmacChanges = queryScalarInt(Module, db,
      "SELECT hex(sqlcipher_vle_hmac('msg','key')) != hex(sqlcipher_vle_hmac('msg2','key'));");
    check('sqlcipher_vle_hmac output changes with input', hmacChanges === 1, `=${hmacChanges}`);

    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 10b. VLE works layered inside an already full-database-encrypted
  //      connection (PRAGMA key already set) -- the two encryption layers
  //      are independent (see doc/vle.md).
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/vle-layered.db'); } catch (e) {}
  {
    const { db, rc } = openDb(Module, '/vle-layered.db', validKey);
    check('open full-db-encrypted connection for layered VLE test', rc === SQLITE_OK, `rc=${rc}`);

    const layeredOk = queryScalarInt(Module, db,
      `SELECT sqlcipher_vle_decrypt(sqlcipher_vle_encrypt('layered', ${hexKey(0x33, 48)}), ${hexKey(0x33, 48)}) = 'layered';`);
    check('VLE round trip inside a full-db-encrypted connection', layeredOk === 1, `=${layeredOk}`);

    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 11. Encrypted virtual tables (sqlcipher_vle module, doc/vle.md): a real
  //     sqlite3_module backed by a real "<table>_shadow" table, with
  //     excluded (plaintext) columns and encrypted (BLOB envelope) columns.
  // ---------------------------------------------------------------------
  {
    const { db, rc } = openDb(Module, ':memory:', null);
    check('open :memory: db for encrypted-vtab tests', rc === SQLITE_OK, `rc=${rc}`);

    const vtabKey = hexKey(0x7c, 40);
    let erc = exec(Module, db, `SELECT sqlcipher_vle_key(${vtabKey});`);
    check('set VLE key before creating the encrypted vtab', erc === SQLITE_OK, errmsg(Module, db));

    erc = exec(Module, db,
      `CREATE VIRTUAL TABLE app_secrets USING sqlcipher_vle(
         CREATE TABLE app_secrets(id, name, secret),
         '1,2'
       );`);
    check('create encrypted virtual table (embedded-comma DDL parses)', erc === SQLITE_OK, errmsg(Module, db));

    erc = exec(Module, db, "INSERT INTO app_secrets VALUES (1, 'api-key', 'super-secret-value');");
    check('insert row 1 into encrypted vtab', erc === SQLITE_OK, errmsg(Module, db));
    erc = exec(Module, db, "INSERT INTO app_secrets VALUES (2, 'db-pass', 'another-secret');");
    check('insert row 2 into encrypted vtab', erc === SQLITE_OK, errmsg(Module, db));

    const rows = collectRows(Module, db, 'SELECT id, secret FROM app_secrets ORDER BY id;');
    check('encrypted vtab round-trip row content', JSON.stringify(rows) ===
      JSON.stringify([[1, 'super-secret-value'], [2, 'another-secret']]), JSON.stringify(rows));

    const shadowIsBlob = queryScalarText(Module, db, "SELECT typeof(secret) FROM app_secrets_shadow WHERE id=1;");
    check('shadow table stores the encrypted column as BLOB', shadowIsBlob === 'blob', shadowIsBlob);

    // compared via hex(): a BLOB column is never SQL-equal to a TEXT
    // literal regardless of content, so this must be a byte-level check
    // rather than relying on that storage-class mismatch.
    const shadowNotPlaintext = queryScalarInt(Module, db,
      "SELECT hex(secret) != hex('super-secret-value') FROM app_secrets_shadow WHERE id=1;");
    check('shadow table does not store plaintext bytes', shadowNotPlaintext === 1, `=${shadowNotPlaintext}`);

    const excludedIsPlaintext = queryScalarText(Module, db, "SELECT name FROM app_secrets_shadow WHERE id=1;");
    check('excluded column is stored as plaintext in the shadow table', excludedIsPlaintext === 'api-key', excludedIsPlaintext);

    erc = exec(Module, db, "UPDATE app_secrets SET secret = 'updated-secret' WHERE id = 1;");
    check('update encrypted vtab row', erc === SQLITE_OK, errmsg(Module, db));
    const afterUpdate = queryScalarText(Module, db, "SELECT secret FROM app_secrets WHERE id = 1;");
    check('encrypted vtab row reflects the update', afterUpdate === 'updated-secret', afterUpdate);

    erc = exec(Module, db, 'DELETE FROM app_secrets WHERE id = 2;');
    check('delete encrypted vtab row', erc === SQLITE_OK, errmsg(Module, db));
    const remaining = queryScalarInt(Module, db, 'SELECT count(*) FROM app_secrets;');
    check('encrypted vtab row count after delete', remaining === 1, `count=${remaining}`);

    // cell-splicing protection: copy a live cell's ciphertext into a
    // different row's shadow column and confirm decryption now fails
    // (AAD is bound to table||column||rowid, see doc/vle.md).
    erc = exec(Module, db, "INSERT INTO app_secrets VALUES (3, 'third', 'third-secret');");
    check('insert row 3 for splice test', erc === SQLITE_OK, errmsg(Module, db));
    const ct1Hex = queryScalarText(Module, db, "SELECT hex(secret) FROM app_secrets_shadow WHERE id=1;");
    erc = exec(Module, db, `UPDATE app_secrets_shadow SET secret = x'${ct1Hex}' WHERE id = 3;`);
    check("directly overwrite row 3's shadow cell with row 1's ciphertext", erc === SQLITE_OK, errmsg(Module, db));
    let splst = prepareStep(Module, db, 'SELECT secret FROM app_secrets WHERE id=3;');
    check('spliced shadow cell fails to decrypt', splst.rc !== SQLITE_ROW, `rc=${splst.rc} msg=${splst.msg}`);
    if (splst.stmt) Module._sqlite3_finalize(splst.stmt);

    Module._sqlite3_close(db);
  }

  // ---------------------------------------------------------------------
  // 11b. Querying/inserting an encrypted vtab before a key is set fails
  //      cleanly, both on a fresh table and on a reopened connection over
  //      an already-populated one.
  // ---------------------------------------------------------------------
  try { Module.FS.unlink('/vtab-nokey.db'); } catch (e) {}
  {
    const { db } = openDb(Module, '/vtab-nokey.db', null);
    let nst = prepareStep(Module, db,
      "CREATE VIRTUAL TABLE t USING sqlcipher_vle(CREATE TABLE t(a, b), '');");
    check('create encrypted vtab without a key', nst.rc === SQLITE_DONE || nst.rc === SQLITE_OK, `rc=${nst.rc} msg=${nst.msg}`);
    if (nst.stmt) Module._sqlite3_finalize(nst.stmt);

    let ist = prepareStep(Module, db, 'INSERT INTO t VALUES (1,2);');
    check('insert into encrypted vtab without a key fails cleanly', ist.rc !== SQLITE_DONE, `rc=${ist.rc} msg=${ist.msg}`);
    if (ist.stmt) Module._sqlite3_finalize(ist.stmt);

    exec(Module, db, `SELECT sqlcipher_vle_key(${hexKey(0x21, 32)});`);
    let ist2 = prepareStep(Module, db, 'INSERT INTO t VALUES (1,2);');
    check('insert succeeds once a key is set', ist2.rc === SQLITE_DONE, `rc=${ist2.rc} msg=${ist2.msg}`);
    if (ist2.stmt) Module._sqlite3_finalize(ist2.stmt);

    Module._sqlite3_close(db);
  }
  {
    // reopen the same file on a fresh connection that never calls
    // sqlcipher_vle_key(): querying existing encrypted rows must fail.
    const { db } = openDb(Module, '/vtab-nokey.db', null);
    exec(Module, db, "SELECT sqlcipher_vle_random(1);"); // touch the connection, no key set
    let qst = prepareStep(Module, db, 'SELECT a,b FROM t;');
    check('query on a reopened connection with no key fails cleanly', qst.rc !== SQLITE_ROW, `rc=${qst.rc} msg=${qst.msg}`);
    if (qst.stmt) Module._sqlite3_finalize(qst.stmt);
    Module._sqlite3_close(db);
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
