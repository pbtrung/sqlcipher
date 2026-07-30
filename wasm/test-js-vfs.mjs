// Verification for the JS-backed sqlite3_vfs (wasm/js-vfs.mjs +
// wasm/js_vfs.c), run under Node.js. See wasm/README.md's "JS-backed
// sqlite3_vfs" section.
//
// Usage: node wasm/test-js-vfs.mjs

import Sqlite3Wasm from './sqlcipher.js';
import { registerJsVfs } from './js-vfs.mjs';

const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_OPEN_READWRITE = 0x00000002;
const SQLITE_OPEN_CREATE = 0x00000004;

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

function openV2(Module, filename, vfsName, keyStr) {
  const ppDb = Module._malloc(4);
  const { ptr: fnPtr } = cString(Module, filename);
  const { ptr: vfsPtr } = vfsName ? cString(Module, vfsName) : { ptr: 0 };
  const rc = Module._sqlite3_open_v2(
    fnPtr, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, vfsPtr);
  const db = Module.getValue(ppDb, 'i32');
  Module._free(ppDb);
  Module._free(fnPtr);
  if (vfsPtr) Module._free(vfsPtr);
  if (rc !== SQLITE_OK) return { db, rc };
  if (keyStr !== undefined) {
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

function bytesToString(bytes) {
  return Buffer.from(bytes).toString('latin1');
}

async function main() {
  const Module = await Sqlite3Wasm();
  const { name: vfsName, files } = registerJsVfs(Module, { name: 'jsvfs' });
  check('jsvfs registered under requested name', vfsName === 'jsvfs', vfsName);

  // -------------------------------------------------------------------
  // 1. Plain (unencrypted) round trip entirely through the JS-backed VFS
  // -------------------------------------------------------------------
  {
    const { db, rc } = openV2(Module, '/vfs-test.db', vfsName);
    check('open db via jsvfs', rc === SQLITE_OK, `rc=${rc}`);

    let erc = exec(Module, db, 'CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT);');
    check('create table via jsvfs', erc === SQLITE_OK, errmsg(Module, db));

    erc = exec(Module, db,
      "INSERT INTO t(a,b) VALUES (1,'row one'),(2,'row two'),(3,'row three');");
    check('insert rows via jsvfs', erc === SQLITE_OK, errmsg(Module, db));

    Module._sqlite3_close(db);

    const entry = files.get('/vfs-test.db');
    check('jsvfs store received bytes for the main db file',
      !!entry && entry.bytes.length > 0, entry && entry.bytes.length);
    check('jsvfs store has no leftover rollback journal after commit',
      !files.has('/vfs-test.db-journal'));
  }

  {
    const { db, rc } = openV2(Module, '/vfs-test.db', vfsName);
    check('reopen db via jsvfs', rc === SQLITE_OK, `rc=${rc}`);

    const rows = collectRows(Module, db, 'SELECT a,b FROM t ORDER BY a;');
    check('jsvfs round-trip row content', JSON.stringify(rows) ===
      JSON.stringify([[1, 'row one'], [2, 'row two'], [3, 'row three']]),
      JSON.stringify(rows));

    Module._sqlite3_close(db);
  }

  // -------------------------------------------------------------------
  // 2. SQLCipher's codec layered on top of the JS-backed VFS
  // -------------------------------------------------------------------
  {
    const key = "x'" + '5a'.repeat(256) + "'";
    const { db, rc } = openV2(Module, '/vfs-test-enc.db', vfsName, key);
    check('open encrypted db via jsvfs', rc === SQLITE_OK, `rc=${rc}`);

    let erc = exec(Module, db, 'CREATE TABLE secret(v TEXT);');
    check('create table (encrypted, jsvfs)', erc === SQLITE_OK, errmsg(Module, db));

    erc = exec(Module, db, "INSERT INTO secret(v) VALUES ('super-secret-value');");
    check('insert row (encrypted, jsvfs)', erc === SQLITE_OK, errmsg(Module, db));

    Module._sqlite3_close(db);

    const entry = files.get('/vfs-test-enc.db');
    const raw = bytesToString(entry.bytes);
    check('encrypted jsvfs-backed file does not contain plaintext',
      !raw.includes('super-secret-value'));
  }

  {
    const key = "x'" + '5a'.repeat(256) + "'";
    const { db, rc } = openV2(Module, '/vfs-test-enc.db', vfsName, key);
    check('reopen encrypted db via jsvfs with same key', rc === SQLITE_OK, `rc=${rc}`);

    const ppStmt = Module._malloc(4);
    const { ptr } = cString(Module, 'SELECT v FROM secret;');
    Module._sqlite3_prepare_v2(db, ptr, -1, ppStmt, 0);
    Module._free(ptr);
    const stmt = Module.getValue(ppStmt, 'i32');
    Module._free(ppStmt);
    let value = null;
    if (Module._sqlite3_step(stmt) === SQLITE_ROW) {
      value = Module.UTF8ToString(Module._sqlite3_column_text(stmt, 0));
    }
    Module._sqlite3_finalize(stmt);
    check('decrypted row content matches after jsvfs reopen',
      value === 'super-secret-value', value);

    Module._sqlite3_close(db);
  }

  // -------------------------------------------------------------------
  // 3. Registering jsvfs (non-default) must not disturb the default VFS
  // -------------------------------------------------------------------
  {
    const ppDb = Module._malloc(4);
    const { ptr: fnPtr } = cString(Module, '/default-vfs-still-works.db');
    const rc = Module._sqlite3_open(fnPtr, ppDb);
    const db = Module.getValue(ppDb, 'i32');
    Module._free(ppDb);
    Module._free(fnPtr);
    check('default (MEMFS) vfs still works after jsvfs registration',
      rc === SQLITE_OK, `rc=${rc}`);
    const erc = exec(Module, db, 'CREATE TABLE x(a);');
    check('default vfs still functional (create table)', erc === SQLITE_OK, errmsg(Module, db));
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
