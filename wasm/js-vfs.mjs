// JS-backed sqlite3_vfs for wasm/sqlcipher.js (see wasm/README.md's
// "JS-backed sqlite3_vfs" section and wasm/js_vfs.c).
//
// Registers a full sqlite3_vfs whose xOpen/xRead/xWrite/... methods are
// plain JS functions, turned into real, indirectly-callable WASM function
// pointers via Module.addFunction() (requires the build's
// `-s ALLOW_TABLE_GROWTH=1`), and wired into an actual C sqlite3_vfs
// struct by wasm/js_vfs.c's sqlite3_js_vfs_register(). SQLite's core C
// code calls these exactly like it would any native VFS's methods.
//
// Storage backend: a plain in-memory JS Map from filename to a growable
// Uint8Array -- this proves out the VFS-in-JS mechanism end to end, but
// (like the module's default MEMFS-backed behavior) is not actually
// persistent beyond the lifetime of the returned store object. A real
// persistence layer (IndexedDB/OPFS in a browser, fs in Node) can be
// swapped in later by reimplementing this same set of method functions
// against that backend instead of `files`.
//
// Only sqlite3_vfs/sqlite3_io_methods version 1 is implemented (no WAL
// shared-memory methods) -- this VFS only supports rollback-journal mode.
// `PRAGMA journal_mode=WAL` will fail against it.

const SQLITE_OK = 0;
const SQLITE_IOERR_SHORT_READ = 522; // 10 | (2 << 8)
const SQLITE_NOTFOUND = 12;

const SQLITE_OPEN_DELETEONCLOSE = 0x00000008;

const SQLITE_ACCESS_EXISTS = 0;

/**
 * @param {object} Module - an instantiated Sqlite3Wasm() module.
 * @param {object} [opts]
 * @param {string} [opts.name='jsvfs'] - name this VFS is registered under;
 *   pass to sqlite3_open_v2()'s zVfs argument to select it.
 * @param {boolean} [opts.makeDefault=false] - if true, register as the
 *   process-wide default VFS (used when zVfs is NULL/0).
 * @returns {{name: string, files: Map<string, Uint8Array>}} the backing
 *   store (inspectable/clearable by the caller) and the registered name.
 */
export function registerJsVfs(Module, opts = {}) {
  const name = opts.name || 'jsvfs';
  const makeDefault = !!opts.makeDefault;

  /** @type {Map<string, {bytes: Uint8Array}>} */
  const files = new Map();
  /** @type {Map<number, {name: string, deleteOnClose: boolean}>} */
  const openFiles = new Map();
  let tempCounter = 0;
  // Assigned below, after registration -- a fixed static-struct address, so
  // it's safe for xOpen() (only invoked later, once files are opened) to
  // close over this binding ahead of the assignment.
  let ioMethodsPtr = 0;

  function fileEntry(name) {
    let entry = files.get(name);
    if (!entry) {
      entry = { bytes: new Uint8Array(0) };
      files.set(name, entry);
    }
    return entry;
  }

  function resize(entry, newLen) {
    if (newLen === entry.bytes.length) return;
    const next = new Uint8Array(newLen); // zero-filled by construction
    next.set(entry.bytes.subarray(0, Math.min(entry.bytes.length, newLen)));
    entry.bytes = next;
  }

  // --- sqlite3_io_methods (per-open-file) ----------------------------------

  function xClose(pFile) {
    const of = openFiles.get(pFile);
    if (of) {
      if (of.deleteOnClose) files.delete(of.name);
      openFiles.delete(pFile);
    }
    return SQLITE_OK;
  }

  function xRead(pFile, pBuf, iAmt, iOfstBig) {
    const of = openFiles.get(pFile);
    const entry = fileEntry(of.name);
    const iOfst = Number(iOfstBig);
    const avail = entry.bytes.length - iOfst;
    if (avail <= 0) {
      Module.HEAPU8.fill(0, pBuf, pBuf + iAmt);
      return SQLITE_IOERR_SHORT_READ;
    }
    const n = Math.min(avail, iAmt);
    Module.HEAPU8.set(entry.bytes.subarray(iOfst, iOfst + n), pBuf);
    if (n < iAmt) {
      Module.HEAPU8.fill(0, pBuf + n, pBuf + iAmt);
      return SQLITE_IOERR_SHORT_READ;
    }
    return SQLITE_OK;
  }

  function xWrite(pFile, pBuf, iAmt, iOfstBig) {
    const of = openFiles.get(pFile);
    const entry = fileEntry(of.name);
    const iOfst = Number(iOfstBig);
    if (iOfst + iAmt > entry.bytes.length) resize(entry, iOfst + iAmt);
    entry.bytes.set(Module.HEAPU8.subarray(pBuf, pBuf + iAmt), iOfst);
    return SQLITE_OK;
  }

  function xTruncate(pFile, sizeBig) {
    const of = openFiles.get(pFile);
    const entry = fileEntry(of.name);
    resize(entry, Number(sizeBig));
    return SQLITE_OK;
  }

  function xSync(_pFile, _flags) {
    return SQLITE_OK; // already "durable" -- it's a JS heap object
  }

  function xFileSize(pFile, pSize) {
    const of = openFiles.get(pFile);
    const entry = fileEntry(of.name);
    const len = entry.bytes.length;
    Module.HEAP32[pSize >> 2] = len >>> 0; // low 32 bits
    Module.HEAP32[(pSize >> 2) + 1] = 0;   // high 32 bits (len always small here)
    return SQLITE_OK;
  }

  function xLock(_pFile, _eLock) { return SQLITE_OK; }
  function xUnlock(_pFile, _eLock) { return SQLITE_OK; }
  function xCheckReservedLock(_pFile, pResOut) {
    Module.HEAP32[pResOut >> 2] = 0;
    return SQLITE_OK;
  }
  function xFileControl(_pFile, _op, _pArg) { return SQLITE_NOTFOUND; }
  function xSectorSize(_pFile) { return 4096; }
  function xDeviceCharacteristics(_pFile) { return 0; }

  // --- sqlite3_vfs (global) -------------------------------------------------

  function xOpen(_pVfs, zName, pFile, flags, pOutFlags) {
    const fname = zName ? Module.UTF8ToString(zName) : `:jsvfs-temp-${tempCounter++}:`;
    fileEntry(fname); // ensure it exists, even if empty
    Module.HEAP32[pFile >> 2] = ioMethodsPtr; // pFile->pMethods
    openFiles.set(pFile, {
      name: fname,
      deleteOnClose: !!(flags & SQLITE_OPEN_DELETEONCLOSE),
    });
    if (pOutFlags) Module.HEAP32[pOutFlags >> 2] = flags;
    return SQLITE_OK;
  }

  function xDelete(_pVfs, zName, _syncDir) {
    files.delete(Module.UTF8ToString(zName));
    return SQLITE_OK;
  }

  function xAccess(_pVfs, zName, flags, pResOut) {
    const exists = files.has(Module.UTF8ToString(zName));
    Module.HEAP32[pResOut >> 2] = (flags === SQLITE_ACCESS_EXISTS) ? (exists ? 1 : 0) : 1;
    return SQLITE_OK;
  }

  function xFullPathname(_pVfs, zName, nOut, zOut) {
    Module.stringToUTF8(Module.UTF8ToString(zName), zOut, nOut);
    return SQLITE_OK;
  }

  function xRandomness(_pVfs, nByte, zOut) {
    const bytes = new Uint8Array(nByte);
    for (let off = 0; off < nByte; ) {
      const chunk = bytes.subarray(off, Math.min(off + 65536, nByte));
      globalThis.crypto.getRandomValues(chunk);
      off += chunk.length;
    }
    Module.HEAPU8.set(bytes, zOut);
    return nByte;
  }

  function xSleep(_pVfs, microseconds) {
    return microseconds; // no real sleep -- this VFS is fully synchronous
  }

  function xCurrentTime(_pVfs, pTimeOut) {
    const julianDay = 2440587.5 + Date.now() / 86400000;
    Module.HEAPF64[pTimeOut >> 3] = julianDay;
    return SQLITE_OK;
  }

  function xGetLastError(_pVfs, nBuf, zBuf) {
    if (nBuf > 0) Module.HEAPU8[zBuf] = 0;
    return SQLITE_OK;
  }

  // --- wire it all up --------------------------------------------------------

  const methodPtrs = [
    Module.addFunction(xOpen, 'iiiiii'),
    Module.addFunction(xDelete, 'iiii'),
    Module.addFunction(xAccess, 'iiiii'),
    Module.addFunction(xFullPathname, 'iiiii'),
    Module.addFunction(xRandomness, 'iiii'),
    Module.addFunction(xSleep, 'iii'),
    Module.addFunction(xCurrentTime, 'iii'),
    Module.addFunction(xGetLastError, 'iiii'),
    Module.addFunction(xClose, 'ii'),
    Module.addFunction(xRead, 'iiiij'),
    Module.addFunction(xWrite, 'iiiij'),
    Module.addFunction(xTruncate, 'iij'),
    Module.addFunction(xSync, 'iii'),
    Module.addFunction(xFileSize, 'iii'),
    Module.addFunction(xLock, 'iii'),
    Module.addFunction(xUnlock, 'iii'),
    Module.addFunction(xCheckReservedLock, 'iii'),
    Module.addFunction(xFileControl, 'iiii'),
    Module.addFunction(xSectorSize, 'ii'),
    Module.addFunction(xDeviceCharacteristics, 'ii'),
  ];

  const ptrBuf = Module._malloc(methodPtrs.length * 4);
  Module.HEAP32.set(methodPtrs, ptrBuf >> 2);

  const nameLen = Module.lengthBytesUTF8(name);
  const namePtr = Module._malloc(nameLen + 1);
  Module.stringToUTF8(name, namePtr, nameLen + 1);

  // szOsFile: only pMethods (one pointer) of per-file state lives in WASM
  // memory -- everything else is tracked JS-side in `openFiles`, keyed by
  // the pFile pointer address itself.
  const szOsFile = 4;
  const mxPathname = 512;

  const rc = Module._sqlite3_js_vfs_register(namePtr, szOsFile, mxPathname, makeDefault ? 1 : 0, ptrBuf);

  Module._free(namePtr);
  Module._free(ptrBuf);

  if (rc !== SQLITE_OK) {
    throw new Error(`sqlite3_js_vfs_register('${name}') failed: rc=${rc}`);
  }

  ioMethodsPtr = Module._sqlite3_js_vfs_io_methods();

  return { name, files };
}
