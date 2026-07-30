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
** Glue for registering a real, C-struct sqlite3_vfs whose xOpen/xRead/
** xWrite/... method bodies actually live in JS (see wasm/js-vfs.mjs).
**
** The JS side turns each method into a real, indirectly-callable function
** pointer via Emscripten's Module.addFunction() (which requires this
** build's `-s ALLOW_TABLE_GROWTH=1`, see tool/build-wasm.sh, since the
** function table has no free/reserved slots for late additions
** otherwise) and passes those pointers here, packed as a flat array of
** ints, to be written into a real sqlite3_vfs/sqlite3_io_methods pair.
** From that point on SQLite's core C code calls these exactly like any
** other VFS's methods -- it has no idea the callee is a JS trampoline.
**
** This deliberately does not redeclare the sqlite3_vfs/sqlite3_io_methods
** field layouts by hand in JS/memory-offset terms; the array is unpacked
** by *this* file via ordinary C struct-field assignment against the
** struct definitions in sqlite3.h, so there is no risk of the layout
** drifting out of sync with whatever amalgamation this is linked against.
**
** Only VFS/io_methods version 1 is implemented (no WAL shared-memory
** methods, no xFetch/xUnfetch mmap methods) -- sufficient for rollback-
** journal mode, which is all this JS-backed VFS supports.
*/
#include "sqlite3.h"
#include <string.h>
#include <emscripten.h>

/* Index of each JS-supplied function pointer within the flat array passed
** to sqlite3_js_vfs_register() -- must match the order wasm/js-vfs.mjs
** builds its array in. */
enum {
  JSVFS_XOPEN = 0,
  JSVFS_XDELETE,
  JSVFS_XACCESS,
  JSVFS_XFULLPATHNAME,
  JSVFS_XRANDOMNESS,
  JSVFS_XSLEEP,
  JSVFS_XCURRENTTIME,
  JSVFS_XGETLASTERROR,
  JSVFS_XCLOSE,
  JSVFS_XREAD,
  JSVFS_XWRITE,
  JSVFS_XTRUNCATE,
  JSVFS_XSYNC,
  JSVFS_XFILESIZE,
  JSVFS_XLOCK,
  JSVFS_XUNLOCK,
  JSVFS_XCHECKRESERVEDLOCK,
  JSVFS_XFILECONTROL,
  JSVFS_XSECTORSIZE,
  JSVFS_XDEVICECHARACTERISTICS,
  JSVFS_NPTRS
};

/* A single JS-backed VFS instance per module -- this build only ever
** registers one (see wasm/js-vfs.mjs); a real multi-instance API would
** need one of these per registration, which isn't needed here. */
static sqlite3_io_methods js_vfs_io_methods;
static sqlite3_vfs js_vfs;
static char js_vfs_name[64];

EMSCRIPTEN_KEEPALIVE
int sqlite3_js_vfs_register(
  const char *zName,
  int szOsFile,
  int mxPathname,
  int makeDefault,
  const int *ptrs /* JSVFS_NPTRS-element array, see enum above */
) {
  if (zName == 0 || ptrs == 0) return SQLITE_MISUSE;

  memset(&js_vfs_io_methods, 0, sizeof(js_vfs_io_methods));
  js_vfs_io_methods.iVersion = 1;
  js_vfs_io_methods.xClose =
    (int(*)(sqlite3_file*))ptrs[JSVFS_XCLOSE];
  js_vfs_io_methods.xRead =
    (int(*)(sqlite3_file*,void*,int,sqlite3_int64))ptrs[JSVFS_XREAD];
  js_vfs_io_methods.xWrite =
    (int(*)(sqlite3_file*,const void*,int,sqlite3_int64))ptrs[JSVFS_XWRITE];
  js_vfs_io_methods.xTruncate =
    (int(*)(sqlite3_file*,sqlite3_int64))ptrs[JSVFS_XTRUNCATE];
  js_vfs_io_methods.xSync =
    (int(*)(sqlite3_file*,int))ptrs[JSVFS_XSYNC];
  js_vfs_io_methods.xFileSize =
    (int(*)(sqlite3_file*,sqlite3_int64*))ptrs[JSVFS_XFILESIZE];
  js_vfs_io_methods.xLock =
    (int(*)(sqlite3_file*,int))ptrs[JSVFS_XLOCK];
  js_vfs_io_methods.xUnlock =
    (int(*)(sqlite3_file*,int))ptrs[JSVFS_XUNLOCK];
  js_vfs_io_methods.xCheckReservedLock =
    (int(*)(sqlite3_file*,int*))ptrs[JSVFS_XCHECKRESERVEDLOCK];
  js_vfs_io_methods.xFileControl =
    (int(*)(sqlite3_file*,int,void*))ptrs[JSVFS_XFILECONTROL];
  js_vfs_io_methods.xSectorSize =
    (int(*)(sqlite3_file*))ptrs[JSVFS_XSECTORSIZE];
  js_vfs_io_methods.xDeviceCharacteristics =
    (int(*)(sqlite3_file*))ptrs[JSVFS_XDEVICECHARACTERISTICS];

  memset(&js_vfs_name, 0, sizeof(js_vfs_name));
  strncpy(js_vfs_name, zName, sizeof(js_vfs_name) - 1);

  memset(&js_vfs, 0, sizeof(js_vfs));
  js_vfs.iVersion = 1;
  js_vfs.szOsFile = szOsFile;
  js_vfs.mxPathname = mxPathname;
  js_vfs.zName = js_vfs_name;
  js_vfs.xOpen =
    (int(*)(sqlite3_vfs*,sqlite3_filename,sqlite3_file*,int,int*))ptrs[JSVFS_XOPEN];
  js_vfs.xDelete =
    (int(*)(sqlite3_vfs*,const char*,int))ptrs[JSVFS_XDELETE];
  js_vfs.xAccess =
    (int(*)(sqlite3_vfs*,const char*,int,int*))ptrs[JSVFS_XACCESS];
  js_vfs.xFullPathname =
    (int(*)(sqlite3_vfs*,const char*,int,char*))ptrs[JSVFS_XFULLPATHNAME];
  js_vfs.xRandomness =
    (int(*)(sqlite3_vfs*,int,char*))ptrs[JSVFS_XRANDOMNESS];
  js_vfs.xSleep =
    (int(*)(sqlite3_vfs*,int))ptrs[JSVFS_XSLEEP];
  js_vfs.xCurrentTime =
    (int(*)(sqlite3_vfs*,double*))ptrs[JSVFS_XCURRENTTIME];
  js_vfs.xGetLastError =
    (int(*)(sqlite3_vfs*,int,char*))ptrs[JSVFS_XGETLASTERROR];

  return sqlite3_vfs_register(&js_vfs, makeDefault);
}

/* So the JS xOpen implementation can set (sqlite3_file*)->pMethods (the
** first field of whatever szOsFile-byte struct SQLite allocated for it)
** to this shared vtable, the same way every C VFS implementation does. */
EMSCRIPTEN_KEEPALIVE
const sqlite3_io_methods *sqlite3_js_vfs_io_methods(void) {
  return &js_vfs_io_methods;
}

EMSCRIPTEN_KEEPALIVE
int sqlite3_js_vfs_unregister(void) {
  return sqlite3_vfs_unregister(&js_vfs);
}
