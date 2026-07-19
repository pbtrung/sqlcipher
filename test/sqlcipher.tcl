# codec.test developed by Stephen Lombardo (Zetetic LLC) 
# sjlombardo at zetetic dot net
# http://zetetic.net
# 
# Copyright (c) 2018, ZETETIC LLC
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the ZETETIC LLC nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This file implements regression tests for SQLite library.  The
# focus of this script is testing code cipher features.
#
# NOTE: tester.tcl has overridden the definition of sqlite3 to 
# automatically pass in a key value. Thus tests in this file
# should explicitly close and open db with sqlite_orig in order
# to bypass default key assignment.


set testdir [file dirname $argv0]
set sampleDir [file normalize [file dirname [file dirname $argv0]]]/sqlcipher-resources

catch {file delete -force test.db}
file delete -force test2.db
file delete -force test3.db
file delete -force test4.db

# If the library is not compiled with has_codec support then
# skip all tests in this file.
if {![sqlite_orig -has-codec]} {
  finish_test
  return
}

# NOTE: sqlcipher_test_key / sqlcipher_test_key_hex / sqlcipher_short_key are
# defined in tester.tcl (sourced above this file by every sqlcipher-*.test
# file) and are the single source of truth for the raw, >=256-byte "x'<hex>'"
# keys required by the leancrypto-based codec (see doc/crypto.md). "key" here
# is expected to already be a full, quoted PRAGMA key value expression, e.g.
# [sqlcipher_test_key] or "x'...'" written out literally.
proc setup {file key} {
  sqlite_orig db $file
  execsql "PRAGMA key=$key;"
  execsql {
    CREATE table t1(a,b);
    INSERT INTO t1 VALUES ('test1', 'test2');
  } db
  db close
}

proc get_cipher_provider {} {
   sqlite_orig db test.db
   execsql "PRAGMA key = \"[sqlcipher_test_key]\";"
   return [execsql {
     PRAGMA cipher_provider;
   }];
}

# There is exactly one cipher provider now (leancrypto, see doc/crypto.md) --
# the historic openssl/libtomcrypt/commoncrypto/nss providers and their
# if_built_with_* guards no longer exist. if_built_with_leancrypto is kept as
# the (currently redundant, since it's the only provider that can be built)
# analogous guard so provider-specific tests read the same way they always
# have and so a future second provider could reuse the pattern.
proc if_built_with_leancrypto {name cmd expected} {
    if {[get_cipher_provider] == "leancrypto"} {
        do_test $name $cmd $expected
    }
}

proc cmpFilesChunked {file1 file2 {chunksize 16384}} {
    set f1 [open $file1]; fconfigure $f1 -translation binary
    set f2 [open $file2]; fconfigure $f2 -translation binary
    while {1} {
        set d1 [read $f1 $chunksize]
        set d2 [read $f2 $chunksize]
        set diff [string compare $d1 $d2]
        if {$diff != 0 || [eof $f1] || [eof $f2]} {
            close $f1; close $f2
            return $diff
        }
    }
    return 0
}

proc trace_proc sql {
  global TRACE_OUT
  lappend TRACE_OUT [string trim $sql]
}

