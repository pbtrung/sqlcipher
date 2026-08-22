# Page manifest: query front-running for page-by-page HTTP storage

## Status

Design document only — **nothing in this file is implemented yet**. Written
before any code, matching this project's convention (see `doc/crypto.md`,
`doc/vle.md`) of recording the design first. There is no
`src/sqlcipher_page_manifest.c`, no new PRAGMA, no schema, no wasm/JS
changes yet. This document exists so the design can be reviewed before any
of that is written.

## Problem

Target deployment shape: a SQLite/SQLCipher database file lives on a plain
HTTP origin that supports byte-range requests (a static file host, object
storage, a dumb file server — no SQLite-aware backend required), and a
browser client (this project's WASM build) wants to run read queries
against it **without downloading the whole file**, fetching only the pages
a given query actually needs.

The pager already does this on demand — a JS-backed `sqlite3_vfs`
(`wasm/js-vfs.mjs`) can serve `xRead` with an HTTP Range request for exactly
the bytes SQLite asks for. The problem is *latency*, not correctness: a
b-tree lookup walks root → interior → interior → leaf, and each level's
page number is only known after decoding the *previous* level's page. Over
a real network, that's one round trip per tree level, serialized, for every
lookup — slow, even though the total number of bytes fetched is tiny.

**Goal:** let the client learn, before running a query, as much of the page
set it will need as it can from information already sitting in cache, then
fetch all of those pages **in parallel** (or from one consolidated request)
before stepping the actual statement — "front-running" the query's own page
requests instead of following the pager's naturally sequential ones.

## Approach: a sparse fence-pointer manifest

For each b-tree of interest (a table's rowid/`INTEGER PRIMARY KEY` tree, or
a secondary index), maintain one manifest row **per leaf page**:

```
(index_name, leaf_pgno, min_key, max_key)
```

`min_key`/`max_key` are the smallest and largest key present on that leaf
page. This is exactly the boundary-key information that already lives
inside that index's *interior* pages — the same information a client would
otherwise only learn one HTTP round trip at a time while walking down the
tree — flattened into one small, directly queryable table instead.

Given a query's constraint on an indexed column (e.g.
`WHERE id BETWEEN X AND Y`), the client can compute the *exact* set of
candidate leaf pages with a single **local** lookup against the (small,
already-fetched) manifest:

```sql
SELECT leaf_pgno FROM sqlcipher_page_manifest
WHERE index_name = ?1 AND NOT (max_key < ?2 OR min_key > ?3);
```

Root pages and the handful of interior pages above the leaf level are cheap
to always keep warm (there are `O(log n)` of them per index, typically
single digits) — fetch them eagerly on open and never worry about them
again until the manifest itself goes stale.

The manifest lives **inside the database** as an ordinary table, so it
inherits whatever encryption is already active (the full-database codec
and/or per-value VLE, see `doc/crypto.md`/`doc/vle.md`) automatically, and
travels with the database file with no separate side channel.

### Why not just a full page inventory?

`dbstat` (`SQLITE_ENABLE_DBSTAT_VTAB`, already enabled in this build) can
already report every page belonging to a table/index. That's not what this
feature is missing — a bare page *set*, with no key-range information
attached, only helps a full scan. It can't answer "which pages does
`WHERE id = 12345` need," because it has thrown away exactly the ordering
information that would answer that. The manifest keeps that information.

## Schema

```sql
CREATE TABLE IF NOT EXISTS sqlcipher_page_manifest(
  index_name TEXT    NOT NULL,  -- table or index name this leaf page belongs to
  leaf_pgno  INTEGER NOT NULL,  -- page number of this leaf
  min_key    BLOB,              -- serialized lower-bound key on this page (NULL = unbounded, e.g. first page)
  max_key    BLOB,              -- serialized upper-bound key on this page (NULL = unbounded, e.g. last page)
  PRIMARY KEY(index_name, leaf_pgno)
);

CREATE TABLE IF NOT EXISTS sqlcipher_page_manifest_meta(
  index_name   TEXT    PRIMARY KEY,
  data_version INTEGER NOT NULL,  -- PRAGMA data_version this index's manifest rows were built from
  built_at     INTEGER NOT NULL   -- unix timestamp, diagnostics only
);
```

Key serialization mirrors VLE's value-envelope convention (`doc/vle.md`):
`INTEGER` as 8-byte big-endian, `TEXT`/`BLOB` as raw bytes. Range comparison
in the manifest lookup above is then a plain byte-wise `BLOB` comparison,
which matches SQLite's default `BINARY` collation exactly. **This is a
known limitation, not an oversight**: an index on a column using `NOCASE`
or a custom collation would need key encoding that preserves that
collation's ordering, or must be excluded from manifest coverage — see
"Known limitations" below.

## Rebuild: keeping the manifest in sync (the "write" side)

The manifest is **not** maintained incrementally on every write. Hooking
`INSERT`/`UPDATE`/`DELETE` to patch manifest rows on every b-tree mutation
would mean re-implementing SQLite's own page-split/merge/freelist
bookkeeping at the SQL layer, on the hot path of every write, and would
break silently under autovacuum, `VACUUM`, and WAL checkpointing reshuffling
pages independently of any such hook. Given this is purely a read-side
latency optimization for one specific deployment shape, that cost isn't
justified.

Instead, rebuild is **lazy**, gated on `PRAGMA data_version`:

1. Compare `sqlcipher_page_manifest_meta.data_version` for an index against
   the connection's current `PRAGMA data_version`. Equal → the manifest is
   trustworthy, do nothing.
2. If stale, rebuild that index's manifest rows:
   - Walk the index's b-tree pages directly (the same low-level page-walk
     `ext/misc`'s `dbstat.c` already performs — this needs C-level access
     to btree internals, not a pure-SQL reconstruction, since ordinary SQL
     results don't expose "which page is this row's cell physically on").
     For each leaf page visited, record its lowest and highest key.
   - Replace that index's rows in `sqlcipher_page_manifest` and stamp the
     new `data_version` in `sqlcipher_page_manifest_meta`, in one
     transaction.
3. Cost is `O(number of leaf pages)` I/O — the same as one full index scan
   — but it is paid once per burst of writes since the last rebuild, not
   once per query.

**Where rebuild runs matters.** The target deployment is: a writable
canonical copy of the database lives somewhere with normal disk access (a
server process, a build step, a sync job); the browser client is a
**read-only** remote consumer fetching pages over HTTP. Rebuild happens
wherever the writes happen, immediately before republishing the updated
`.db` file (or serving updated page ranges) to clients — not in the
browser. A client that only ever reads over HTTP never has enough
information to rebuild an authoritative manifest itself; it can only detect
that its cached manifest is stale (see below) and fall back to normal
on-demand fetching for that query.

Manual/explicit rebuild is a new SQL function,
`sqlcipher_page_manifest_rebuild(index_name)` (or with no argument, every
index) — callable wherever writes happen, e.g. right before a commit that's
about to be published, or on a cron/CI step that republishes a static `.db`
snapshot.

## Read flow in the browser (WASM client)

1. **Transport.** No SQLite-aware backend is required: the simplest option
   is plain HTTP Range requests against the `.db` file's own bytes, page
   `pgno` living at byte offset `(pgno-1) * page_size`, length `page_size`
   — any static host that honors `Range` (S3, GitHub Pages, nginx) works.
   This becomes a new VFS backend for `wasm/js-vfs.mjs` (today it only has
   an in-memory `Map` backend — see `wasm/README.md`'s "Storage backend"
   section, which already calls out swapping in a different backend as the
   intended extension point): `xRead` issues
   `fetch(url, {headers: {Range: 'bytes=X-Y'}})` instead of reading from the
   `Map`; `xWrite`/`xTruncate`/`xSync` are no-ops or return an error (this
   VFS is read-only — see "Known limitations"); fetched pages are cached
   (in memory for a session, or `IndexedDB`/the `Cache API` for
   persistence across page loads).
2. **Open.** The client always eagerly fetches page 1 (header +
   `sqlite_schema`) and, from it, the root pages of
   `sqlcipher_page_manifest`/`_meta` (their `rootpage` values are right
   there in `sqlite_schema`, decoded from the page 1 fetch already made).
3. **Warm the manifest.** The client runs a normal query
   (`SELECT * FROM sqlcipher_page_manifest`) once per session (or once per
   detected `data_version` change) to pull the whole manifest into the
   local page cache — manifest tables are small, so this is a handful of
   page fetches regardless of how large the real tables are.
4. **Staleness check.** Compare `PRAGMA data_version` (from the page 1
   fetch already in hand) against the value(s) stamped in
   `sqlcipher_page_manifest_meta`. If the live `data_version` is newer than
   what the manifest was built from, the manifest is stale for that index:
   the client either falls back to plain on-demand fetching for queries
   against it (still correct, just not accelerated), or requests a fresh
   `.db`/manifest snapshot from the origin.
5. **Plan.** Before running a real query, the app (or a small JS helper)
   knows the query's constraint bounds on an indexed column and calls a new
   SQL function, e.g. `sqlcipher_page_manifest_pages(index_name, min, max)`,
   returning the candidate `leaf_pgno` set for that range (root/interior
   pgnos for the same index are already warm from step 2/one-time cheap
   fetches, so they don't need to be in this result).
6. **Prefetch.** JS issues all of those page fetches **in parallel**
   (`Promise.all` over one `fetch()` per page, or a single multi-range
   request if the origin supports `Range: bytes=a-b, c-d, ...`), populating
   the VFS's page cache.
7. **Run.** The client now calls the real query
   (`sqlite3_prepare_v2`/`sqlite3_step`) through the wasm C API exactly as
   today (see `wasm/test-roundtrip.mjs` for the raw-API calling pattern).
   The pager's own reads mostly hit the now-warm cache; anything the
   manifest didn't predict (overflow pages for large `TEXT`/`BLOB` cells,
   pages outside the requested range because the query plan didn't use the
   index the manifest covers) still falls back to a normal single on-demand
   fetch through the same `xRead` — correctness never depends on the
   prefetch guess being complete, only its usefulness does.

Everything above the transport/VFS layer is SQL-surfaced — same as VLE
(`doc/vle.md`) — so the manifest tables and the two new SQL functions need
no new low-level wasm export; they're reachable through the existing
`sqlite3_exec`/`sqlite3_prepare_v2` exports. The one genuinely new wasm/JS
piece is the HTTP-Range-backed VFS transport itself (step 1).

## Enable/disable: a new PRAGMA

`PRAGMA page_manifest_prefetch;` / `PRAGMA page_manifest_prefetch = ON|OFF;`
— boolean getter/setter, **default OFF**.

- **OFF (default):** no manifest maintenance, no new tables created, the
  new SQL functions are either absent or return a clear "feature not
  enabled" error; on-demand page-by-page fetching behaves exactly as it
  does today. Zero overhead for the overwhelming majority of deployments
  (a normal local file, or a remote db not accessed page-by-page) that get
  no benefit from this feature.
- **ON:** enables `sqlcipher_page_manifest`/`_meta` table creation (lazily,
  on first rebuild — turning the pragma on doesn't itself create anything
  until a rebuild actually runs) and makes
  `sqlcipher_page_manifest_rebuild()`/`sqlcipher_page_manifest_pages()`
  usable.
- **Scope:** per-connection, following the existing `PRAGMA cipher_*`
  convention in this codebase.
- **Wiring:** `src/pragma.c`'s `sqlite3Pragma()` already has exactly one
  hook point for a completely-custom (non-built-in) pragma name —
  `sqlcipher_codec_pragma(db, iDb, pParse, zLeft, zRight)`, called early
  and, if it returns non-zero, short-circuiting the rest of pragma
  dispatch (this is how `PRAGMA key`/`PRAGMA cipher_provider`/etc. already
  work, entirely inside `src/sqlcipher.c`, with no changes to `pragma.c`'s
  built-in table). The natural extension point is for
  `sqlcipher_codec_pragma()` to delegate an unrecognized name to a new
  `sqlcipher_page_manifest_pragma(...)` living beside this feature's own
  code (mirroring how VLE's code lives in its own file rather than being
  folded into `sqlcipher.c` directly), rather than growing
  `sqlcipher_codec_pragma()`'s own body.

## Known limitations (anticipated)

- **Collation:** manifest range comparison assumes `BINARY` collation.
  Indexes using `NOCASE` or a custom collation aren't correctly served by
  a byte-wise manifest lookup; v1 either excludes such indexes from
  manifest coverage or documents that prefetch silently falls back to
  fetching too little/too much for them (to be decided before
  implementation, not assumed here).
- **Overflow pages:** large `TEXT`/`BLOB` cells that spill past a single
  b-tree page aren't tracked by the manifest and are always fetched
  on-demand when actually read — a correctness non-issue, just an
  unoptimized path.
- **Read-only transport:** the HTTP-Range VFS this feature is designed
  around has no write story. Writing to a page-by-page-over-HTTP-backed
  database is out of scope for this feature; a client that needs to write
  should do so through a different channel (an API call to the origin,
  not through this VFS), and that write path is responsible for triggering
  a manifest rebuild before republishing.
- **Staleness is a snapshot model, not a guarantee:** a client's fetched
  manifest reflects `data_version` at fetch time. If the origin changes
  after that, the client's prefetch guess may be based on an out-of-date
  page layout. This never produces wrong query results (the real query
  still runs against whatever the VFS actually returns, verified by
  SQLite's own page/free-list/pointer-map consistency checks same as any
  other read), only wasted or insufficient prefetching — worth restating
  because "stale cache" bugs are easy to mis-read as correctness bugs when
  they're actually just missed optimization opportunities here.
- **Manifest size:** for a very large table, the manifest has one row per
  leaf page — smaller than the leaf data itself, but still `O(table size /
  page size)` rows. For extremely large tables this may itself become
  large enough to need paging through rather than fetching whole; not
  addressed in this design (assumed acceptable for the target
  small-to-medium remote-db use case; revisit if it isn't).

## Suggested implementation order (once this design is approved)

1. Schema + `sqlcipher_page_manifest_pragma()` (enable/disable only, no
   rebuild/lookup logic yet) — proves out the `sqlcipher_codec_pragma()`
   delegation wiring in isolation.
2. Rebuild: the C-level leaf-page-boundary walk + `sqlcipher_page_manifest_rebuild()`
   SQL function, tested against a variety of table/index shapes (including
   ones deliberately triggering page splits) with a native `testfixture`
   build, comparing manifest output against `dbstat` for consistency.
3. Lookup: `sqlcipher_page_manifest_pages()` SQL function plus the
   `data_version` staleness check.
4. WASM: rebuild `wasm/sqlcipher.js`/`.wasm` once steps 1-3 land (no wasm
   build changes needed themselves, same as VLE — see `doc/vle-plan.md`'s
   "WASM" step).
5. JS: a new HTTP-Range-backed VFS transport for `wasm/js-vfs.mjs`
   (read-only), plus a small prefetch-orchestration helper implementing the
   "Read flow" steps above, with its own `wasm/test-*.mjs` coverage
   (ideally against a real local HTTP server serving a static `.db` file
   with Range support, not just the in-memory VFS).
