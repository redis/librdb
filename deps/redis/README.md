# deps/redis

Code adapted from [Redis](https://github.com/redis/redis), compiled into librdb
so it can decode the encodings found in RDB files (listpack, ziplist, zipmap,
intset, rax, stream, LZF, CRC64, double formatting). It is **not** a tracked
vendoring: the files were copied from **Redis 7.0.11** (`fpconv_*` from Redis
7.2 `deps/fpconv`) and have been edited locally since. `version.h` records the
origin version.

## How the files relate to Redis

| File(s) | Relation to upstream |
|---|---|
| `crcspeed.[ch]`, `endianconv.c`, `lzf_c.c`, `lzf_d.c`, `lzf.h`, `lzfP.h`, `sha256.[ch]`, `zipmap.h`, `fpconv_*` | Verbatim copies. |
| `listpack.[ch]`, `listpack_malloc.h`, `intset.[ch]`, `rax.[ch]`, `rax_malloc.h`, `zipmap.c`, `crc64.[ch]`, `ziplist.[ch]`, `config.h`, `endianconv.h` | Copies with small local edits, each marked by a `librdb:` comment (see below). |
| `t_zset.[ch]`, `t_stream.c`, `stream.h`, `util.[ch]` | librdb-authored extracts: only the helpers the parser needs, rewritten without `server.h`. A resync means re-extracting, not diffing. |

## Local edits (all marked `librdb:` in the source)

- **Allocator**: `zmalloc`/`zfree` replaced by libc `malloc`/`free` through the
  existing `lp_malloc`, `rax_malloc` and (added) `is_malloc` macros; `zipmap.c`
  calls libc directly.
- **Assertions**: `redisassert.h` replaced by `<assert.h>` (`listpack.c`,
  `intset.c`).
- **Additions**: `crc64_init_thread_safe()` (crc64), `intsetMax()`/`intsetMin()`
  (intset), `#error` guard on `BYTE_ORDER` (endianconv.h), `__sun` and GCC
  version tweaks plus unsafe-libc deprecation attributes (config.h).
- **Removals**: `raxRandomWalk()` declaration (needs `math.h`), `ziplistTest()`
  declaration, `lpStringToInt64()` moved to `util.c`.
- **Backports from newer Redis**: `lpUpgradeCompactBacklen()` and its helper
  `lpEncodeBacklenBytes()` from Redis 8.12 (redis/redis#16099), fenced by
  `librdb: begin/end backport` comments. Two lines differ from upstream, both
  marked: the vendored `lpCurrentEncodedSizeBytes()` takes a pointer, and the
  source listpack is not freed because the parser owns it.

## Updating

Prefer backporting a whole upstream function, verbatim and fenced, over writing
a librdb-shaped variant: it keeps the next resync a mechanical diff. When
resyncing a file, re-apply the edits listed above and update this file and
`version.h`.
