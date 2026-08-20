#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "handlersCommon.h"
#include "../lib/defines.h" /* valid include since it brings only RDB_* defines */

#define _STDOUT_STR "<stdout>"

/* Rough overhead constants for the in-memory size estimate (%z / statistics).
 * Approximations in the spirit of Redis `MEMORY USAGE`, calibrated so large keys
 * land within ~25% of live MEMORY USAGE. Small-key-heavy dumps skew low: unlike
 * `MEMORY USAGE` we don't round allocations up to jemalloc size classes. */
#define OBJ_OVERHEAD        16
#define SDS_OVERHEAD        16
#define KEYSPACE_DICTENTRY  16  /* keyspace no_value dictEntry {key,next} (Redis 7.4+) */
#define EXPIRE_OVERHEAD     32  /* entry in the expires dict (dictEntry + int64) */
#define META_SLOT            8  /* embedded meta slot (module, hash-field TTL)  */
#define LP_HEADER           11
#define LP_ELEM_OVERHEAD     3
#define DICTENTRY_OVERHEAD  24
#define SKIPLIST_NODE       56
#define QL_NODE_OVERHEAD    11
#define QL_NODE_FILL       128
#define INTSET_HEADER        8
#define INTSET_ELEM          4
#define ZSET_SCORE_BYTES     4

/*** Type / encoding names ***/

const char *rdbxTypeName(int dataType) {
    switch (dataType) {
        case RDB_DATA_TYPE_STRING:   return "string";
        case RDB_DATA_TYPE_LIST:     return "list";
        case RDB_DATA_TYPE_SET:      return "set";
        case RDB_DATA_TYPE_ZSET:     return "zset";
        case RDB_DATA_TYPE_HASH:     return "hash";
        case RDB_DATA_TYPE_STREAM:   return "stream";
        case RDB_DATA_TYPE_MODULE:   return "module";
        case RDB_DATA_TYPE_FUNCTION: return "function";
        case RDB_DATA_TYPE_ARRAY:    return "array";
        default:                     return "unknown";
    }
}

/* Maps the on-disk RDB type (RdbKeyInfo.opcode) to an encoding name (%n). */
const char *rdbxEncodingStr(int opcode) {
    switch (opcode) {
        case RDB_TYPE_STRING:                   return "string";
        case RDB_TYPE_LIST:
        case RDB_TYPE_LIST_QUICKLIST:
        case RDB_TYPE_LIST_QUICKLIST_2:         return "quicklist";
        case RDB_TYPE_LIST_ZIPLIST:             return "ziplist";
        case RDB_TYPE_SET:                      return "hashtable";
        case RDB_TYPE_SET_INTSET:               return "intset";
        case RDB_TYPE_SET_LISTPACK:             return "listpack";
        case RDB_TYPE_ZSET:
        case RDB_TYPE_ZSET_2:                   return "skiplist";
        case RDB_TYPE_ZSET_ZIPLIST:             return "ziplist";
        case RDB_TYPE_ZSET_LISTPACK:            return "listpack";
        case RDB_TYPE_HASH:
        case RDB_TYPE_HASH_METADATA:
        case RDB_TYPE_HASH_METADATA_PRE_GA:     return "hashtable";
        case RDB_TYPE_HASH_ZIPMAP:              return "zipmap";
        case RDB_TYPE_HASH_ZIPLIST:             return "ziplist";
        case RDB_TYPE_HASH_LISTPACK:
        case RDB_TYPE_HASH_LISTPACK_EX:
        case RDB_TYPE_HASH_LISTPACK_EX_PRE_GA:  return "listpack";
        case RDB_TYPE_MODULE_2:
        case RDB_TYPE_MODULE_PRE_GA:            return "module";
        case RDB_TYPE_STREAM_LISTPACKS:
        case RDB_TYPE_STREAM_LISTPACKS_2:
        case RDB_TYPE_STREAM_LISTPACKS_3:
        case RDB_TYPE_STREAM_LISTPACKS_4:
        case RDB_TYPE_STREAM_LISTPACKS_5:       return "stream";
        case RDB_TYPE_ARRAY:                    return "array";
        default:                                return "unknown";
    }
}

/*** Memory estimate (rough; mirrors Redis MEMORY USAGE, object only) ***/

static int estimIsIntegerStr(const char *s, size_t len) {
    if (len == 0 || len > 20) return 0;
    size_t i = (s[0] == '-') ? 1 : 0;
    if (i == len) return 0;
    if (s[i] == '0' && len - i > 1) return 0; /* no leading zeros */
    for (; i < len; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

static uint64_t estimValueBytes(int opcode, uint64_t n, uint64_t s,
                         uint64_t bytes, uint64_t moduleBytes, int isIntStr) {
    switch (opcode) {
        case RDB_TYPE_STRING:
            return isIntStr ? 0 : (bytes + SDS_OVERHEAD);
        case RDB_TYPE_LIST_ZIPLIST: case RDB_TYPE_ZSET_ZIPLIST: case RDB_TYPE_ZSET_LISTPACK:
        case RDB_TYPE_HASH_ZIPLIST: case RDB_TYPE_HASH_ZIPMAP:  case RDB_TYPE_HASH_LISTPACK:
        case RDB_TYPE_HASH_LISTPACK_EX: case RDB_TYPE_HASH_LISTPACK_EX_PRE_GA:
        case RDB_TYPE_SET_LISTPACK:
            return LP_HEADER + bytes + LP_ELEM_OVERHEAD * s;
        case RDB_TYPE_SET_INTSET:
            return INTSET_HEADER + n * INTSET_ELEM;
        case RDB_TYPE_LIST: case RDB_TYPE_LIST_QUICKLIST: case RDB_TYPE_LIST_QUICKLIST_2: {
            uint64_t nodes = (n + QL_NODE_FILL - 1) / QL_NODE_FILL; if (nodes < 1) nodes = 1;
            return nodes * (LP_HEADER + QL_NODE_OVERHEAD) + bytes + LP_ELEM_OVERHEAD * s;
        }
        case RDB_TYPE_HASH: case RDB_TYPE_HASH_METADATA: case RDB_TYPE_HASH_METADATA_PRE_GA:
        case RDB_TYPE_SET:
            return bytes + SDS_OVERHEAD * s + DICTENTRY_OVERHEAD * n;
        case RDB_TYPE_ZSET: case RDB_TYPE_ZSET_2:
            return bytes + (SDS_OVERHEAD + DICTENTRY_OVERHEAD + SKIPLIST_NODE) * n;
        case RDB_TYPE_MODULE_2: case RDB_TYPE_MODULE_PRE_GA:
            return moduleBytes;
        default: /* stream / array / fallback */
            return LP_HEADER + bytes + LP_ELEM_OVERHEAD * s;
    }
}

void rdbxComputeMemBytes(RdbxKeyCtx *kc) {
    uint64_t meta = (kc->info.expiretime != -1 ? EXPIRE_OVERHEAD : 0) +
                    (uint64_t) kc->info.numMeta * META_SLOT;
    kc->memBytes = OBJ_OVERHEAD + kc->keyLen + SDS_OVERHEAD + KEYSPACE_DICTENTRY + meta +
        estimValueBytes(kc->info.opcode, kc->items, kc->numStrings,
                        kc->sumStrBytes, kc->moduleBytes, kc->isIntStr);
}

void rdbxKeyCtxSetString(RdbxKeyCtx *kc, const char *s, size_t len) {
    kc->isIntStr = estimIsIntegerStr(s, len);
    kc->numStrings = 1;
    kc->sumStrBytes = len;
    kc->largest = len;
    rdbxComputeMemBytes(kc);
}

/*** Setup / teardown ***/

int rdbxBaseInit(RdbParser *p, RdbxHandlersBase *base, const char *outFilename) {
    FILE *f;

    if (outFilename == NULL) {
        f = stdout;
        outFilename = _STDOUT_STR;
    } else if (!(f = fopen(outFilename, "w"))) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_FILE,
                        "handlersCommon: Failed to open file `%s`. errno=%d: %s",
                        outFilename, errno, strerror(errno));
        return 1;
    }

    RDB_log(p, RDB_LOG_DBG, "handlersCommon: Opening file %s", outFilename);
    base->p = p;
    base->outfile = f;
    base->outfileName = RDB_alloc(p, strlen(outFilename) + 1);
    strcpy(base->outfileName, outFilename);
    return 0;
}

void rdbxBaseDestroy(RdbParser *p, RdbxHandlersBase *base) {
    RDB_bulkCopyFree(p, base->keyCtx.key);

    RDB_log(p, RDB_LOG_DBG, "handlersCommon: Closing file %s", base->outfileName);
    if ((base->outfile) && (base->outfile != stdout))
        fclose(base->outfile);

    RDB_free(p, base->outfileName);
}

/*** key-size accumulation helpers ***/

void rdbxKeyCtxReset(RdbParser *p, RdbxKeyCtx *kc, RdbBulk key, RdbKeyInfo *info) {
    kc->key = RDB_bulkClone(p, key);
    kc->keyLen = RDB_bulkLen(p, key);
    kc->info = *info;
    kc->skip = 0;
    kc->items = 0;
    kc->numStrings = kc->sumStrBytes = kc->largest = 0;
    kc->moduleBytes = kc->memBytes = 0;
    kc->isIntStr = 0;
}

void rdbxAccountElem(RdbxKeyCtx *kc, uint64_t len, unsigned strings) {
    kc->items++;
    kc->numStrings += strings;
    kc->sumStrBytes += len;
    if (len > kc->largest) kc->largest = len;
}

void rdbxAccountPair(RdbxKeyCtx *kc, uint64_t flen, uint64_t vlen) {
    kc->items++;
    kc->numStrings += 2;
    kc->sumStrBytes += flen + vlen;
    if (flen > kc->largest) kc->largest = flen;
    if (vlen > kc->largest) kc->largest = vlen;
}

void rdbxAccountZset(RdbxKeyCtx *kc, uint64_t mlen) {
    kc->items++;
    kc->numStrings += 2;                              /* member + score: two listpack elements */
    kc->sumStrBytes += mlen + ZSET_SCORE_BYTES;       /* score counts for memory */
    if (mlen > kc->largest) kc->largest = mlen;       /* but not for "largest"   */
}

/* A module value of `serializedSize` bytes. */
void rdbxAccountModule(RdbxKeyCtx *kc, uint64_t serializedSize) {
    kc->moduleBytes = serializedSize;
    if (serializedSize > kc->largest) kc->largest = serializedSize;
}
