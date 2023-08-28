#include <string.h>
#include <assert.h>
#include "common.h"
#include "../../deps/redis/crc64.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/endianconv.h"
#include <sys/uio.h>

#define _RDB_TYPE_STRING 0
#define VER_VAL(major,minor) (((unsigned int)(major)<<8) | (unsigned int)(minor))

typedef struct RedisToRdbVersion {
    unsigned int redis;
    unsigned char rdb;
} RedisToRdbVersion;

const RedisToRdbVersion redisToRdbVersion[] = {
        {VER_VAL(7,2), 11},
        {VER_VAL(7,0), 10},
        {VER_VAL(5,0), 9}, //6 and 6.2 had v9 too
        {VER_VAL(4,0), 8},
        {VER_VAL(3,2), 7},
        {VER_VAL(2,6), 6}, //2.8 had v6 too
        {VER_VAL(2,4), 5},
};

typedef enum DelKeyBeforeWrite {
    DEL_KEY_BEFORE_NONE,
    DEL_KEY_BEFORE_BY_DEL_CMD,
    DEL_KEY_BEFORE_BY_RESTORE_REPLACE, /* RESTORE supported */
} DelKeyBeforeWrite;

#define IOV_CONST(iov, str)       iov_plain(iov, str, sizeof(str)-1)
#define IOV_STRING(iov, str, len) iov_plain(iov, str, len)
#define IOV_VALUE(iov, val, ar)   iov_value(iov, val, ar, sizeof(ar))
#define IOV_LEN_AND_VALUE(iov, val, ar1, ar2) \
   do {\
        int l = IOV_VALUE((iov)+1, val, ar2); \
        IOV_VALUE( (iov), l, ar1); \
   } while (0);

struct RdbxToResp {

    RdbxToRespConf conf;

    /* Init to 2. Attempted to be released twice on termination by
     * raw handler and data handler */
    int refcount;

    RdbParser *parser;
    RdbxRespWriter respWriter;
    int respWriterConfigured;

    unsigned int targetVerValue;  /* major << 8 | minor */

    struct {
        RdbBulkCopy key;
        size_t keyLen;
        RdbKeyInfo info;
    } keyCtx;

    struct {
        int sentFirstFrag;
        size_t valSize;
    } rawCtx;

    uint64_t crc;
    int srcRdbVer;
    DelKeyBeforeWrite delKeyBeforeWrite;
};

static void deleteRdbToRespCtx(RdbParser *p, void *context) {
    RdbxToResp *ctx = (RdbxToResp *) context;

    if (!ctx) return;

    /* ignore the first release attempt */
    if (--ctx->refcount) return;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    /* delete respWriter */
    if (ctx->respWriter.delete)
        ctx->respWriter.delete(ctx->respWriter.ctx);

    RDB_free(p, ctx);
}

static inline void iov_plain(struct iovec *iov, const char *s, size_t l) {
    iov->iov_base = (void *) s;
    iov->iov_len = l;
}

static int iov_value(struct iovec *iov, long long count, char *buf, int bufsize) {
    int len = 0;
    len = ll2string(buf, bufsize, count);

    int lenWithNewLine = len;
    buf[lenWithNewLine++] = '\r';
    buf[lenWithNewLine++] = '\n';

    iov_plain(iov, buf, lenWithNewLine);
    return len;
}

static int rdbVerFromRedisVer(RdbxToResp *ctx) {
    const char *ver = ctx->conf.dstRedisVersion;
    if (!ver) return 0;

    int mjr=0, mnr, pch, pos1 = 0, pos2 = 0;
    int scanned = sscanf(ver, "%d.%d%n.%d%n", &mjr, &mnr, &pos1, &pch, &pos2);
    if ((scanned == 3 && pos2 == (int) strlen(ver)) ||
        (scanned == 2 && pos1 == (int) strlen(ver))) {

        ctx->targetVerValue = VER_VAL(mjr, mnr);
        unsigned int i;
        for (i = 0; i < sizeof(redisToRdbVersion) / sizeof(redisToRdbVersion[0]); i++)
            if (ctx->targetVerValue >= redisToRdbVersion[i].redis) return redisToRdbVersion[i].rdb;
    }
    return 0;
}

static void resolveSupportRestore(RdbParser *p, RdbxToResp *ctx, int srcRdbVer) {
    int dstRdbVer;

    ctx->srcRdbVer = srcRdbVer;

    ctx->delKeyBeforeWrite = (ctx->conf.delKeyBeforeWrite) ? DEL_KEY_BEFORE_BY_DEL_CMD : DEL_KEY_BEFORE_NONE;

    if (ctx->conf.supportRestore) {
        /* if not configured destination RDB version, then resolve it from
         * configured destination Redis version */
        dstRdbVer = rdbVerFromRedisVer(ctx);

        if (dstRdbVer < srcRdbVer) {
            RDB_log(p, RDB_LOG_WRN,
                    "Cannot support RESTORE. source RDB version (=%d) is higher than destination (=%d)",
                    srcRdbVer, dstRdbVer);
            ctx->conf.supportRestore = 0;
        } else {
            if (ctx->conf.delKeyBeforeWrite) {
                RDB_log(p, RDB_LOG_INF, "As RESTORE is supported, configuration del-key-before-write will be ignored.");
                ctx->delKeyBeforeWrite = DEL_KEY_BEFORE_BY_RESTORE_REPLACE;
            }
        }
    }

    RdbHandlersLevel lvl = (ctx->conf.supportRestore) ? RDB_LEVEL_RAW : RDB_LEVEL_DATA;
    for (int i = 0; i < RDB_DATA_TYPE_MAX; ++i) {
        RDB_handleByLevel(p, (RdbDataType) i, lvl, 0);
    }

    /* librdb cannot parse a module object */
    RDB_handleByLevel(p, RDB_DATA_TYPE_MODULE, RDB_LEVEL_RAW, 0);
}

static inline RdbRes writevWrap(RdbxToResp *ctx, struct iovec *iov, int cnt, int startCmd, int endCmd) {
    RdbxRespWriter *writer = &ctx->respWriter;
    if (unlikely(writer->writev(writer->ctx, iov, cnt, startCmd, endCmd))) {
        RdbRes errCode = RDB_getErrorCode(ctx->parser);
        assert(errCode != RDB_OK);
        return RDB_getErrorCode(ctx->parser);
    }

    return RDB_OK;
}

/*** Handling common ***/

static RdbRes toRespNewDb(RdbParser *p, void *userData, int dbid) {
    UNUSED(p);

    struct iovec iov[10];
    char dbidStr[10], cntStr[10];

    RdbxToResp *ctx = userData;

    int cnt = ll2string(dbidStr, sizeof(dbidStr), dbid);

    IOV_CONST(&iov[0], "*2\r\n$6\r\nSELECT\r\n$");
    IOV_VALUE(&iov[1], cnt, cntStr);
    IOV_STRING(&iov[2], dbidStr, cnt);
    IOV_CONST(&iov[3], "\r\n");
    return writevWrap(ctx, iov, 4, 1, 1);
}

static RdbRes toRespStartRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    resolveSupportRestore(p, ctx, rdbVersion);

    return RDB_OK;
}

/* TODO: support expiry */
static RdbRes toRespNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(info);
    RdbxToResp *ctx = userData;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);

    /* handling new key */
    ctx->crc = 0;
    ctx->keyCtx.info = *info;
    ctx->keyCtx.keyLen = RDB_bulkLen(p, key);
    if ((ctx->keyCtx.key = RDB_bulkClone(p, key)) == NULL)
        return RDB_ERR_FAIL_ALLOC;

    /* apply del-key-before-write if configured, unless it is 'SET' command where
     * the key is overridden if it already exists, without encountering any problems. */
    if ((ctx->delKeyBeforeWrite == DEL_KEY_BEFORE_BY_DEL_CMD) && (info->opcode != _RDB_TYPE_STRING)) {
        struct iovec iov[4];
        char keyLenStr[32];
        IOV_CONST(&iov[0], "*2\r\n$3\r\nDEL\r\n$");
        IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n");
        return writevWrap(ctx, iov, 4, 1, 1);
    }
    return RDB_OK;
}

static RdbRes toRespEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* key is in db. Set its expiration time */
    if (ctx->keyCtx.info.expiretime != -1) {
        struct iovec iov[6];
        char keyLenStr[32], expireLenStr[32], expireStr[32];
        /* PEXPIREAT */
        IOV_CONST(&iov[0], "*3\r\n$9\r\nPEXPIREAT\r\n$");

        /* KEY-LEN and KEY */
        IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n$");
        IOV_LEN_AND_VALUE(iov+4, ctx->keyCtx.info.expiretime, expireLenStr, expireStr);

        return writevWrap(ctx, iov, 6, 1, 1);
    }

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toRespString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToResp *ctx = userData;

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, string);

    /*** fillup iovec ***/

    struct iovec iov[7];
    /* write SET */
    IOV_CONST(&iov[0], "*3\r\n$3\r\nSET\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write string */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], string, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespList(RdbParser *p, void *userData, RdbBulk item) {
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, item);

    struct iovec iov[7];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$5\r\nRPUSH\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write item */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], item, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[32], fieldLenStr[32], valueLenStr[32];
    int fieldLen = RDB_bulkLen(p, field);
    int valueLen = RDB_bulkLen(p, value);

    struct iovec iov[10];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*4\r\n$4\r\nHSET\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write field */
    IOV_VALUE(&iov[4], fieldLen, fieldLenStr);
    IOV_STRING(&iov[5], field, fieldLen);
    IOV_CONST(&iov[6], "\r\n$");
    /* write value */
    IOV_VALUE(&iov[7], valueLen, valueLenStr);
    IOV_STRING(&iov[8], value, valueLen);
    IOV_CONST(&iov[9], "\r\n");
    return writevWrap(ctx, iov, sizeof(iov)/sizeof(iov[0]), 1, 1);
}

static RdbRes toRespSet(RdbParser *p, void *userData, RdbBulk member) {
    RdbxToResp *ctx = userData;
    char keyLenStr[32], valLenStr[32];

    int valLen = RDB_bulkLen(p, member);

    struct iovec iov[7];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$4\r\nSADD\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write member */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], member, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespEndRdb(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    RdbxRespWriter *writer = &ctx->respWriter;
    if (likely(writer->flush(writer->ctx) == 0))
        return RDB_OK;

    if (RDB_getErrorCode(p) != RDB_OK)
        return RDB_getErrorCode(p);

    /* writer didn't take care to report an error */
    RDB_log(p, RDB_LOG_WRN, "Writer returned error indication but didn't RDB_reportError()");
    RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_WRITE, "RESP writer returned error on flush()");
    return (RdbRes) RDBX_ERR_RESP_WRITE;
}

/*** Handling raw ***/

static RdbRes toRespRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    ctx->rawCtx.valSize = size;
    ctx->rawCtx.sentFirstFrag = 0;
    return RDB_OK;
}

static RdbRes toRespRawFrag(RdbParser *p, void *userData, RdbBulk frag) {
    long long expireTime = 0;
    char expireTimeStr[32], expireTimeLenStr[32], keyLenStr[32], totalLenStr[32];
    UNUSED(p);
    RdbxToResp *ctx = userData;
    struct iovec iov[10];
    int iovs = 0;
    size_t fragLen = RDB_bulkLen(p, frag);

    ctx->crc = crc64(ctx->crc, (unsigned char *) frag , fragLen);

    if (likely(!(ctx->rawCtx.sentFirstFrag))) {
        ctx->rawCtx.sentFirstFrag = 1;

        int extra_args = 0;
        /* this logic must be exactly the same as in toRespRawFragEnd() */
        if (ctx->targetVerValue >= VER_VAL(5,0))
        {
            if (ctx->keyCtx.info.expiretime != -1) {
                expireTime = ctx->keyCtx.info.expiretime;
                extra_args++; /* ABSTTL */
            }

            /* TODO: lru_idle <idle>, lfu_freq <freq>*/
        }

        if (ctx->delKeyBeforeWrite == DEL_KEY_BEFORE_BY_RESTORE_REPLACE)
            extra_args++;

        char cmd[64];
        int len = sprintf(cmd, "*%d\r\n$7\r\nRESTORE\r\n$", 4+extra_args);

        IOV_STRING(&iov[iovs++], cmd, len);                             /* RESTORE */
        IOV_VALUE(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);         /* write key len */
        IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);  /* write key */

        if (expireTime) {
            IOV_CONST(&iov[iovs++], "\r\n$");
            IOV_LEN_AND_VALUE(&iov[iovs], expireTime, expireTimeLenStr, expireTimeStr);
            iovs += 2;
            IOV_CONST(&iov[iovs++], "$");
        } else {
            IOV_CONST(&iov[iovs++], "\r\n$1\r\n0\r\n$");
        }
        IOV_VALUE(&iov[iovs++], ctx->rawCtx.valSize + 10, totalLenStr); /* write value length */
    }
    IOV_STRING(&iov[iovs++], frag, fragLen);                            /* write value */

    return writevWrap(ctx, iov, iovs, 1, 0);
}

static RdbRes toRespRawFragEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    uint64_t *crc = &(ctx->crc);

    char footer[10];
    footer[0] = ctx->srcRdbVer & 0xff;
    footer[1] = (ctx->srcRdbVer >> 8) & 0xff;
    *crc = crc64(*crc, (unsigned char *) footer, 2);
    /* CRC64 */
    memrev64ifbe(crc);
    memcpy(footer + 2, crc, 8);

    struct iovec iov[10];
    int iovs = 0;

    IOV_STRING(&iov[iovs++], footer, 10);
    if (ctx->delKeyBeforeWrite == DEL_KEY_BEFORE_BY_RESTORE_REPLACE)
        IOV_CONST(&iov[iovs++], "\r\n$7\r\nREPLACE\r\n");
    else
        IOV_CONST(&iov[iovs++], "\r\n");

    if (likely(ctx->targetVerValue >= VER_VAL(5,0))) {
        if (ctx->keyCtx.info.expiretime != -1) {
            IOV_CONST(&iov[iovs++], "$6\r\nABSTTL\r\n");
            ctx->keyCtx.info.expiretime = -1; /* take care reset before reach toRespEndKey() */
        }
    }

    return writevWrap(ctx, iov, iovs, 0, 1);
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConf *conf) {
    RdbxToResp *ctx;

    if ((ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset(ctx, 0, sizeof(RdbxToResp));

    if (conf)
        ctx->conf = *conf;

    ctx->refcount = 2;
    ctx->parser = p;

    RdbHandlersDataCallbacks dataCb;
    memset(&dataCb, 0, sizeof(RdbHandlersDataCallbacks));
    dataCb.handleStartRdb = toRespStartRdb;
    if (ctx->conf.applySelectDbCmds)
        dataCb.handleNewDb = toRespNewDb;
    dataCb.handleNewKey = toRespNewKey;
    dataCb.handleEndKey = toRespEndKey;
    dataCb.handleStringValue = toRespString;
    dataCb.handleListItem = toRespList;
    dataCb.handleHashField = toRespHash;
    dataCb.handleSetMember = toRespSet;
    dataCb.handleEndRdb = toRespEndRdb;
    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToRespCtx);

    RdbHandlersRawCallbacks rawCb;
    memset(&rawCb, 0, sizeof(RdbHandlersRawCallbacks));
    rawCb.handleStartRdb = NULL; /* already registered to this common callback */
    rawCb.handleNewKey = toRespNewKey;
    rawCb.handleEndKey = toRespEndKey;
    rawCb.handleFrag = toRespRawFrag;
    rawCb.handleBegin = toRespRawBegin;
    rawCb.handleEnd = toRespRawFragEnd;
    RDB_createHandlersRaw(p, &rawCb, ctx, deleteRdbToRespCtx);
    return ctx;
}

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer) {
    assert (rdbToResp->respWriterConfigured == 0);
    rdbToResp->respWriter = *writer;
    rdbToResp->respWriterConfigured = 1;
}