#include <string.h>
#include <assert.h>
#include "common.h"
#include "../../deps/redis/crc64.h"
#include "../../deps/redis/utils.h"
#include "../../deps/redis/endianconv.h"
#include <sys/uio.h>

#define RETURN_ON_WRITE_ERR(cmd) do {\
    if (unlikely(0 == (cmd))) return (RdbRes) RDBX_ERR_RESP_WRITE; \
    } while(0);

#define WRITE_CONST_STR(wr, str, endCmd) (wr)->write((wr)->ctx, str, sizeof(str) - 1, endCmd)

void setIov(struct iovec *iov, const char *s, size_t l) {
    iov->iov_base = (void *) s;
    iov->iov_len = l;
}

#define IOV_CONST_STR(iov, str) setIov(iov, str, sizeof(str)-1)
#define IOV_STRING(iov, str, len) setIov(iov, str, len)

struct RdbxToResp {

    RdbxToRespConf conf;

    /* Init to 2. Attempted to be released twice on termination by
     * raw handler and data handler */
    int refcount;

    RdbParser *parser;
    RdbxRespWriter respWriter;
    int respWriterConfigured;

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

static int iov_stringLen(struct iovec *iov, long count, char *buf) {
    int len = 0;
    len = ll2string(buf, sizeof(buf) - 1, count);

    int lenWithNewLine = len;
    buf[lenWithNewLine++] = '\r';
    buf[lenWithNewLine++] = '\n';

    iov->iov_base = buf;
    iov->iov_len = lenWithNewLine;
    return len;
}

static int rdbVerFromRedisVer(const char *ver) {
    if (!ver) return 0;

    struct {
        char redis;
        char rdb;
    } redis2rdb[] = {
            {0x72, 11},
            {0x70, 10},
            {0x50, 9}, //6 and 6.2 had v9 too
            {0x40, 8},
            {0x32, 7},
            {0x26, 6}, //2.8 had v6 too
            {0x24, 5},
    };
    int a, b, c, pos1 = 0, pos2 = 0;
    int scanned = sscanf(ver, "%d.%d%n.%d%n", &a, &b, &pos1, &c, &pos2);
    if ((scanned == 3 && pos2 == (int) strlen(ver)) ||
        (scanned == 2 && pos1 == (int) strlen(ver))) {
        unsigned char hex = (a << 4) | b;
        unsigned int i;
        for (i = 0; i < sizeof(redis2rdb) / sizeof(redis2rdb[0]); i++)
            if (hex >= redis2rdb[i].redis) return redis2rdb[i].rdb;
    }
    return 0;
}

static void resolveSupportRestore(RdbParser *p, RdbxToResp *ctx, int srcRdbVer) {
    int isRestore = ctx->conf.supportRestore;
    int dstRdbVer = ctx->conf.restore.dstRdbVersion;

    ctx->srcRdbVer = srcRdbVer;

    if (isRestore) {
        /* if not configured destination RDB version, then resolve it from
         * configured destination Redis version */
        if (!dstRdbVer)
            dstRdbVer = rdbVerFromRedisVer(ctx->conf.restore.dstRedisVersion);

        if (dstRdbVer < srcRdbVer)
            isRestore = 0;
    }

    RdbHandlersLevel lvl = (isRestore) ? RDB_LEVEL_RAW : RDB_LEVEL_DATA;
    for (int i = 0; i < RDB_DATA_TYPE_MAX; ++i) {
        RDB_handleByLevel(p, (RdbDataType) i, lvl, 0);
    }

    /* librdb cannot parse a module object */
    RDB_handleByLevel(p, RDB_DATA_TYPE_MODULE, RDB_LEVEL_RAW, 0);
}

static inline RdbRes writevWrap(RdbxToResp *ctx, const struct iovec *iov, int cnt, uint64_t bulksBitmask, int endCmd) {
    RdbxRespWriter *writer = &ctx->respWriter;
    if (unlikely(writer->writev(writer->ctx, iov, cnt, bulksBitmask, endCmd))) {
        RdbRes errCode = RDB_getErrorCode(ctx->parser);
        assert(errCode != RDB_OK);
        return RDB_getErrorCode(ctx->parser);
    }

    return RDB_OK;
}

/*** Handling common ***/

static RdbRes toRespHandlingNewDb(RdbParser *p, void *userData, int dbid) {
    UNUSED(p);

    struct iovec iov[10];
    char dbidStr[10], cntStr[10];

    RdbxToResp *ctx = userData;

    int cnt = ll2string(dbidStr, sizeof(dbidStr), dbid);

    IOV_CONST_STR(&iov[0], "*2\r\n$6\r\nSELECT\r\n$");
    iov_stringLen(&iov[1], cnt, cntStr);
    IOV_STRING(&iov[2], dbidStr, cnt);
    IOV_CONST_STR(&iov[3], "\r\n");
    return writevWrap(ctx, iov, 4, 0 /*bulksBitmask*/, 1);
}

static RdbRes toRespHandlingNewRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    resolveSupportRestore(p, ctx, rdbVersion);

    return RDB_OK;
}

/* todo: support option rdb2resp del key before write */
/* todo: support expiry */
static RdbRes toRespHandlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(info);
    RdbxToResp *ctx = userData;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);

    /* handling new key */
    ctx->keyCtx.info = *info;
    ctx->keyCtx.keyLen = RDB_bulkLen(p, key);
    if ((ctx->keyCtx.key = RDB_bulkClone(p, key)) == NULL)
        return RDB_ERR_FAIL_ALLOC;
    return RDB_OK;
}

static RdbRes toRespHandlingEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toRespHandlingString(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = userData;

    char keyLenStr[64], valLenStr[64];
    int valLen = RDB_bulkLen(p, value);

    uint64_t bulksBitmask = (1 << 5);

    /*** fillup iovec ***/

    struct iovec iov[7];
    /* write SET */
    IOV_CONST_STR(&iov[0], "*3\r\n$3\r\nSET\r\n$");
    /* write key */
    iov_stringLen(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST_STR(&iov[3], "\r\n$");
    /* write value */
    iov_stringLen(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], value, valLen);
    IOV_CONST_STR(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, bulksBitmask, 1);
}

static RdbRes toRespHandlingList(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[64], valLenStr[64];
    int valLen = RDB_bulkLen(p, value);

    uint64_t bulksBitmask = (1 << 2) | (1 << 4);
    struct iovec iov[7];
    /* write RPUSH */
    IOV_CONST_STR(&iov[0], "*3\r\n$5\r\nRPUSH\r\n$");
    /* write key */
    iov_stringLen(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST_STR(&iov[3], "\r\n$");
    /* write value */
    iov_stringLen(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], value, valLen);
    IOV_CONST_STR(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, bulksBitmask, 1);
}

static RdbRes toRespHandlingEndRdb(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    RdbxRespWriter *writer = &ctx->respWriter;
    writer->flush(writer->ctx);
    return RDB_OK;
}

/*** Handling raw ***/

static RdbRes toRespHandlingRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    ctx->rawCtx.valSize = size;
    ctx->rawCtx.sentFirstFrag = 0;
    return RDB_OK;
}

static RdbRes toRespHandlingRawFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    struct iovec iov[10];
    uint64_t bulksBitmask;
    int iovs = 0;

    ctx->crc = crc64(ctx->crc, (unsigned char *) frag, RDB_bulkLen(p, frag));

    if (likely(!(ctx->rawCtx.sentFirstFrag))) {
        char keyLenStr[64], totalLenStr[64];

        ctx->rawCtx.sentFirstFrag = 1;

        IOV_CONST_STR(&iov[iovs++], "*4\r\n$7\r\nRESTORE\r\n$");        /* RESTORE */
        iov_stringLen(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);     /* write key len */
        IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);  /* write key */
        IOV_CONST_STR(&iov[iovs++], "\r\n$1\r\n0\r\n$");                /* newline + write TTL */
        iov_stringLen(&iov[iovs++], ctx->rawCtx.valSize + 10, totalLenStr);    /* write value length */
        IOV_STRING(&iov[iovs++], frag, RDB_bulkLen(p, frag));           /* write value */
        bulksBitmask = 1 << 5;

    } else {
        bulksBitmask = 1 << 0;
        IOV_STRING(&iov[iovs++], frag, RDB_bulkLen(p, frag)); /* write value */
    }
    return writevWrap(ctx, iov, iovs, bulksBitmask, 0);
}

static RdbRes toRespHandlingRawFragEnd(RdbParser *p, void *userData) {
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

    struct iovec iov[] = {
            {footer, 10},
            {"\r\n", 2}
    };
    return writevWrap(ctx, iov, 2, 0, 1);
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConf *conf) {
    RdbxToResp *ctx;

    if ((ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset(ctx, 0, sizeof(RdbxToResp));

    if (conf) {
        ctx->conf = *conf;
    } else {
        ctx->conf.supportRestore = 0;
    }
    ctx->refcount = 2;
    ctx->parser = p;

    RdbHandlersDataCallbacks dataCb;
    memset(&dataCb, 0, sizeof(RdbHandlersDataCallbacks));
    dataCb.handleNewRdb = toRespHandlingNewRdb;
    if (ctx->conf.applySelectDbCmds)
        dataCb.handleNewDb = toRespHandlingNewDb;
    dataCb.handleNewKey = toRespHandlingNewKey;
    dataCb.handleEndKey = toRespHandlingEndKey;
    dataCb.handleStringValue = toRespHandlingString;
    dataCb.handleListElement = toRespHandlingList;
    dataCb.handleEndRdb = toRespHandlingEndRdb;
    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToRespCtx);

    RdbHandlersRawCallbacks rawCb;
    memset(&rawCb, 0, sizeof(RdbHandlersRawCallbacks));
    rawCb.handleNewRdb = NULL; /* already registered to this common callback */
    rawCb.handleNewKey = toRespHandlingNewKey;
    rawCb.handleEndKey = toRespHandlingEndKey;
    rawCb.handleFrag = toRespHandlingRawFrag;
    rawCb.handleBegin = toRespHandlingRawBegin;
    rawCb.handleEnd = toRespHandlingRawFragEnd;
    RDB_createHandlersRaw(p, &rawCb, ctx, deleteRdbToRespCtx);
    return ctx;
}

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer) {
    assert (rdbToResp->respWriterConfigured == 0);
    rdbToResp->respWriter = *writer;
    rdbToResp->respWriterConfigured = 1;
}