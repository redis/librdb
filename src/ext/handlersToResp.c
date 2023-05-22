#include <string.h>
#include <assert.h>
#include "common.h"
#include "../../deps/redis/crc64.h"
#include "../../deps/redis/utils.h"
#include "../../deps/redis/endianconv.h"

#define RETURN_ON_WRITE_ERR(cmd) do {\
    if (unlikely(0 == (cmd))) return (RdbRes) RDBX_ERR_RESP_WRITE; \
    } while(0);

#define WRITE_CONST_STR(wr, str, endCmd) (wr)->write((wr)->ctx, str, sizeof(str) - 1, endCmd)

struct RdbxToResp {

    RdbxToRespConf conf;

    /* Init to 2. Attempted to be released twice on termination by
     * raw handler and data handler */
    int refcount;

    RdbxRespWriter respWriter;
    int respWriterConfigured;

    struct {
        RdbBulkCopy key;
        size_t keyLen;
        RdbKeyInfo info;
    } keyCtx;

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

static size_t writeStrLength(RdbxRespWriter *writer, char prefix, long count) {
    char buf[128];
    int len;

    buf[0] = prefix;
    len = 1 + ll2string(buf + 1, sizeof(buf) - 1, count);
    buf[len++] = '\r';
    buf[len++] = '\n';
    return writer->write(writer->ctx, buf, len, 0);
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
    int a,b,c,pos1=0,pos2=0;
    int scanned = sscanf(ver,"%d.%d%n.%d%n",&a,&b,&pos1,&c,&pos2);
    if ((scanned == 3 && pos2 == (int)strlen(ver)) ||
        (scanned == 2 && pos1 == (int)strlen(ver))) {
        unsigned char hex = (a<<4) | b;
        unsigned int i;
        for (i=0; i<sizeof(redis2rdb)/sizeof(redis2rdb[0]); i++)
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
    for (int i = 0 ; i < RDB_DATA_TYPE_MAX ; ++i) {
        RDB_handleByLevel(p, (RdbDataType) i, lvl, 0);
    }

    /* librdb cannot parse a module object */
    RDB_handleByLevel(p, RDB_DATA_TYPE_MODULE, RDB_LEVEL_RAW, 0);
}

/*** Handling common ***/

static RdbRes toRespHandlingNewRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    resolveSupportRestore(p, ctx, rdbVersion);

    return RDB_OK;
}

static RdbRes toRespHandlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(info);
    RdbxToResp *ctx = (RdbxToResp *) userData;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);

    /* handling new key */
    ctx->keyCtx.info = *info;
    ctx->keyCtx.keyLen = RDB_bulkLen(p, key);
    if ( (ctx->keyCtx.key = RDB_bulkClone(p, key)) == NULL)
        return RDB_ERR_FAIL_ALLOC;
    return RDB_OK;
}

static RdbRes toRespHandlingEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toRespHandlingString(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;

    /* write SET */
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "*3\r\n$3\r\nSET\r\n", 0));

    /* write key */
    RETURN_ON_WRITE_ERR(writeStrLength(writer, '$', ctx->keyCtx.keyLen));
    RETURN_ON_WRITE_ERR(writer->write(writer->ctx, ctx->keyCtx.key, ctx->keyCtx.keyLen, 0));
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "\r\n", 0));

    /* write value */
    RETURN_ON_WRITE_ERR(writeStrLength(writer, '$', RDB_bulkLen(p, value)));
    RETURN_ON_WRITE_ERR(writer->writeBulk(writer->ctx, value, 0));
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "\r\n", 1));
    return RDB_OK;
}

static RdbRes toRespHandlingList (RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;

    /* write RPUSH */
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "*3\r\n$5\r\nRPUSH\r\n", 0));

    /* write key */
    writeStrLength(writer, '$', ctx->keyCtx.keyLen);
    writer->write(writer->ctx, ctx->keyCtx.key, ctx->keyCtx.keyLen, 0);
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "\r\n", 0));

    /* write value */
    writeStrLength(writer, '$', RDB_bulkLen(p, value));
    writer->writeBulk(writer->ctx, value, 0);
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "\r\n", 1));

    return RDB_OK;
}

/*** Handling raw ***/

static RdbRes toRespHandlingRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;

    /* write RESTORE */
    int numArgs = 4;
    char cmd[64];
    int cmdLen = sprintf(cmd, "*%d\r\n$7\r\nRESTORE\r\n", numArgs);
    RETURN_ON_WRITE_ERR(writer->write(writer->ctx, cmd, cmdLen, 0));

    /* write key */
    RETURN_ON_WRITE_ERR(writeStrLength(writer, '$', ctx->keyCtx.keyLen));
    RETURN_ON_WRITE_ERR(writer->write(writer->ctx, ctx->keyCtx.key, ctx->keyCtx.keyLen, 0));

    /* newline + write TTL */
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(writer, "\r\n$1\r\n0\r\n", 0));

    /* start write value by writing its length */
    RETURN_ON_WRITE_ERR(writeStrLength(writer, '$', size  + 10 /*footer*/));
    return RDB_OK;
}

static RdbRes toRespHandlingRawFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;
    ctx->crc = crc64(ctx->crc, (unsigned char *) frag, RDB_bulkLen(p, frag) );
    RETURN_ON_WRITE_ERR(ctx->respWriter.writeBulk(ctx->respWriter.ctx, frag, 0));
    return RDB_OK;
}

static RdbRes toRespHandlingRawFragEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;
    uint64_t *crc = &(ctx->crc);

    char footer[10];
    footer[0] = ctx->srcRdbVer & 0xff;
    footer[1] = (ctx->srcRdbVer >> 8) & 0xff;
    *crc = crc64(*crc, (unsigned char *) footer, 2);
    /* CRC64 */
    memrev64ifbe(crc);
    memcpy(footer+2, crc, 8);

    RETURN_ON_WRITE_ERR(writer->write(writer->ctx, footer, 10, 1));
    RETURN_ON_WRITE_ERR(WRITE_CONST_STR(&(ctx->respWriter), "\r\n", 1));
    return RDB_OK;
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConf *conf) {
    RdbxToResp *ctx;

    if ( (ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset (ctx, 0, sizeof(RdbxToResp));

    if (conf) {
        ctx->conf = *conf;
    } else {
        ctx->conf.supportRestore = 0;
    }
    ctx->refcount = 2;

    RdbHandlersDataCallbacks dataCb;
    memset (&dataCb, 0, sizeof(RdbHandlersDataCallbacks));
    dataCb.handleNewRdb = toRespHandlingNewRdb;
    dataCb.handleNewKey = toRespHandlingNewKey;
    dataCb.handleEndKey = toRespHandlingEndKey;
    dataCb.handleStringValue = toRespHandlingString;
    dataCb.handleListElement = toRespHandlingList;
    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToRespCtx);

    RdbHandlersRawCallbacks rawCb;
    memset (&rawCb, 0, sizeof(RdbHandlersRawCallbacks));
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