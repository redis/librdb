#include <string.h>
#include <assert.h>
#include "common.h"
#include "../../deps/redis/utils.h"

#define WRITE_CONST_STR(writer, str, endCmd) writer->write(writer->ctx, str, sizeof(str) - 1, endCmd)

struct RdbxToResp {
    RdbxToRespConfig config;

    RdbxRespWriter respWriter;
    int respWriterConfigured;

    RdbBulkCopy key;
    size_t keyLen;
    RdbKeyInfo info;
};

static void deleteRdbToRespCtx(RdbParser *p, void *context) {
    RdbxToResp *ctx = (RdbxToResp *) context;

    if (!ctx) return;

    if (ctx->key != NULL)
        RDB_bulkCopyFree(p, ctx->key);

    /* delete respWriter */
    if (ctx->respWriter.delete)
        ctx->respWriter.delete(ctx->respWriter.ctx);

    RDB_free(p, ctx);
}

static size_t writeStrLength(RdbxRespWriter *writer, char prefix, long count) {
    char cbuf[128];
    int clen;

    cbuf[0] = prefix;
    clen = 1+ll2string(cbuf+1,sizeof(cbuf)-1,count);
    cbuf[clen++] = '\r';
    cbuf[clen++] = '\n';
    if ((writer->write(writer->ctx, cbuf, clen, 0)) == 0 ) return 0;
    return clen;
}

static RdbRes toRespHandlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(info);
    RdbxToResp *ctx = (RdbxToResp *) userData;

    if (ctx->key != NULL)
        RDB_bulkCopyFree(p, ctx->key);

    ctx->keyLen = RDB_bulkLen(p, key);
    if ( (ctx->key = RDB_bulkClone(p, key)) == NULL)
        return RDB_ERR_FAIL_ALLOC;

    ctx->info = *info;
    return RDB_OK;
}

static RdbRes toRespHandlingString(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;

    /* write SET */
    WRITE_CONST_STR(writer, "*3\r\n$3\r\nSET\r\n", 0);

    /* write key */
    writeStrLength(writer, '$', ctx->keyLen);
    writer->write(writer->ctx, ctx->key, ctx->keyLen, 0);
    WRITE_CONST_STR(writer, "\r\n", 0);

    /* write value */
    writeStrLength(writer, '$', RDB_bulkLen(p, value));
    writer->writeBulk(writer->ctx, value, 0);
    WRITE_CONST_STR(writer, "\r\n", 1);
    return RDB_OK;
}

static RdbRes toRespHandlingNewRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = (RdbxToResp *) userData;

    printf ("RDB VERSION:%d\n", rdbVersion);

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    /* TODO: configure handlers based on rdbVersion vs Target rdb version */

    return RDB_OK;
}

static RdbRes toRespHandlingList (RdbParser *p, void *userData, RdbBulk value) {
    RdbxToResp *ctx = (RdbxToResp *) userData;
    RdbxRespWriter *writer = &ctx->respWriter;

    /* write RPUSH */
    WRITE_CONST_STR(writer, "*3\r\n$5\r\nRPUSH\r\n", 0);

    /* write key */
    writeStrLength(writer, '$', ctx->keyLen);
    writer->write(writer->ctx, ctx->key, ctx->keyLen, 0);
    WRITE_CONST_STR(writer, "\r\n", 0);

    /* write value */
    writeStrLength(writer, '$', RDB_bulkLen(p, value));
    writer->writeBulk(writer->ctx, value, 0);
    WRITE_CONST_STR(writer, "\r\n", 1);

    return RDB_OK;
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConfig *config) {
    //static int ssl_init = 0;
    RdbxToResp *ctx;

    if ( (ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset (ctx, 0, sizeof(RdbxToResp));

    ctx->key = NULL;

    if (config)
        ctx->config = *config;

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));
    callbacks.common.handleNewRdb = toRespHandlingNewRdb;
    callbacks.common.handleNewKey = toRespHandlingNewKey;
    callbacks.dataCb.handleStringValue = toRespHandlingString;
    callbacks.dataCb.handleListElement = toRespHandlingList;

    /* TODO: support also raw level and decide which level based on RDB vs. target version */
//    callbacks.rawCb.handleFrag = toRespHandlingFrag;
//    callbacks.rawCb.handleBegin = toRespHandlingRawBegin;
//    callbacks.rawCb.handleEnd = toRespHandlingRawEnd;
    RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteRdbToRespCtx);
    return ctx;
}

_LIBRDB_API void RDB_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer) {
    assert (rdbToResp->respWriterConfigured == 0);

    rdbToResp->respWriter = *writer;
    rdbToResp->respWriterConfigured = 1;
}