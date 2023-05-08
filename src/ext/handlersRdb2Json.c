#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "common.h"

struct Rdb2JsonCtx;

typedef void (*EncodingFunc)(struct Rdb2JsonCtx *ctx, char *p, size_t len);

typedef enum
{
    R2J_IDLE = 0,
    R2J_IN_DB,
    R2J_IN_KEY,

    /* Possible states in R2J_IN_KEY */
    R2J_IN_LIST,
    R2J_IN_SET,
    R2J_IN_STRING,
    R2J_IN_HASH,
    R2J_IN_ZSET
} Rdb2JsonState;

typedef struct Rdb2JsonConfig {
    char *filename;
    RdbxConvJsonEnc encoding;
} Rdb2JsonConfig;

typedef struct Rdb2JsonCtx {
    Rdb2JsonConfig conf;
    Rdb2JsonState state;
    FILE *outfile;
    EncodingFunc encfunc;

    struct {
        RdbBulkCopy key;
        RdbKeyInfo info;
    } keyCtx;

    unsigned int count_keys;
    unsigned int count_db;
} Rdb2JsonCtx;

#define ouput_fprintf(ctx, ...) fprintf(ctx->outfile, ##__VA_ARGS__);

static void outputPlainEscaping(Rdb2JsonCtx *ctx, char *p, size_t len) {
    while(len--) {
        switch(*p) {
            case '\\':
            case '"':
                ouput_fprintf(ctx, "\\%c", *p); break;
            case '\n': ouput_fprintf(ctx, "\\n"); break;
            case '\f': ouput_fprintf(ctx, "\\f"); break;
            case '\r': ouput_fprintf(ctx, "\\r"); break;
            case '\t': ouput_fprintf(ctx, "\\t"); break;
            case '\b': ouput_fprintf(ctx, "\\b"); break;
            default:
                // todo: formalize rdb2json supported outputs
                //ouput_fprintf(ctx, (*p >= 0 && *p <= 0x1f) ? "\\u%04x" : "%c",*p);
                ouput_fprintf(ctx, (isprint(*p)) ? "%c" : "\\x%02x", (unsigned char)*p);
        }
        p++;
    }
}

static void outputQuotedEscaping(Rdb2JsonCtx *ctx, char *data, size_t len) {
    ouput_fprintf(ctx, "\"");
    ctx->encfunc(ctx, data, len);
    ouput_fprintf(ctx, "\"");
}

static void deleteRdb2JsonCtx(RdbParser *p, void *data) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) data;
    if (ctx->outfile) fclose(ctx->outfile);
    RDB_free(p, ctx->conf.filename);
    RDB_free(p, ctx);
}

static Rdb2JsonCtx *initRdb2JsonCtx(RdbParser *p, RdbxConvJsonEnc encoding, const char *filename) {
    FILE *f;

    if (!(f = fopen(filename, "w"))) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_FAILED_OPEN_FILE,
                        "HandlersRdb2Json: Failed to open file");
        return NULL;
    }

    /* init Rdb2Json context */
    Rdb2JsonCtx *ctx = RDB_alloc(p, sizeof(Rdb2JsonCtx));
    ctx->conf.filename = RDB_alloc(p, strlen(filename)+1);
    strcpy(ctx->conf.filename, filename);
    ctx->outfile = f;
    ctx->state = R2J_IDLE;
    ctx->count_keys = 0;
    ctx->conf.encoding = encoding;
    switch(encoding) {
        case RDBX_CONV_JSON_ENC_PLAIN: ctx->encfunc = outputPlainEscaping; break;
        case RDBX_CONV_JSON_ENC_BASE64: /* todo: support base64 */
        default: assert(0); break;
    }

    return ctx;
}

/*** Handling common ***/

static RdbRes handlingAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;
    UNUSED(p);

    /* output json part */
    outputQuotedEscaping(ctx, auxkey, RDB_bulkLen(p, auxkey));
    ouput_fprintf(ctx, ":");
    outputQuotedEscaping(ctx, auxval, RDB_bulkLen(p, auxval));
    ouput_fprintf(ctx, ",\n");

    return RDB_OK;
}

static RdbRes handlingEndKey(RdbParser *p, void *userData) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    /* output json part */
    switch(ctx->state) {
        case R2J_IN_LIST:
        case R2J_IN_SET:
            ouput_fprintf(ctx, "]");
            break;
        case R2J_IN_HASH:
        case R2J_IN_ZSET:
            ouput_fprintf(ctx, "}");
            break;
        case R2J_IN_KEY:
        case R2J_IN_STRING:
            break; /* do nothing */
        default:
            RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                            "handlingEndKey(): Invalid state value: %d", ctx->state);
            return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    RDB_bulkFree(p, ctx->keyCtx.key);

    /* update new state */
    ctx->state = R2J_IN_DB;

    return RDB_OK;
}

static RdbRes handlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    if (ctx->state != R2J_IN_DB) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "handlingNewKey(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }
    ctx->keyCtx.key = RDB_bulkClone(p, key);
    ctx->keyCtx.info = *info;

    /* update new state */
    ctx->state = R2J_IN_KEY;

    /* output json part */
    ouput_fprintf(ctx, "%s    ", (++ctx->count_keys == 1) ? "" : ",\n");
    outputQuotedEscaping(ctx, key, RDB_bulkLen(p, key));
    ouput_fprintf(ctx, ":");

    return RDB_OK;
}

static RdbRes handlingNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(db);
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    if (ctx->state == R2J_IDLE) {
        ouput_fprintf(ctx, "[{\n");
    } else if (ctx->state == R2J_IN_DB) {
        /* output json part */
        ouput_fprintf(ctx, "},{\n");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "handlingNewDb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* update new state */
    ctx->state = R2J_IN_DB;
    ++ctx->count_db;
    ctx->count_keys = 0;
    return RDB_OK;
}

static RdbRes handlingEndRdb(RdbParser *p, void *userData) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    if (ctx->state != R2J_IN_DB) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "handlingEndRdb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    ouput_fprintf(ctx, "\n}]\n");

    /* update new state */
    ctx->state = R2J_IDLE;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes handlingString(RdbParser *p, void *userData, RdbBulk value) {
    UNUSED(p);
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    /* output json part */
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));

    return RDB_OK;
}

static RdbRes handlingList(RdbParser *p, void *userData, RdbBulk str) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    if (ctx->state == R2J_IN_KEY) {

        /* output json part */
        ouput_fprintf(ctx, "[");
        outputQuotedEscaping(ctx, str, RDB_bulkLen(p, str));

        /* update new state */
        ctx->state = R2J_IN_LIST;

    } else if (ctx->state == R2J_IN_LIST) {

        /* output json part */
        ouput_fprintf(ctx, ",");
        outputQuotedEscaping(ctx, str, RDB_bulkLen(p, str));

        /* state unchanged */

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "handlingList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

/*** Handling struct ***/

static RdbRes handlingQListNode(RdbParser *p, void *userData, RdbBulk listNode) {
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;

    if (ctx->state == R2J_IN_KEY) {

        /* output json part */
        ouput_fprintf(ctx, "[");
        outputQuotedEscaping(ctx, listNode, RDB_bulkLen(p, listNode));

        /* update new state */
        ctx->state = R2J_IN_LIST;

    } else if (ctx->state == R2J_IN_LIST) {

        /* output json part */
        ouput_fprintf(ctx, ",");
        outputQuotedEscaping(ctx, listNode, RDB_bulkLen(p, listNode));

        /* state unchanged */

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "handlingList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

/*** Handling raw ***/

static RdbRes handlingFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;
    /* output json part */
    ctx->encfunc(ctx, frag, RDB_bulkLen(p, frag));
    return RDB_OK;
}

static RdbRes handlingRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    UNUSED(size);
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;
    ouput_fprintf(ctx, "\"");
    return RDB_OK;
}

static RdbRes handlingRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    Rdb2JsonCtx *ctx = (Rdb2JsonCtx *) userData;
    ouput_fprintf(ctx, "\"");
    return RDB_OK;
}

RdbHandlers *RDBX_createHandlersRdb2Json(RdbParser *p, RdbxConvJsonEnc encoding, const char *filename, RdbHandlersLevel lvl) {
    Rdb2JsonCtx *ctx = initRdb2JsonCtx(p, encoding, filename);
    if (ctx == NULL) return NULL;

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));

    callbacks.common.handleAuxField = handlingAuxField;
    callbacks.common.handleNewKey = handlingNewKey;
    callbacks.common.handleEndKey = handlingEndKey;
    callbacks.common.handleNewDb = handlingNewDb;
    callbacks.common.handleEndRdb = handlingEndRdb;

    if (lvl == RDB_LEVEL_DATA) {
        callbacks.dataCb.handleStringValue = handlingString;
        callbacks.dataCb.handleListElement = handlingList;
        return RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteRdb2JsonCtx);
    }

    if (lvl == RDB_LEVEL_STRUCT) {
        callbacks.structCb.handleStringValue = handlingString;
        callbacks.structCb.handlerQListNode = handlingQListNode;
        callbacks.structCb.handlerPlainNode = handlingList;
        return RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteRdb2JsonCtx);
    }

    /* else (lvl == RDB_LEVEL_RAW) */
    callbacks.rawCb.handleFrag = handlingFrag;
    callbacks.rawCb.handleBegin = handlingRawBegin;
    callbacks.rawCb.handleEnd = handlingRawEnd;
    return RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteRdb2JsonCtx);
}
