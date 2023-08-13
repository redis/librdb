#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "common.h"

struct RdbxToJson;

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
} RdbxToJsonState;

struct RdbxToJson {
    char *filename;
    RdbxToJsonConf conf;
    RdbxToJsonState state;
    FILE *outfile;
    void (*encfunc)(struct RdbxToJson *ctx, char *p, size_t len);
    //EncodingFunc encfunc;

    struct {
        RdbBulkCopy key;
        RdbKeyInfo info;
    } keyCtx;

    unsigned int count_keys;
    unsigned int count_db;
};

#define ouput_fprintf(ctx, ...) fprintf(ctx->outfile, ##__VA_ARGS__)

static void outputPlainEscaping(RdbxToJson *ctx, char *p, size_t len) {
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
                /* TODO: formalize rdb2json supported outputs */
                //ouput_fprintf(ctx, (*p >= 0 && *p <= 0x1f) ? "\\u%04x" : "%c",*p);
                ouput_fprintf(ctx, (isprint(*p)) ? "%c" : "\\x%02x", (unsigned char)*p);
        }
        p++;
    }
}

static void outputQuotedEscaping(RdbxToJson *ctx, char *data, size_t len) {
    ouput_fprintf(ctx, "\"");
    ctx->encfunc(ctx, data, len);
    ouput_fprintf(ctx, "\"");
}

static void deleteRdbToJsonCtx(RdbParser *p, void *data) {
    RdbxToJson *ctx = (RdbxToJson *) data;

    if (ctx->keyCtx.key)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);

    RDB_log(p, RDB_LOG_DBG, "handlersToJson: Closing file %s", ctx->filename);

    if ((ctx->outfile) && (ctx->outfile != stdout))
        fclose(ctx->outfile);

    RDB_free(p, ctx->filename);
    RDB_free(p, ctx);
}

static RdbxToJson *initRdbToJsonCtx(RdbParser *p, const char *filename, RdbxToJsonConf *conf) {
    FILE *f;

    if (filename == NULL) {
        f = stdout;
        filename = "<stdout>";
    } else if (!(f = fopen(filename, "w"))) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_FAILED_OPEN_FILE,
                        "HandlersRdbToJson: Failed to open file");
        return NULL;
    }

    RDB_log(p, RDB_LOG_DBG, "handlersToJson: Opening file %s", filename);

    /* init RdbToJson context */
    RdbxToJson *ctx = RDB_alloc(p, sizeof(RdbxToJson));
    memset(ctx, 0, sizeof(RdbxToJson));
    ctx->filename = RDB_alloc(p, strlen(filename)+1);
    strcpy(ctx->filename, filename);
    ctx->outfile = f;
    ctx->state = R2J_IDLE;
    ctx->count_keys = 0;

    /* default configuration */
    ctx->conf.encoding = RDBX_CONV_JSON_ENC_PLAIN;
    ctx->conf.level = RDB_LEVEL_DATA;
    ctx->conf.skipAuxField = 0;

    /* override configuration if provided */
    if (conf) ctx->conf = *conf;

    switch(ctx->conf.encoding) {
        case RDBX_CONV_JSON_ENC_PLAIN: ctx->encfunc = outputPlainEscaping; break;
        case RDBX_CONV_JSON_ENC_BASE64: /* TODO: support base64 */
        default: assert(0); break;
    }

    return ctx;
}

/*** Handling common ***/

static RdbRes handlingAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    RdbxToJson *ctx = userData;
    UNUSED(p);

    /* output json part */
    outputQuotedEscaping(ctx, auxkey, RDB_bulkLen(p, auxkey));
    ouput_fprintf(ctx, ":");
    outputQuotedEscaping(ctx, auxval, RDB_bulkLen(p, auxval));
    ouput_fprintf(ctx, ",\n");

    return RDB_OK;
}

static RdbRes toJsonEndKey(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

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
                            "toJsonEndKey(): Invalid state value: %d", ctx->state);
            return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    /* update new state */
    ctx->state = R2J_IN_DB;

    return RDB_OK;
}

static RdbRes toJsonNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_DB) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonNewKey(): Invalid state value: %d", ctx->state);
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

static RdbRes toJsonNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(db);
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        if (!ctx->conf.flatten) ouput_fprintf(ctx, "{\n");
    } else if (ctx->state == R2J_IN_DB) {
        /* output json part */
        if (!ctx->conf.flatten) {
            ouput_fprintf(ctx, "\n},{\n");
        } else {
            ouput_fprintf(ctx, ",\n");
        }
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonNewDb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* update new state */
    ctx->state = R2J_IN_DB;
    ++ctx->count_db;
    ctx->count_keys = 0;
    return RDB_OK;
}

static RdbRes toJsonNewRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(rdbVersion);
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IDLE) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonNewRdb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (!ctx->conf.flatten) ouput_fprintf(ctx, "[");

    return RDB_OK;
}

static RdbRes toJsonEndRdb(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        RDB_log(p, RDB_LOG_WRN, "RDB is empty.");
    } else if (ctx->state == R2J_IN_DB) {
        if (!ctx->conf.flatten) ouput_fprintf(ctx, "\n}");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonEndRdb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (!ctx->conf.flatten) ouput_fprintf(ctx, "]\n");

    /* update new state */
    ctx->state = R2J_IDLE;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toJsonString(RdbParser *p, void *userData, RdbBulk string) {
    UNUSED(p);
    RdbxToJson *ctx = userData;

    /* output json part */
    outputQuotedEscaping(ctx, string, RDB_bulkLen(p, string));

    return RDB_OK;
}

static RdbRes toJsonList(RdbParser *p, void *userData, RdbBulk item) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_KEY) {

        /* output json part */
        ouput_fprintf(ctx, "[");
        outputQuotedEscaping(ctx, item, RDB_bulkLen(p, item));

        /* update new state */
        ctx->state = R2J_IN_LIST;

    } else if (ctx->state == R2J_IN_LIST) {

        /* output json part */
        ouput_fprintf(ctx, ",");
        outputQuotedEscaping(ctx, item, RDB_bulkLen(p, item));

        /* state unchanged */

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

static RdbRes toJsonSet(RdbParser *p, void *userData, RdbBulk member) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_KEY) {

        /* output json part */
        ouput_fprintf(ctx, "[");
        outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));

        /* update new state */
        ctx->state = R2J_IN_SET;

    } else if (ctx->state == R2J_IN_SET) {

        /* output json part */
        ouput_fprintf(ctx, ",");
        outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));

        /* state unchanged */

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonSet(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

static RdbRes toJsonHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_KEY) {

        /* output json part */
        ouput_fprintf(ctx, "{");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        ouput_fprintf(ctx, ":");
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
        /* update new state */
        ctx->state = R2J_IN_HASH;
    } else if (ctx->state == R2J_IN_HASH) {
        /* output json part */
        ouput_fprintf(ctx, ",");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        ouput_fprintf(ctx, ":");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

/*** Handling struct ***/

static RdbRes toJsonStruct(RdbParser *p, void *userData, RdbBulk value) {
    UNUSED(p);
    RdbxToJson *ctx = userData;

    /* output json part */
    ouput_fprintf(ctx, "[");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    ouput_fprintf(ctx, "]");

    return RDB_OK;
}

/*** Handling raw ***/

static RdbRes toJsonFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    RdbxToJson *ctx = userData;
    /* output json part */
    ctx->encfunc(ctx, frag, RDB_bulkLen(p, frag));
    return RDB_OK;
}

static RdbRes toJsonRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    UNUSED(size);
    RdbxToJson *ctx = userData;
    ouput_fprintf(ctx, "\"");
    return RDB_OK;
}

static RdbRes toJsonRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToJson *ctx = userData;
    ouput_fprintf(ctx, "\"");
    return RDB_OK;
}

RdbxToJson *RDBX_createHandlersToJson(RdbParser *p, const char *filename, RdbxToJsonConf *conf) {
    RdbxToJson *ctx = initRdbToJsonCtx(p, filename, conf);
    if (ctx == NULL) return NULL;

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));

    if (!(ctx->conf.skipAuxField))
        callbacks.common.handleAuxField = handlingAuxField;

    callbacks.common.handleNewKey = toJsonNewKey;
    callbacks.common.handleEndKey = toJsonEndKey;
    callbacks.common.handleNewDb = toJsonNewDb;
    callbacks.common.handleStartRdb = toJsonNewRdb;
    callbacks.common.handleEndRdb = toJsonEndRdb;

    if (ctx->conf.level == RDB_LEVEL_DATA) {
        callbacks.dataCb.handleStringValue = toJsonString;
        callbacks.dataCb.handleListItem = toJsonList;
        callbacks.dataCb.handleHashField = toJsonHash;
        callbacks.dataCb.handleSetMember = toJsonSet;
        RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteRdbToJsonCtx);
    } else  if (ctx->conf.level == RDB_LEVEL_STRUCT) {
        callbacks.structCb.handleString = toJsonString;
        /* list */
        callbacks.structCb.handleListPlain = toJsonList;
        callbacks.structCb.handleListLP = toJsonStruct;
        callbacks.structCb.handleListZL = toJsonStruct;
        /* hash */
        callbacks.structCb.handleHashPlain = toJsonHash;
        callbacks.structCb.handleHashZL = toJsonStruct;
        callbacks.structCb.handleHashLP = toJsonStruct;
        callbacks.structCb.handleHashZM = toJsonStruct;
        /* set */
        callbacks.structCb.handleSetPlain = toJsonSet;
        callbacks.structCb.handleSetIS = toJsonStruct;
        callbacks.structCb.handleSetLP = toJsonStruct;
        RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteRdbToJsonCtx);
    } else if (ctx->conf.level == RDB_LEVEL_RAW) {
        callbacks.rawCb.handleFrag = toJsonFrag;
        callbacks.rawCb.handleBegin = toJsonRawBegin;
        callbacks.rawCb.handleEnd = toJsonRawEnd;
        RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteRdbToJsonCtx);
    }

    return ctx;
}
