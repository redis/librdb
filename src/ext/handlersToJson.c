#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "common.h"

struct RdbxToJson;

#define _RDB_TYPE_MODULE_2 7
#define _STDOUT_STR "<stdout>"

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
    RdbxToJsonConf conf;
    RdbxToJsonState state;

    char *outfileName;  /* Holds output filename or equals _STDOUT_STR */
    FILE *outfile;

    void (*encfunc)(struct RdbxToJson *ctx, char *p, size_t len);

    struct {
        RdbBulkCopy key;
        RdbKeyInfo info;
    } keyCtx;

    unsigned int count_keys;
    unsigned int count_functions;
    unsigned int count_db;
};

static void outputPlainEscaping(RdbxToJson *ctx, char *p, size_t len) {
    while(len--) {
        switch(*p) {
            case '\\':
            case '"':
                fprintf(ctx->outfile, "\\%c", *p); break;
            case '\n': fprintf(ctx->outfile, "\\n"); break;
            case '\f': fprintf(ctx->outfile, "\\f"); break;
            case '\r': fprintf(ctx->outfile, "\\r"); break;
            case '\t': fprintf(ctx->outfile, "\\t"); break;
            case '\b': fprintf(ctx->outfile, "\\b"); break;
            default:
                /* TODO: formalize rdb2json supported outputs */
                //fprintf(ctx->outfile, (*p >= 0 && *p <= 0x1f) ? "\\u%04x" : "%c",*p);
                fprintf(ctx->outfile, (isprint(*p)) ? "%c" : "\\x%02x", (unsigned char)*p);
        }
        p++;
    }
}

static void outputQuotedEscaping(RdbxToJson *ctx, char *data, size_t len) {
    fprintf(ctx->outfile, "\"");
    ctx->encfunc(ctx, data, len);
    fprintf(ctx->outfile, "\"");
}

static void deleteRdbToJsonCtx(RdbParser *p, void *data) {
    RdbxToJson *ctx = (RdbxToJson *) data;

    if (ctx->keyCtx.key)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);

    RDB_log(p, RDB_LOG_DBG, "handlersToJson: Closing file %s", ctx->outfileName);

    if ((ctx->outfile) && (ctx->outfile != stdout))
        fclose(ctx->outfile);

    RDB_free(p, ctx->outfileName);
    RDB_free(p, ctx);
}

static RdbxToJson *initRdbToJsonCtx(RdbParser *p, const char *outfilename, RdbxToJsonConf *conf) {
    FILE *f;

    if (outfilename == NULL) {
        f = stdout;
        outfilename = _STDOUT_STR;
    } else if (!(f = fopen(outfilename, "w"))) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_FAILED_OPEN_FILE,
                        "HandlersRdbToJson: Failed to open file");
        return NULL;
    }

    RDB_log(p, RDB_LOG_DBG, "handlersToJson: Opening file %s", outfilename);

    /* init RdbToJson context */
    RdbxToJson *ctx = RDB_alloc(p, sizeof(RdbxToJson));
    memset(ctx, 0, sizeof(RdbxToJson));
    ctx->outfileName = RDB_alloc(p, strlen(outfilename) + 1);
    strcpy(ctx->outfileName, outfilename);
    ctx->outfile = f;
    ctx->state = R2J_IDLE;
    ctx->count_keys = 0;
    ctx->count_functions = 0;

    /* default configuration */
    ctx->conf.encoding = RDBX_CONV_JSON_ENC_PLAIN;
    ctx->conf.level = RDB_LEVEL_DATA;
    ctx->conf.includeAuxField = 0;
    ctx->conf.includeFunc = 0;

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
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, auxval, RDB_bulkLen(p, auxval));
    fprintf(ctx->outfile, ",\n");

    return RDB_OK;
}

static RdbRes toJsonEndKey(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    /* output json part */
    switch(ctx->state) {
        case R2J_IN_LIST:
        case R2J_IN_SET:
            fprintf(ctx->outfile, "]");
            break;
        case R2J_IN_HASH:
        case R2J_IN_ZSET:
            fprintf(ctx->outfile, "}");
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

    if (unlikely(ctx->state != R2J_IN_DB)) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonNewKey(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    ctx->keyCtx.key = RDB_bulkClone(p, key);
    ctx->keyCtx.info = *info;

    /* update new state */
    ctx->state = R2J_IN_KEY;

    /* output json part */
    fprintf(ctx->outfile, "%s    ", (++ctx->count_keys == 1) ? "" : ",\n");
    outputQuotedEscaping(ctx, key, RDB_bulkLen(p, key));
    fprintf(ctx->outfile, ":");

    return RDB_OK;
}

static RdbRes toJsonNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(db);
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        if (!ctx->conf.flatten) fprintf(ctx->outfile, "{\n");
    } else if (ctx->state == R2J_IN_DB) {
        /* output json part */
        if (!ctx->conf.flatten) {
            fprintf(ctx->outfile, "\n},{\n");
        } else {
            fprintf(ctx->outfile, ",\n");
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

    if (!ctx->conf.flatten) fprintf(ctx->outfile, "[");

    return RDB_OK;
}

static RdbRes toJsonEndRdb(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        RDB_log(p, RDB_LOG_WRN, "RDB is empty.");
    } else if (ctx->state == R2J_IN_DB) {
        if (!ctx->conf.flatten) fprintf(ctx->outfile, "\n}");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonEndRdb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (!ctx->conf.flatten) fprintf(ctx->outfile, "]\n");

    /* update new state */
    ctx->state = R2J_IDLE;

    return RDB_OK;
}

static RdbRes toJsonModule(RdbParser *p, void *userData, RdbBulk moduleName, size_t serializedSize) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_KEY) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonNewRdb(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    fprintf(ctx->outfile, "\"<Content of Module '%s'. Occupies a serialized size of %ld bytes>\"",
            moduleName,
            serializedSize);

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
        fprintf(ctx->outfile, "[");
        outputQuotedEscaping(ctx, item, RDB_bulkLen(p, item));

        /* update new state */
        ctx->state = R2J_IN_LIST;

    } else if (ctx->state == R2J_IN_LIST) {

        /* output json part */
        fprintf(ctx->outfile, ",");
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
        fprintf(ctx->outfile, "[");
        outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));

        /* update new state */
        ctx->state = R2J_IN_SET;

    } else if (ctx->state == R2J_IN_SET) {

        /* output json part */
        fprintf(ctx->outfile, ",");
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
        fprintf(ctx->outfile, "{");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        fprintf(ctx->outfile, ":");
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
        /* update new state */
        ctx->state = R2J_IN_HASH;
    } else if (ctx->state == R2J_IN_HASH) {
        /* output json part */
        fprintf(ctx->outfile, ",");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        fprintf(ctx->outfile, ":");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

static RdbRes toJsonFunction(RdbParser *p, void *userData, RdbBulk func) {
    RdbxToJson *ctx = userData;
    /* output json part */
    fprintf(ctx->outfile, "    \"Function_%d\":", ++ctx->count_functions);
    outputQuotedEscaping( (RdbxToJson *) userData, func, RDB_bulkLen(p, func));
    fprintf(ctx->outfile, ",\n");
    return RDB_OK;
}

/*** Handling struct ***/

static RdbRes toJsonStruct(RdbParser *p, void *userData, RdbBulk value) {
    UNUSED(p);
    RdbxToJson *ctx = userData;

    /* output json part */
    fprintf(ctx->outfile, "[");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    fprintf(ctx->outfile, "]");

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
    fprintf(ctx->outfile, "\"");
    return RDB_OK;
}

static RdbRes toJsonRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToJson *ctx = userData;
    fprintf(ctx->outfile, "\"");
    return RDB_OK;
}

RdbxToJson *RDBX_createHandlersToJson(RdbParser *p, const char *filename, RdbxToJsonConf *conf) {
    RdbxToJson *ctx = initRdbToJsonCtx(p, filename, conf);
    if (ctx == NULL) return NULL;

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));

    if (ctx->conf.includeAuxField)
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
        callbacks.dataCb.handleFunction = (conf->includeFunc) ? toJsonFunction : NULL;
        callbacks.dataCb.handleModule = toJsonModule;
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
        /* function */
        callbacks.structCb.handleFunction = (conf->includeFunc) ? toJsonFunction : NULL;
        /* module */
        callbacks.structCb.handleModule = toJsonModule;
        RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteRdbToJsonCtx);

    } else if (ctx->conf.level == RDB_LEVEL_RAW) {

        callbacks.rawCb.handleFrag = toJsonFrag;
        callbacks.rawCb.handleBegin = toJsonRawBegin;
        callbacks.rawCb.handleEnd = toJsonRawEnd;
        RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteRdbToJsonCtx);
    }

    return ctx;
}
