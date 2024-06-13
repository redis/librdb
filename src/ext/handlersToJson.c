#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "common.h"
#include "../../deps/redis/util.h"

struct RdbxToJson;

#define _STDOUT_STR "<stdout>"

typedef enum
{
    R2J_IDLE = 0,
    R2J_AUX_FIELDS,
    R2J_FUNCTIONS,

    R2J_IN_DB,
    R2J_IN_KEY,

    /* Possible states in R2J_IN_KEY */
    R2J_IN_LIST,
    R2J_IN_SET,
    R2J_IN_STRING,
    R2J_IN_HASH,
    R2J_IN_ZSET,

    /* Possible states in R2J_IN_STREAM */
    R2J_IN_STREAM,
    R2J_IN_STREAM_ENTRIES,
    R2J_IN_STREAM_ENTRIES_PAIRS,
    R2J_IN_STREAM_CG,
    R2J_IN_STREAM_CG_PEL,
    R2J_IN_STREAM_CG_CONSUMER,
    R2J_IN_STREAM_CG_CONSUMER_PEL,

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

const char *jsonMetaPrefix = "__";  /* Distinct meta from data with prefix string. */

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
                fprintf(ctx->outfile, (isprint(*p)) ? "%c" : "\\u%04x", (unsigned char)*p);
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
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_FILE,
                        "HandlersRdbToJson: Failed to open file. errno=%d: %s", errno, strerror(errno));
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
    ctx->conf.includeStreamMeta = 0;
    ctx->conf.includeDbInfo = 0;

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

static RdbRes toJsonDbSize(RdbParser *p, void *userData, uint64_t db_size, uint64_t exp_size) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_DB) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonDbSize(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    fprintf(ctx->outfile, "    \"__dbsize__\": {\n");
    fprintf(ctx->outfile, "      \"size\": %" PRIu64 ",\n", db_size);
    fprintf(ctx->outfile, "      \"expires\": %" PRIu64 "\n", exp_size);
    fprintf(ctx->outfile, "    }%s\n", (db_size) ? "," : "");

    return RDB_OK;
}

static RdbRes toJsonSlotInfo(RdbParser *p, void *userData, RdbSlotInfo *info) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_DB) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonSlotInfo(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    fprintf(ctx->outfile, "    \"__slotinfo__\": {\n");
    fprintf(ctx->outfile, "      \"slotId\": %lu,\n", info->slot_id);
    fprintf(ctx->outfile, "      \"slotSize\": %lu,\n", info->slot_size);
    fprintf(ctx->outfile, "      \"slotSExpiresSize\": %lu\n", info->expires_slot_size);
    fprintf(ctx->outfile, "    },\n");
    return RDB_OK;
}

static RdbRes toJsonAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        ctx->state = R2J_AUX_FIELDS;
        fprintf(ctx->outfile, "\"__aux__\" : {\n    "); /* group aux-fields with { ... } */
    } else if (ctx->state == R2J_AUX_FIELDS) {
        fprintf(ctx->outfile, ",\n    ");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonAuxField(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    outputQuotedEscaping(ctx, auxkey, RDB_bulkLen(p, auxkey));
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, auxval, RDB_bulkLen(p, auxval));

    return RDB_OK;
}

static RdbRes toJsonEndKey(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    /* output json part */
    switch(ctx->state) {
        case R2J_IN_STREAM:
            fprintf(ctx->outfile, "\n   }");
            break;
        case R2J_IN_STREAM_ENTRIES:
            fprintf(ctx->outfile, "\n   ]}");
            break;
        case R2J_IN_STREAM_CG:
            fprintf(ctx->outfile, "}]}");
            break;
        case R2J_IN_STREAM_CG_PEL:
            fprintf(ctx->outfile, "]}]}");
            break;
        case R2J_IN_STREAM_CG_CONSUMER:
            fprintf(ctx->outfile, "}]}]}");
            break;
        case R2J_IN_STREAM_CG_CONSUMER_PEL:
            fprintf(ctx->outfile, "]}]}]}");
            break;

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
        /* old RDBs might not have aux-fields */
        if (!ctx->conf.flatten) fprintf(ctx->outfile, "{\n");
    } else if (ctx->state == R2J_AUX_FIELDS || ctx->state == R2J_FUNCTIONS) {
        fprintf(ctx->outfile, "\n},\n");
        if (!ctx->conf.flatten) fprintf(ctx->outfile, "{\n");
    } else if (ctx->state == R2J_IN_DB) {
        /* output json part */
        if (ctx->conf.flatten) {
            fprintf(ctx->outfile, ",\n");
        } else {
            fprintf(ctx->outfile, "\n},{\n");
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
    } else if (ctx->state == R2J_AUX_FIELDS || ctx->state == R2J_FUNCTIONS) {
        fprintf(ctx->outfile, "\n},\n");
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

static RdbRes toJsonZset(RdbParser *p, void *userData, RdbBulk member, double score) {
    RdbxToJson *ctx = userData;

    char scoreStr[MAX_D2STRING_CHARS];
    int len = d2string(scoreStr, sizeof(scoreStr), score);

    /* -0 is a valid double, but we want to output it as 0 */
    if ((len == 2) && (scoreStr[0] == '-') && (scoreStr[1] == '0')) {
        scoreStr[0] = '0';
        scoreStr[1] = '\0';
    }

    if (ctx->state == R2J_IN_KEY) {
        /* output json part */
        fprintf(ctx->outfile, "{");
        outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));
        fprintf(ctx->outfile, ":\"%.*s\"", len, scoreStr);

        /* update new state */
        ctx->state = R2J_IN_ZSET;

    } else if (ctx->state == R2J_IN_ZSET) {
        /* output json part */
        fprintf(ctx->outfile, ",");
        outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));
        fprintf(ctx->outfile, ":\"%.*s\"", len, scoreStr);

        /* state unchanged */

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonZset(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

static RdbRes toJsonHash(RdbParser *p, void *userData, RdbBulk field,
                         RdbBulk value, int64_t expireAt)
{
    UNUSED(expireAt);
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
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonList(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    return RDB_OK;
}

static RdbRes toJsonFunction(RdbParser *p, void *userData, RdbBulk func) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        ctx->state = R2J_FUNCTIONS;
        fprintf(ctx->outfile, "\"__func__\": {\n");
    } else if (ctx->state == R2J_AUX_FIELDS) {
        fprintf(ctx->outfile, "\n},\n \"__func__\": {\n");
        ctx->state = R2J_FUNCTIONS;
    } else if (ctx->state == R2J_FUNCTIONS) {
        fprintf(ctx->outfile, ",\n");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonFunction(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    /* output json part */
    fprintf(ctx->outfile, "    \"%sFunction_%d\":", jsonMetaPrefix, ++ctx->count_functions);
    outputQuotedEscaping( (RdbxToJson *) userData, func, RDB_bulkLen(p, func));
    ctx->count_functions++;
    return RDB_OK;
}

static RdbRes toJsonStreamItem(RdbParser *p, void *userData, RdbStreamID *id, RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    RdbxToJson *ctx = userData;

    if ( (ctx->state == R2J_IN_KEY) || (ctx->state == R2J_IN_STREAM_ENTRIES)) {
        /* start of stream array of entries */
        if (ctx->state == R2J_IN_KEY)
            fprintf(ctx->outfile, "{\n      \"entries\":[");

        /* output another stream entry */
        fprintf(ctx->outfile, "%c\n        { \"id\":\"%lu-%lu\", ",
                (ctx->state == R2J_IN_STREAM_ENTRIES) ? ',' : ' ',
                id->ms, id->seq );
        fprintf(ctx->outfile, "\"items\":{");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        fprintf(ctx->outfile, ":");
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    } else if (ctx->state == R2J_IN_STREAM_ENTRIES_PAIRS) {
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        fprintf(ctx->outfile, ":");
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamItem(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (itemsLeft) {
        fprintf(ctx->outfile, ", ");
        ctx->state = R2J_IN_STREAM_ENTRIES_PAIRS;
    } else {
        fprintf(ctx->outfile, "} }");
        ctx->state = R2J_IN_STREAM_ENTRIES;
    }
    return RDB_OK;
}

static RdbRes toJsonStreamMetadata(RdbParser *p, void *userData, RdbStreamMeta *meta) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_KEY) /* no entries recorded. place empty array */
        fprintf(ctx->outfile, "{\n      \"entries\":[");
    else if (ctx->state != R2J_IN_STREAM_ENTRIES) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamMetadata(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }
    ctx->state = R2J_IN_STREAM;
    fprintf(ctx->outfile, "],\n      \"length\": %lu, ", meta->length);
    fprintf(ctx->outfile, "\n      \"entriesAdded\": %lu, ", meta->entriesAdded);
    fprintf(ctx->outfile, "\n      \"firstID\": \"%lu-%lu\", ", meta->firstID.ms, meta->firstID.seq);
    fprintf(ctx->outfile, "\n      \"lastID\": \"%lu-%lu\", ", meta->lastID.ms, meta->lastID.seq);
    fprintf(ctx->outfile, "\n      \"maxDelEntryID\": \"%lu-%lu\",", meta->maxDelEntryID.ms, meta->maxDelEntryID.seq);
    return RDB_OK;
}

static RdbRes toJsonStreamNewCGroup(RdbParser *p, void *userData, RdbBulk grpName, RdbStreamGroupMeta *meta) {
    RdbxToJson *ctx = userData;
    char *prefix;
    if (ctx->state == R2J_IN_STREAM) {
        prefix = "\n      \"groups\": [\n";
    } else if (ctx->state == R2J_IN_STREAM_CG) {
        prefix = "},\n";
    } else if (ctx->state == R2J_IN_STREAM_CG_PEL) {
        prefix = "]},\n";
    } else if (ctx->state == R2J_IN_STREAM_CG_CONSUMER_PEL) {
        prefix = "]}]},\n";
    } else if (ctx->state == R2J_IN_STREAM_CG_CONSUMER) {
        prefix = "}]},\n";
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamNewCGroup(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }
    fprintf(ctx->outfile, "%s        {\"name\": \"%s\", \"lastid\": \"%lu-%lu\", \"entriesRead\": %lu",
            prefix, grpName, meta->lastId.ms, meta->lastId.seq, meta->entriesRead);

    ctx->state = R2J_IN_STREAM_CG;
    return RDB_OK;
}

static RdbRes toJsonStreamCGroupPendingEntry(RdbParser *p, void *userData, RdbStreamPendingEntry *pe) {
    char *prefix;
    RdbxToJson *ctx = userData;
    if (ctx->state == R2J_IN_STREAM_CG) {
        ctx->state = R2J_IN_STREAM_CG_PEL;
        prefix = ",\n         \"pending\": [ ";
    } else if (ctx->state == R2J_IN_STREAM_CG_PEL) {
        prefix = ", ";
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamCGroupPendingEntry(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }
    fprintf(ctx->outfile, "%s\n           { \"sent\": %lu, \"id\":\"%lu-%lu\", \"count\": %lu }",
            prefix, pe->deliveryTime, pe->id.ms, pe->id.seq, pe->deliveryCount);
    return RDB_OK;
}

static RdbRes toJsonStreamNewConsumer(RdbParser *p, void *userData, RdbBulk consName, RdbStreamConsumerMeta *meta) {
    RdbxToJson *ctx = userData;
    char *prefix ="";

    if (ctx->state == R2J_IN_STREAM_CG) {
        prefix = ",\n         \"consumers\"";
    } else if (ctx->state == R2J_IN_STREAM_CG_PEL) {
        /* close pending entries array */
        prefix = "],\n         \"consumers\": [";
    } else if (ctx->state == R2J_IN_STREAM_CG_CONSUMER) {
        prefix = "}, ";
    } else if (ctx->state == R2J_IN_STREAM_CG_CONSUMER_PEL) {
        prefix = "]}, "; /* take care to close previous cons + cons PEL */
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamNewConsumer(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    ctx->state = R2J_IN_STREAM_CG_CONSUMER;
    fprintf(ctx->outfile, "%s\n           { \"name\": \"%s\", \"activeTime\": %llu, \"seenTime\": %llu",
            prefix, consName, meta->activeTime, meta->seenTime);

    return RDB_OK;
}

static RdbRes toJsonStreamConsumerPendingEntry(RdbParser *p, void *userData, RdbStreamID *streamId) {
    UNUSED(p);
    RdbxToJson *ctx = userData;
    char *prefix;
    if (ctx->state == R2J_IN_STREAM_CG_CONSUMER) {
        prefix = ",\n             \"pending\": [";

    } if (ctx->state == R2J_IN_STREAM_CG_CONSUMER_PEL) {
        prefix = ", ";
    }

    ctx->state = R2J_IN_STREAM_CG_CONSUMER_PEL;
    fprintf(ctx->outfile, "%s\n               {\"id\":\"%lu-%lu\"}", prefix, streamId->ms, streamId->seq);
    return RDB_OK;
}

/*** Handling struct ***/

static RdbRes toJsonStruct(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToJson *ctx = userData;

    /* output json part */
    fprintf(ctx->outfile, "[");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    fprintf(ctx->outfile, "]");

    return RDB_OK;
}

static RdbRes toJsonStreamLP(RdbParser *p, void *userData, RdbBulk nodekey, RdbBulk streamLP) {
    RdbxToJson *ctx = userData;

    /* output json part */
    fprintf(ctx->outfile, "{");
    outputQuotedEscaping(ctx, nodekey, RDB_bulkLen(p, nodekey));
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, streamLP, RDB_bulkLen(p, streamLP));
    fprintf(ctx->outfile, "}");

    return RDB_OK;
}

/*** Handling raw ***/

static RdbRes toJsonFrag(RdbParser *p, void *userData, RdbBulk frag) {
    RdbxToJson *ctx = userData;
    /* output json part */
    ctx->encfunc(ctx, frag, RDB_bulkLen(p, frag));
    return RDB_OK;
}

static RdbRes toJsonRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p, size);
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

    if (ctx->conf.level == RDB_LEVEL_DATA) {

        RdbHandlersDataCallbacks dataCb = {
                toJsonNewRdb,
                toJsonEndRdb,
                toJsonNewDb,
                NULL, /*handleDbSize*/
                NULL, /*handleSlotInfo*/
                NULL, /*handleAuxField*/
                toJsonNewKey,
                toJsonEndKey,
                toJsonString,
                toJsonList,
                toJsonHash,
                toJsonSet,
                toJsonZset,
                NULL, /* handleFunction */
                toJsonModule,
                NULL, /*handleStreamMetadata*/
                toJsonStreamItem,
                NULL, /* handleStreamNewCGroup */
                NULL, /* handleStreamCGroupPendingEntry */
                NULL, /* handleStreamNewConsumer */
                NULL, /* handleStreamConsumerPendingEntry */
        };

        if (ctx->conf.includeAuxField)
            dataCb.handleAuxField = toJsonAuxField;

        if (ctx->conf.includeFunc)
            dataCb.handleFunction = toJsonFunction;

        if (ctx->conf.includeStreamMeta) {
            dataCb.handleStreamMetadata = toJsonStreamMetadata;
            dataCb.handleStreamNewCGroup = toJsonStreamNewCGroup;
            dataCb.handleStreamCGroupPendingEntry = toJsonStreamCGroupPendingEntry;
            dataCb.handleStreamNewConsumer = toJsonStreamNewConsumer;
            dataCb.handleStreamConsumerPendingEntry = toJsonStreamConsumerPendingEntry;
        }

        if (ctx->conf.includeDbInfo) {
            dataCb.handleDbSize = toJsonDbSize;
            dataCb.handleSlotInfo = toJsonSlotInfo;
        }

        RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToJsonCtx);

    } else  if (ctx->conf.level == RDB_LEVEL_STRUCT) {
        RdbHandlersStructCallbacks structCb = {
                toJsonNewRdb,
                toJsonEndRdb,
                toJsonNewDb,
                NULL, /*handleDbSize*/
                NULL, /*handleSlotInfo*/
                NULL, /*handleAuxField*/
                toJsonNewKey,
                toJsonEndKey,
                toJsonString,
                /*list*/
                toJsonList,
                toJsonStruct, /* handleListZL*/
                toJsonStruct, /* handleListLP*/
                /*hash*/
                toJsonHash,   /*handleHashPlain*/
                toJsonStruct, /*handleHashZL*/
                toJsonStruct, /*handleHashLP*/
                toJsonStruct, /*handleHashLPEx*/
                toJsonStruct, /*handleHashZM*/
                /*set*/
                toJsonSet,
                toJsonStruct, /* handleSetIS*/
                toJsonStruct, /* handleSetLP*/
                /*zset*/
                toJsonZset,
                toJsonStruct, /* handleZsetZL*/
                toJsonStruct, /* handleZsetLP*/
                /*function*/
                NULL, /* handleFunction */
                /*module*/
                toJsonModule,
                /*stream*/
                toJsonStreamLP,
        };

        if (ctx->conf.includeAuxField)
            structCb.handleAuxField = toJsonAuxField;

        if (ctx->conf.includeFunc)
            structCb.handleFunction = toJsonFunction;

        RDB_createHandlersStruct(p, &structCb, ctx, deleteRdbToJsonCtx);

    } else if (ctx->conf.level == RDB_LEVEL_RAW) {
        RdbHandlersRawCallbacks rawCb = {
                toJsonNewRdb,
                toJsonEndRdb,
                toJsonNewDb,
                NULL, /*handleDbSize*/
                NULL, /*handleSlotInfo*/
                NULL, /*handleAuxField*/
                toJsonNewKey,
                toJsonEndKey,
                NULL, /*handleBeginModuleAux*/
                toJsonRawBegin,
                toJsonFrag,
                toJsonRawEnd,
        };

        if (ctx->conf.includeAuxField)
            rawCb.handleAuxField = toJsonAuxField;

        RDB_createHandlersRaw(p, &rawCb, ctx, deleteRdbToJsonCtx);

    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_LEVEL,
                        "RDBX_createHandlersToJson(): Invalid level value: %d", ctx->conf.level);
        return NULL;
    }

    return ctx;
}
