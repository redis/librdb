#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "extCommon.h"
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

    R2J_IN_STREAM,  /* value is a stream; ctx->streamState tracks the phase within it */

    R2J_IN_ARRAY, /*(v14+)*/

} RdbxToJsonState;

/* Sub-state while state == R2J_IN_STREAM. The stream is emitted in phases:
 * its entries, then metadata scalars, then the groups/idmp subtree (whose
 * nesting is tracked by the container stack, not by these values). */
typedef enum
{
    R2J_STREAM_ENTRIES,       /* between entries (entries array open)          */
    R2J_STREAM_ENTRY_FIELDS,  /* mid-entry, appending field:value to "items"   */
    R2J_STREAM_META,          /* entries closed, awaiting groups/idmp          */
    R2J_STREAM_SUBTREE,       /* inside the groups/idmp subtree (stack-tracked)*/
} RdbxStreamState;

/* Nesting levels of a key's value containers, outer (small) to inner (large).
 * Only the ordinal matters: jUnwindTo(level) closes every open container whose
 * level is >= the requested one, so toJsonEndKey just unwinds to 0. Siblings
 * that never coexist on the stack (e.g. "entries"/"groups"/"idmp", or a group's
 * "pending"/"consumers"/"nacked") share a level. */
enum {
    JLVL1_VALUE = 1,                       /* the key's top-level container: list/set/hash/zset/array/stream object */
    JLVL2_ENTRIES = 2, JLVL2_GROUPS = 2, JLVL2_IDMP = 2, /* direct children of the value */
    JLVL3_GROUP = 3,  JLVL3_PRODUCERS = 3,
    JLVL4_GPEL = 4,   JLVL4_NACKED = 4, JLVL4_CONSUMERS = 4, JLVL4_PRODUCER = 4,
    JLVL5_CONSUMER = 5, JLVL5_PENTRIES = 5,
    JLVL6_CPEL = 6,
};

struct RdbxToJson {
    RdbxToJsonConf conf;
    RdbxToJsonState state;
    RdbxStreamState streamState;  /* phase within a stream; valid while state == R2J_IN_STREAM */

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

    /* Stack of open JSON containers for the current key's value. Each opener
     * records the string that closes it (a literal, e.g. "]" or "]}"); the
     * opening bracket itself is part of the caller's own output. jUnwindTo()
     * pops and prints closers on demand, so toJsonEndKey just unwinds to 0.
     * Depth is bounded by the deepest nesting (stream: object > groups > group >
     * consumers > consumer > pel). */
    struct { int level; const char *close; } stack[8];
    int stackTop;
};

/* Record an open container without printing anything - only its closer string. */
static void jPush(RdbxToJson *ctx, int level, const char *close) {
    ctx->stack[ctx->stackTop].level = level;
    ctx->stack[ctx->stackTop].close = close;
    ctx->stackTop++;
}

/* Open a container: print its opening text (bracket, and any separator/label
 * that precedes it) and record the matching closer for later jUnwindTo(). Any
 * formatted body is printed by the caller afterwards. */
static void jOpen(RdbxToJson *ctx, int level, const char *open, const char *close) {
    fputs(open, ctx->outfile);
    jPush(ctx, level, close);
}

/* Level of the innermost open container, or 0 if the stack is empty. */
static int jTop(RdbxToJson *ctx) {
    return ctx->stackTop ? ctx->stack[ctx->stackTop - 1].level : 0;
}

/* Close (pop + print) every open container whose level is >= `level`. */
static void jUnwindTo(RdbxToJson *ctx, int level) {
    while (ctx->stackTop && ctx->stack[ctx->stackTop - 1].level >= level)
        fputs(ctx->stack[--ctx->stackTop].close, ctx->outfile);
}

const char *jsonMetaPrefix = "__";  /* Distinct meta from data with prefix string. */

static void outputPlainEscaping(RdbxToJson *ctx, char *p, size_t len) {
    while (len--) {
        switch (*p) {
            case '\\':
            case '"':
                fprintf(ctx->outfile, "\\%c", *p); break;
            case '\n': fprintf(ctx->outfile, "\\n"); break;
            case '\f': fprintf(ctx->outfile, "\\f"); break;
            case '\r': fprintf(ctx->outfile, "\\r"); break;
            case '\t': fprintf(ctx->outfile, "\\t"); break;
            case '\b': fprintf(ctx->outfile, "\\b"); break;
            default:
                fprintf(ctx->outfile, (isprint((unsigned char)*p)) ? "%c" : "\\u%04x", (unsigned char)*p);
        }
        p++;
    }
}

/* Verify that 'p' points to a well-formed UTF-8 sequence of length 'seqLen'.
 * Validates continuation bytes and rejects overlong encodings and surrogate
 * code points (U+D800..U+DFFF). 'seqLen' bytes are guaranteed available. */
static int utf8SeqValid(const unsigned char *p, int seqLen) {
    for (int i = 1; i < seqLen; ++i)
        if ((p[i] & 0xC0) != 0x80) return 0; /* not a 10xxxxxx continuation byte */

    /* Reject overlong encodings / surrogates by checking the second byte range */
    if (seqLen == 3 && p[0] == 0xE0 && p[1] < 0xA0) return 0; /* overlong */
    if (seqLen == 3 && p[0] == 0xED && p[1] > 0x9F) return 0; /* surrogate */
    if (seqLen == 4 && p[0] == 0xF0 && p[1] < 0x90) return 0; /* overlong */
    if (seqLen == 4 && p[0] == 0xF4 && p[1] > 0x8F) return 0; /* > U+10FFFF */
    return 1;
}

/* Like outputPlainEscaping(), but valid UTF-8 multi-byte sequences are passed
 * through verbatim instead of being escaped byte-by-byte. Bytes that are not
 * part of a well-formed UTF-8 sequence fall back to \u00XX escaping, so binary
 * (non-UTF-8) data still yields valid, lossless JSON. */
static void outputUtf8Escaping(RdbxToJson *ctx, char *p, size_t len) {
    while (len) {
        unsigned char c = (unsigned char) *p;
        switch (c) {
            case '\\':
            case '"':
                fprintf(ctx->outfile, "\\%c", c); ++p; --len; continue;
            case '\n': fprintf(ctx->outfile, "\\n"); ++p; --len; continue;
            case '\f': fprintf(ctx->outfile, "\\f"); ++p; --len; continue;
            case '\r': fprintf(ctx->outfile, "\\r"); ++p; --len; continue;
            case '\t': fprintf(ctx->outfile, "\\t"); ++p; --len; continue;
            case '\b': fprintf(ctx->outfile, "\\b"); ++p; --len; continue;
        }

        if (c < 0x80) { /* ASCII */
            fprintf(ctx->outfile, (isprint(c)) ? "%c" : "\\u%04x", c);
            ++p; --len;
            continue;
        }

        /* the expected length (2..4) of a UTF-8 sequence given its lead byte,
         * or 0 if 'c' is not a valid UTF-8 lead byte. Rejects the invalid/overlong
         * lead bytes 0xC0, 0xC1 and 0xF5..0xFF. */
        int seqLen = (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3 :
                     (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        
        if (seqLen && (size_t)seqLen <= len && utf8SeqValid((unsigned char *)p, seqLen)) {
            fwrite(p, 1, seqLen, ctx->outfile); /* valid UTF-8: emit as-is */
            p += seqLen;
            len -= seqLen;
        } else { /* invalid UTF-8 byte: keep it lossless and JSON-valid */
            fprintf(ctx->outfile, "\\u%04x", c);
            ++p; --len;
        }
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
                        "HandlersRdbToJson: Failed to open file `%s`. errno=%d: %s",
                        outfilename, errno, strerror(errno));
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
    ctx->conf.includeStreamIdmp = 0;
    ctx->conf.includeDbInfo = 0;

    /* override configuration if provided */
    if (conf) ctx->conf = *conf;

    switch(ctx->conf.encoding) {
        case RDBX_CONV_JSON_ENC_PLAIN: ctx->encfunc = outputPlainEscaping; break;
        case RDBX_CONV_JSON_ENC_UTF8: ctx->encfunc = outputUtf8Escaping; break;
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
    fprintf(ctx->outfile, "    \"%sdbsize__\": {\n", jsonMetaPrefix); /* group dbsize with {..} */
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
    fprintf(ctx->outfile, "    \"%sslotinfo__\": {\n", jsonMetaPrefix);
    fprintf(ctx->outfile, "      \"slotId\": %" PRIu64 ",\n", info->slot_id);
    fprintf(ctx->outfile, "      \"slotSize\": %" PRIu64 ",\n", info->slot_size);
    fprintf(ctx->outfile, "      \"slotSExpiresSize\": %" PRIu64 "\n", info->expires_slot_size);
    fprintf(ctx->outfile, "    },\n");
    return RDB_OK;
}

static RdbRes toJsonAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IDLE) {
        ctx->state = R2J_AUX_FIELDS;
        fprintf(ctx->outfile, " \"%saux__\": {\n", jsonMetaPrefix); /* group aux-fields with {..} */
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

    /* Close whatever containers this key's value left open. For scalars and
     * empty values (KEY/STRING) the stack is empty and this is a no-op. */
    switch(ctx->state) {
        case R2J_IN_KEY:
        case R2J_IN_STRING:
        case R2J_IN_LIST:
        case R2J_IN_SET:
        case R2J_IN_HASH:
        case R2J_IN_ZSET:
        case R2J_IN_ARRAY:
        case R2J_IN_STREAM:
            jUnwindTo(ctx, 0);
            break;
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
    ctx->stackTop = 0; /* fresh container stack per key */

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
    fprintf(ctx->outfile, "\"<Content of Module '%s'. Occupies a serialized size of %zu bytes>\"",
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
        jOpen(ctx, JLVL1_VALUE, "[", /*close:*/"]");
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
        jOpen(ctx, JLVL1_VALUE, "[", /*close:*/"]");
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
        jOpen(ctx, JLVL1_VALUE, "{", /*close:*/"}");
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
        jOpen(ctx, JLVL1_VALUE, "{", /*close:*/"}");
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
        fprintf(ctx->outfile, "\"%sfunc__\": {\n", jsonMetaPrefix);
    } else if (ctx->state == R2J_AUX_FIELDS) {
        fprintf(ctx->outfile, "\n},\n \"%sfunc__\": {\n", jsonMetaPrefix);
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

    if ( (ctx->state == R2J_IN_KEY) ||
         (ctx->state == R2J_IN_STREAM && ctx->streamState == R2J_STREAM_ENTRIES) ) {
        /* first field of a new entry */
        int firstEntry = (ctx->state == R2J_IN_KEY);
        if (firstEntry) {
            jOpen(ctx, JLVL1_VALUE, "{", /*close:*/"}");  /* stream object */
            jOpen(ctx, JLVL2_ENTRIES, "\n      \"entries\":[", "]"); /* entries array */
            ctx->state = R2J_IN_STREAM;
        }

        /* output another stream entry */
        fprintf(ctx->outfile, "%c\n        { \"id\":\"%" PRIu64 "-%" PRIu64 "\", ",
                firstEntry ? ' ' : ',', id->ms, id->seq );
        fprintf(ctx->outfile, "\"items\":{");
        outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
        fprintf(ctx->outfile, ":");
        outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    } else if (ctx->state == R2J_IN_STREAM && ctx->streamState == R2J_STREAM_ENTRY_FIELDS) {
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
        ctx->streamState = R2J_STREAM_ENTRY_FIELDS;
    } else {
        fprintf(ctx->outfile, "} }");
        ctx->streamState = R2J_STREAM_ENTRIES;
    }
    return RDB_OK;
}

static RdbRes toJsonStreamMetadata(RdbParser *p, void *userData, RdbStreamMeta *meta) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_KEY) {  /* no entries recorded - emit empty array */
        jOpen(ctx, JLVL1_VALUE, "{", "}");      /* stream object */
        fprintf(ctx->outfile, "\n      \"entries\":[]");
        ctx->state = R2J_IN_STREAM;
    } else if (ctx->state == R2J_IN_STREAM && ctx->streamState == R2J_STREAM_ENTRIES) {
        jUnwindTo(ctx, JLVL2_ENTRIES);          /* close the entries array */
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamMetadata(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }
    ctx->streamState = R2J_STREAM_META;
    fprintf(ctx->outfile, ",\n      \"length\": %" PRIu64 ", ", meta->length);
    fprintf(ctx->outfile, "\n      \"entriesAdded\": %" PRIu64 ", ", meta->entriesAdded);
    fprintf(ctx->outfile, "\n      \"firstID\": \"%" PRIu64 "-%" PRIu64 "\", ", meta->firstID.ms, meta->firstID.seq);
    fprintf(ctx->outfile, "\n      \"lastID\": \"%" PRIu64 "-%" PRIu64 "\", ", meta->lastID.ms, meta->lastID.seq);
    fprintf(ctx->outfile, "\n      \"maxDelEntryID\": \"%" PRIu64 "-%" PRIu64 "\"", meta->maxDelEntryID.ms, meta->maxDelEntryID.seq);
    return RDB_OK;
}

static RdbRes toJsonStreamNewCGroup(RdbParser *p, void *userData, RdbBulk grpName, RdbStreamGroupMeta *meta) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_STREAM && ctx->streamState == R2J_STREAM_META) {
        /* first group: open the "groups" array */
        jOpen(ctx, JLVL2_GROUPS, ",\n      \"groups\": [\n", "]");
    } else if (ctx->state == R2J_IN_STREAM && ctx->streamState == R2J_STREAM_SUBTREE) {
        /* sibling group: close the previous group and whatever it left open */
        jUnwindTo(ctx, JLVL3_GROUP);
        fprintf(ctx->outfile, ",\n");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamNewCGroup(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    jOpen(ctx, JLVL3_GROUP, "        {", "}");
    fprintf(ctx->outfile, "\"name\": \"%s\", \"lastid\": \"%" PRIu64 "-%" PRIu64 "\", \"entriesRead\": %" PRIu64,
            grpName, meta->lastId.ms, meta->lastId.seq, meta->entriesRead);

    ctx->streamState = R2J_STREAM_SUBTREE;
    return RDB_OK;
}

static RdbRes toJsonStreamCGroupPendingEntry(RdbParser *p, void *userData, RdbStreamPendingEntry *pe) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_STREAM || ctx->streamState != R2J_STREAM_SUBTREE) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamCGroupPendingEntry(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (jTop(ctx) == JLVL4_GPEL)
        fprintf(ctx->outfile, ", ");                   /* another entry in the open PEL */
    else
        jOpen(ctx, JLVL4_GPEL, ",\n         \"pending\": [ ", "]"); /* open the group's "pending" array */

    fprintf(ctx->outfile, "\n           { \"sent\": %" PRIu64 ", \"id\":\"%" PRIu64 "-%" PRIu64 "\", \"count\": %" PRIu64 " }",
            pe->deliveryTime, pe->id.ms, pe->id.seq, pe->deliveryCount);
    return RDB_OK;
}

static RdbRes toJsonStreamNewConsumer(RdbParser *p, void *userData, RdbBulk consName, RdbStreamConsumerMeta *meta) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_STREAM || ctx->streamState != R2J_STREAM_SUBTREE) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamNewConsumer(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (jTop(ctx) == JLVL5_CONSUMER || jTop(ctx) == JLVL6_CPEL) {
        /* sibling consumer: close the previous consumer (and its PEL) */
        jUnwindTo(ctx, JLVL5_CONSUMER);
        fprintf(ctx->outfile, ", ");
    } else {
        /* first consumer: close the global PEL if open, then open "consumers" */
        jUnwindTo(ctx, JLVL4_CONSUMERS);
        jOpen(ctx, JLVL4_CONSUMERS, ",\n         \"consumers\": [", "]");
    }

    jOpen(ctx, JLVL5_CONSUMER, "\n           { ", "}");
    fprintf(ctx->outfile, "\"name\": \"%s\", \"activeTime\": %lld, \"seenTime\": %lld",
            consName, meta->activeTime, meta->seenTime);

    return RDB_OK;
}

static RdbRes toJsonStreamConsumerPendingEntry(RdbParser *p, void *userData, RdbStreamID *streamId) {
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_STREAM || ctx->streamState != R2J_STREAM_SUBTREE) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamConsumerPendingEntry(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (jTop(ctx) == JLVL6_CPEL)
        fprintf(ctx->outfile, ", ");                   /* another id in the open consumer PEL */
    else
        jOpen(ctx, JLVL6_CPEL, ",\n             \"pending\": [", "]"); /* open the consumer's "pending" array */

    fprintf(ctx->outfile, "\n               {\"id\":\"%" PRIu64 "-%" PRIu64 "\"}", streamId->ms, streamId->seq);
    return RDB_OK;
}

/* v14: emit a NACKed entry ID into the per-CG "nacked" array. The array is
 * opened on the first call within a CG (closing whatever section preceded it:
 * the global PEL or the consumers array) and closed by the next state
 * transition (new CG / IDMP / end key). */
static RdbRes toJsonStreamNackZoneEntry(RdbParser *p, void *userData, RdbStreamID *id, int64_t itemsLeft) {
    UNUSED(itemsLeft);
    RdbxToJson *ctx = userData;

    if (ctx->state != R2J_IN_STREAM || ctx->streamState != R2J_STREAM_SUBTREE) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamNackZoneEntry(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    if (jTop(ctx) == JLVL4_NACKED) {
        fprintf(ctx->outfile, ", \"");                 /* another id in the open array */
    } else {
        /* close the global PEL / consumers subtree, keep the group, open "nacked" */
        jUnwindTo(ctx, JLVL4_NACKED);
        jOpen(ctx, JLVL4_NACKED, ",\n         \"nacked\": [\"", "]");
    }
    fprintf(ctx->outfile, "%" PRIu64 "-%" PRIu64 "\"", id->ms, id->seq);
    return RDB_OK;
}

static RdbRes toJsonStreamIdmpMeta(RdbParser *p, void *userData, RdbStreamIdmpMeta *meta) {
    RdbxToJson *ctx = userData;

    /* Skip outputting IDMP section if there are no producers - it's effectively empty/default config */
    if (meta->numProducers == 0)
        return RDB_OK;

    /* "idmp" is a sibling of "entries"/"groups" under the stream object. */
    if (ctx->state == R2J_IN_KEY) {
        /* No entries and handleStreamMetadata not registered: open stream object */
        jOpen(ctx, JLVL1_VALUE, "{", "}");
        jOpen(ctx, JLVL2_IDMP, "\n      \"idmp\": {", /*close:*/"}");
        ctx->state = R2J_IN_STREAM;
    } else if (ctx->state == R2J_IN_STREAM) {
        jUnwindTo(ctx, JLVL2_IDMP);  /* close whatever child is open (entries array / groups subtree) */
        jOpen(ctx, JLVL2_IDMP, ",\n      \"idmp\": {", /*close:*/"}");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamIdmpMeta(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    fprintf(ctx->outfile, "\n        \"duration\": %" PRIu64 ", \"maxEntries\": %" PRIu64 ", \"numProducers\": %" PRIu64,
            meta->duration, meta->maxEntries, meta->numProducers);

    ctx->streamState = R2J_STREAM_SUBTREE;
    return RDB_OK;
}

static RdbRes toJsonStreamIdmpProducer(RdbParser *p, void *userData, RdbStreamIdmpProducer *producer) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JLVL2_IDMP) {
        /* first producer: open the "producers" array + producer object */
        jOpen(ctx, JLVL3_PRODUCERS, ",\n        \"producers\": [", /*close:*/"]");
        jOpen(ctx, JLVL4_PRODUCER, "\n          {\"pid\": ", /*close:*/"}");
    } else if (jTop(ctx) == JLVL4_PRODUCER || jTop(ctx) == JLVL5_PENTRIES) {
        /* sibling producer: close the previous producer (and its entries) */
        jUnwindTo(ctx, JLVL4_PRODUCER);
        jOpen(ctx, JLVL4_PRODUCER, ",\n          {\"pid\": ", /*close:*/"}");
    } else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamIdmpProducer(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    outputQuotedEscaping(ctx, producer->pid, RDB_bulkLen(p, producer->pid));
    fprintf(ctx->outfile, ", \"numEntries\": %" PRIu64, producer->numEntries);

    return RDB_OK;
}

static RdbRes toJsonStreamIdmpEntry(RdbParser *p, void *userData, RdbStreamIdmpEntry *entry) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JLVL4_PRODUCER)
        jOpen(ctx, JLVL5_PENTRIES, ",\n           \"entries\": [", "]"); /* open the producer's "entries" array */
    else if (jTop(ctx) == JLVL5_PENTRIES)
        fprintf(ctx->outfile, ", ");
    else {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonStreamIdmpEntry(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    fprintf(ctx->outfile, "{\"iid\": ");
    outputQuotedEscaping(ctx, entry->iid, RDB_bulkLen(p, entry->iid));
    fprintf(ctx->outfile, ", \"streamId\": \"%" PRIu64 "-%" PRIu64 "\"}", entry->streamId.ms, entry->streamId.seq);

    return RDB_OK;
}

static RdbRes toJsonArrayMetadata(RdbParser *p, void *userData, uint64_t count, uint64_t insertIdx) {
    UNUSED(p, count);
    RdbxToJson *ctx = userData;

    if (unlikely(ctx->state != R2J_IN_KEY)) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonArrayMetadata(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    jOpen(ctx, JLVL1_VALUE, "{", /*close:*/"]}");      /* elements array + wrapper object */
    if (insertIdx != RDB_ARRAY_INSERT_IDX_NONE)
        fprintf(ctx->outfile, "\"insert_idx\":\"%" PRIu64 "\",", insertIdx);
    fprintf(ctx->outfile, "\"elements\":[");

    /* state stays R2J_IN_KEY until the first element arrives — that lets
     * toJsonArrayElement omit the leading comma on the first record without
     * a separate "first-element" flag. */
    return RDB_OK;
}

static RdbRes toJsonArrayElement(RdbParser *p, void *userData, uint64_t idx, RdbBulk value) {
    RdbxToJson *ctx = userData;

    if (ctx->state == R2J_IN_ARRAY) {
        fprintf(ctx->outfile, ",");
    } else if (ctx->state != R2J_IN_KEY) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                        "toJsonArrayElement(): Invalid state value: %d", ctx->state);
        return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
    }

    fprintf(ctx->outfile, "{\"idx\":\"%" PRIu64 "\",\"val\":", idx);
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    fprintf(ctx->outfile, "}");

    ctx->state = R2J_IN_ARRAY;
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
            
                /*stream:*/            
                NULL,             /*handleStreamMetadata*/
                toJsonStreamItem, /*handleStreamItem*/
                NULL,             /* handleStreamNewCGroup */
                NULL,             /* handleStreamCGroupPendingEntry */
                NULL,             /* handleStreamNewConsumer */
                NULL,             /* handleStreamConsumerPendingEntry */
                NULL,             /* handleStreamNackZoneEntry */
                NULL,             /* handleStreamIdmpMeta */
                NULL,             /* handleStreamIdmpProducer */
                NULL,             /* handleStreamIdmpEntry */

                /*array (v14+):*/
                toJsonArrayMetadata, /* handleArrayMetadata */
                toJsonArrayElement,  /* handleArrayElement */
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
            dataCb.handleStreamNackZoneEntry = toJsonStreamNackZoneEntry;
        }
        if (ctx->conf.includeStreamIdmp) {
            dataCb.handleStreamIdmpMeta = toJsonStreamIdmpMeta;
            dataCb.handleStreamIdmpProducer = toJsonStreamIdmpProducer;
            dataCb.handleStreamIdmpEntry = toJsonStreamIdmpEntry;
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
