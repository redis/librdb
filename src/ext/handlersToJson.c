/* RDB -> JSON conversion handlers, registered as libRDB parser callbacks (see
 * RDBX_createHandlersToJson()). The parser drives everything: as it walks the
 * RDB file it fires one handler per element (a DB, a key, a list item, a
 * stream entry, ...), and each handler streams straight to ctx->outfile -
 * there is no in-memory JSON tree.
 *
 * Because a JSON container (array/object) opens, receives children across
 * multiple handler calls, and closes incrementally as parsing progresses, the
 * currently-open containers are tracked on an explicit stack (RdbxToJson.stack)
 * rather than via recursion. Each container kind is identified by a JContId
 * (JC_DOC, JC_KEY, JC_LIST, ...), and its printed shape - nesting level,
 * exclusive parent, opening/closing text and the delimiter between children -
 * is declared once in jSpecs[]/ctx->specs[], indexed by id (see jSpec()).
 * Handlers open/close containers by id (jOpen/jOpenUnder/jOpenNext/jUnwindTo)
 * and validate the parser's calling sequence by checking which container is
 * currently innermost (jTop()), instead of running a separate state machine. */

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

/* Ids of the emitted JSON containers, document root to innermost. 0 is reserved
 * as the "nothing open" sentinel (see jTop()) and is never a real id - hence
 * JC_DOC starts at 1. Each id's nesting level and printed shape are looked up
 * from jSpecs[] below: jUnwindTo(id) closes every open container whose level is
 * >= that of the given id, while jTop() comparisons match one exact container.
 * Level is purely an ordering value (child.level > parent.level) - it is not
 * required to equal the container's literal stack depth; jPush validates
 * structure via jSpec(ctx, id)->parent instead. The stack fully captures the
 * emission state - handlers validate against jTop() rather than a separate
 * state machine.
 *
 * The declarations below are indented to mirror this parent/child tree, purely
 * for readability; jSpecs[] (via its designated initializers) is what jPush
 * actually validates against, so keep the indentation in sync by hand when
 * adding an id. */
typedef enum JContId {
    JC_DOC = 1,             /* the RDB document: array of DBs, or bare keys if flatten */
        JC_AUX,             /* "aux" object: RDB metadata key:value pairs */
        JC_FUNC,            /* "func" object: dumped Lua functions */
        JC_DB,              /* one DB object (a no-op frame if flatten) */
            JC_KEY,         /* marker for a key awaiting/holding its value */
                JC_LIST,        /* list value: array of elements */
                JC_SET,         /* set value: array of members */
                JC_HASH,        /* hash value: object of field:value */
                JC_ZSET,        /* zset value: object of member:score */
                JC_ARRAY,       /* (v14+) elements array + wrapper object */
                JC_STREAM,      /* stream object */
                    JC_ENTRIES,     /* "entries" array */
                        JC_ENTRY,       /* one entry */
                            JC_ITEMS,       /* "items" object: the entry's field:value pairs */
                    JC_GROUPS,      /* "groups" array */
                        JC_GROUP,       /* one consumer group */
                            JC_GPEL,        /* "pending" array (global PEL) */
                            JC_NACKED,      /* "nacked" array of entry IDs */
                            JC_CONSUMERS,   /* "consumers" array */
                                JC_CONSUMER,    /* one consumer */
                                    JC_CPEL,        /* "pending" array (per-consumer PEL) */
                    JC_IDMP,        /* "idmp" object: idempotent-producers state */
                        JC_PRODUCERS,   /* "producers" array */
                            JC_PRODUCER,    /* one producer */
                                JC_PENTRIES,    /* "entries" array */
} JContId;

/* Per-container nesting level, exclusive parent, and printed shape, indexed
 * directly by JContId. Every id opens under exactly one fixed parent (JC_DOC's
 * is 0, the same "nothing open" sentinel jTop() uses for an empty stack). This
 * is the default/template table: JC_DOC/JC_DB's open/close actually depend on
 * ctx->conf.flatten, and JC_AUX/JC_FUNC's open on the (CLI-settable)
 * jsonMetaPrefix, so RdbxToJson keeps its own per-conversion copy (ctx->specs)
 * patched for those ids at init - see initRdbToJsonCtx(). The "" here is
 * JC_DOC/JC_DB's flatten=true value, kept only so every id has a full row
 * (their delim is NOT flatten-dependent, so it's the real, always-used
 * value). */
typedef struct { int level; JContId parent; const char *open, *delim, *close; } JContSpec;
static const JContSpec jSpecs[] = {
    /*                 level parent        open                             delim         close */
    [JC_DOC]       = { 1,    0,            "",                              ",\n",        ""       },
    [JC_AUX]       = { 2,    JC_DOC,       "",                              ",\n       ", "\n}"    },
    [JC_FUNC]      = { 2,    JC_DOC,       "",                              ",\n",        "\n}"    },
    [JC_DB]        = { 2,    JC_DOC,       "",                              ",\n",        ""       },
    [JC_KEY]       = { 3,    JC_DB,        "    ",                          "",           ""       },
    [JC_LIST]      = { 4,    JC_KEY,       "[",                             ",",          "]"      },
    [JC_SET]       = { 4,    JC_KEY,       "[",                             ",",          "]"      },
    [JC_HASH]      = { 4,    JC_KEY,       "{",                             ",",          "}"      },
    [JC_ZSET]      = { 4,    JC_KEY,       "{",                             ",",          "}"      },
    [JC_ARRAY]     = { 4,    JC_KEY,       "{",                             ",",          "]}"     },
    [JC_STREAM]    = { 4,    JC_KEY,       "{",                             ",",          "}"      },
    [JC_ENTRIES]   = { 5,    JC_STREAM,    "\n      \"entries\":[",         ",",          "]"      },
    [JC_GROUPS]    = { 5,    JC_STREAM,    "\n      \"groups\": [\n",       ",\n",        "]"      },
    [JC_IDMP]      = { 5,    JC_STREAM,    "\n      \"idmp\": {",           ",",          "}"      },
    [JC_ENTRY]     = { 6,    JC_ENTRIES,   "\n        { ",                  "",           " }"     },
    [JC_GROUP]     = { 6,    JC_GROUPS,    "        {",                     ",",          "}"      },
    [JC_PRODUCERS] = { 6,    JC_IDMP,      "\n        \"producers\": [",    ",",          "]"      },
    [JC_ITEMS]     = { 7,    JC_ENTRY,     "\"items\":{",                   ", ",         "}"      },
    [JC_GPEL]      = { 7,    JC_GROUP,     "\n         \"pending\": [ ",    ",",          "]"      },
    [JC_NACKED]    = { 7,    JC_GROUP,     "\n         \"nacked\": [",      ",",          "]"      },
    [JC_CONSUMERS] = { 7,    JC_GROUP,     "\n         \"consumers\": [",   ",",          "]"      },
    [JC_PRODUCER]  = { 7,    JC_PRODUCERS, "\n          {\"pid\": ",        ",",          "}"      },
    [JC_CONSUMER]  = { 8,    JC_CONSUMERS, "\n           { ",               ",",          "}"      },
    [JC_PENTRIES]  = { 8,    JC_PRODUCER,  "\n           \"entries\": [",   ",",          "]"      },
    [JC_CPEL]      = { 9,    JC_CONSUMER,  "\n             \"pending\": [", ",",          "]"      },
};

struct RdbxToJson {
    RdbxToJsonConf conf;

    char *outfileName;  /* Holds output filename or equals _STDOUT_STR */
    FILE *outfile;

    /* Per-conversion copy of jSpecs[], patched once at init for the ids whose
     * printed shape depends on runtime config rather than being a fixed
     * literal: JC_DOC/JC_DB on conf.flatten, JC_AUX/JC_FUNC's meta-section
     * label on the (CLI-settable) jsonMetaPrefix. Everything else is an exact
     * copy, so jSpec() can serve every id the same way. */
    JContSpec specs[sizeof(jSpecs) / sizeof(jSpecs[0])];

    /* Backing buffers for specs[JC_AUX]/specs[JC_FUNC].open - fixed-size so
     * there's nothing to free; 200 bytes comfortably fits any realistic
     * jsonMetaPrefix plus the fixed "aux__"/"func__" suffix (any excess is
     * safely truncated by snprintf, never overflowed). */
    char auxOpenText[200];
    char funcOpenText[200];

    void (*encfunc)(FILE *out, char *p, size_t len);

    struct {
        RdbBulkCopy key;
        RdbKeyInfo info;
    } keyCtx;

    unsigned int count_functions;
    unsigned int count_db;

    /* Stack of open JSON containers, document root to innermost. Each frame
     * records the container's id and how many children were appended so far:
     * jNewItem()/jOpen() print the delimiter (from ctx->specs[id]) before every
     * child but the first. jUnwindTo() pops and prints closers (also from
     * ctx->specs[id]) on demand, so toJsonEndRdb just unwinds to 0. Depth is
     * bounded by the deepest nesting (doc > db > key > stream > groups > group
     * > consumers > consumer > pel). */
    struct {
        JContId id;
        int nItems;
    } stack[12];
    int stackTop;
};

/* Id of the innermost open container, or 0 if the stack is empty. */
static JContId jTop(RdbxToJson *ctx) {
    return ctx->stackTop ? ctx->stack[ctx->stackTop - 1].id : 0;
}

/* Look up id's spec in ctx's own copy of jSpecs[] (see RdbxToJson.specs);
 * asserts open != NULL so a distinct id missing from the table (e.g. a future
 * enum addition) fails loudly instead of a NULL fputs. */
static const JContSpec *jSpec(RdbxToJson *ctx, JContId id) {
    const JContSpec *s = &ctx->specs[id];
    assert(s->open);
    return s;
}

/* Nesting level of `id`, or 0 for the "nothing open" sentinel (see jTop()) -
 * always below every real level, so jUnwindTo(ctx, 0) still closes everything. */
static int jLevel(RdbxToJson *ctx, JContId id) {
    return id ? jSpec(ctx, id)->level : 0;
}

/* Record an open container without printing anything. */
static void jPush(RdbxToJson *ctx, JContId id) {
    /* Every container opens directly under its declared parent - true even for
     * jOpen's "trusted" pushes, which skip jOpenUnder's own parent check. */
    assert(jTop(ctx) == jSpec(ctx, id)->parent);
    ctx->stack[ctx->stackTop].id = id;
    ctx->stack[ctx->stackTop].nItems = 0;
    ctx->stackTop++;
}

/* Print the innermost container's delimiter before every child but the first. */
static void jDelim(RdbxToJson *ctx) {
    if (ctx->stackTop && ctx->stack[ctx->stackTop - 1].nItems++)
        fputs(jSpec(ctx, ctx->stack[ctx->stackTop - 1].id)->delim, ctx->outfile);
}

/* Start a child in container `id`, which must be the innermost open one. The
 * child itself is printed by the caller afterwards (an inline batch of
 * scalars counts as one child). */
static void jNewItem(RdbxToJson *ctx, JContId id) {
    assert(jTop(ctx) == id);
    (void) id;
    jDelim(ctx);
}

/* Open `id` as a child of the current one: apply the parent's delimiter by
 * need, print id's opening text (bracket and any label that precedes it,
 * from ctx->specs[]) and record the frame for jNewItem()/jUnwindTo(). */
static void jOpen(RdbxToJson *ctx, JContId id) {
    jDelim(ctx);
    fputs(jSpec(ctx, id)->open, ctx->outfile);
    jPush(ctx, id);
}

/* Close (pop + print) every open container at the level of `id` or deeper. */
static void jUnwindTo(RdbxToJson *ctx, JContId id) {
    while (ctx->stackTop && jLevel(ctx, ctx->stack[ctx->stackTop - 1].id) >= jLevel(ctx, id))
        fputs(jSpec(ctx, ctx->stack[--ctx->stackTop].id)->close, ctx->outfile);
}

/* True if container `id` is currently open (depth is tiny, so a scan stays cheap). */
static int jIsOpen(RdbxToJson *ctx, JContId id) {
    for (int i = 0; i < ctx->stackTop; i++)
        if (ctx->stack[i].id == id) return 1;
    return 0;
}

/* Open `id` as a child of its declared (ctx->specs[]) parent, or fail (return
 * 0) if that parent is not the innermost open container - the callback fired
 * in a state it can't accept. */
static int jOpenUnder(RdbxToJson *ctx, JContId id) {
    if (jTop(ctx) != jSpec(ctx, id)->parent) return 0;
    jOpen(ctx, id);
    return 1;
}

/* Like jOpenUnder(), but first close the previous sibling's subtree
 * (everything at `id`'s level or deeper). For advancing to the next section
 * or element within its parent; a failed parent check may thus follow emitted
 * closers, but the conversion is aborted then anyway. */
static int jOpenNext(RdbxToJson *ctx, JContId id) {
    jUnwindTo(ctx, id);
    return jOpenUnder(ctx, id);
}

/* Report that a callback fired while an unexpected container is innermost. */
static RdbRes invalidState(RdbParser *p, RdbxToJson *ctx, const char *caller) {
    RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_INVALID_STATE,
                    "%s(): Invalid container: %d", caller, jTop(ctx));
    return (RdbRes) RDBX_ERR_R2J_INVALID_STATE;
}

const char *jsonMetaPrefix = "__";  /* Distinct meta from data with prefix string. */

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
static void outputUtf8Escaping(FILE *out, char *p, size_t len) {
    while (len) {
        unsigned char c = (unsigned char) *p;
        switch (c) {
            case '\\':
            case '"':
                fprintf(out, "\\%c", c); ++p; --len; continue;
            case '\n': fprintf(out, "\\n"); ++p; --len; continue;
            case '\f': fprintf(out, "\\f"); ++p; --len; continue;
            case '\r': fprintf(out, "\\r"); ++p; --len; continue;
            case '\t': fprintf(out, "\\t"); ++p; --len; continue;
            case '\b': fprintf(out, "\\b"); ++p; --len; continue;
        }

        if (c < 0x80) { /* ASCII */
            fprintf(out, (isprint(c)) ? "%c" : "\\u%04x", c);
            ++p; --len;
            continue;
        }

        /* the expected length (2..4) of a UTF-8 sequence given its lead byte,
         * or 0 if 'c' is not a valid UTF-8 lead byte. Rejects the invalid/overlong
         * lead bytes 0xC0, 0xC1 and 0xF5..0xFF. */
        int seqLen = (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3 :
                     (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        
        if (seqLen && (size_t)seqLen <= len && utf8SeqValid((unsigned char *)p, seqLen)) {
            fwrite(p, 1, seqLen, out); /* valid UTF-8: emit as-is */
            p += seqLen;
            len -= seqLen;
        } else { /* invalid UTF-8 byte: keep it lossless and JSON-valid */
            fprintf(out, "\\u%04x", c);
            ++p; --len;
        }
    }
}

static void outputQuotedEscaping(RdbxToJson *ctx, char *data, size_t len) {
    fprintf(ctx->outfile, "\"");
    ctx->encfunc(ctx->outfile, data, len);
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
        case RDBX_CONV_JSON_ENC_PLAIN: ctx->encfunc = rdbxOutputPlainEscaping; break;
        case RDBX_CONV_JSON_ENC_UTF8: ctx->encfunc = outputUtf8Escaping; break;
        case RDBX_CONV_JSON_ENC_BASE64: /* TODO: support base64 */
        default: assert(0); break;
    }

    /* this conversion's own copy of jSpecs[], patched for conf.flatten and
     * jsonMetaPrefix - see the comment on jSpecs[] and on ctx->specs. */
    memcpy(ctx->specs, jSpecs, sizeof(jSpecs));
    ctx->specs[JC_DOC].open  = ctx->conf.flatten ? "" : "[";
    ctx->specs[JC_DOC].close = ctx->conf.flatten ? "" : "]\n";
    ctx->specs[JC_DB].open   = ctx->conf.flatten ? "" : "{\n";
    ctx->specs[JC_DB].close  = ctx->conf.flatten ? "" : "\n}";
    snprintf(ctx->auxOpenText, sizeof(ctx->auxOpenText), " \"%saux__\": {\n", jsonMetaPrefix);
    snprintf(ctx->funcOpenText, sizeof(ctx->funcOpenText), " \"%sfunc__\": {\n", jsonMetaPrefix);
    ctx->specs[JC_AUX].open  = ctx->auxOpenText;
    ctx->specs[JC_FUNC].open = ctx->funcOpenText;

    return ctx;
}

/*** Handling common ***/

static RdbRes toJsonDbSize(RdbParser *p, void *userData, uint64_t db_size, uint64_t exp_size) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_DB)
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_DB);
    fprintf(ctx->outfile, "    \"%sdbsize__\": {\n", jsonMetaPrefix); /* group dbsize with {..} */
    fprintf(ctx->outfile, "      \"size\": %" PRIu64 ",\n", db_size);
    fprintf(ctx->outfile, "      \"expires\": %" PRIu64 "\n", exp_size);
    fprintf(ctx->outfile, "    }");

    return RDB_OK;
}

static RdbRes toJsonSlotInfo(RdbParser *p, void *userData, RdbSlotInfo *info) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_DB)
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_DB);
    fprintf(ctx->outfile, "    \"%sslotinfo__\": {\n", jsonMetaPrefix);
    fprintf(ctx->outfile, "      \"slotId\": %" PRIu64 ",\n", info->slot_id);
    fprintf(ctx->outfile, "      \"slotSize\": %" PRIu64 ",\n", info->slot_size);
    fprintf(ctx->outfile, "      \"slotSExpiresSize\": %" PRIu64 "\n", info->expires_slot_size);
    fprintf(ctx->outfile, "    }");
    return RDB_OK;
}

static RdbRes toJsonAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_AUX && /* first aux-field: group them with {..} */
        !jOpenUnder(ctx, JC_AUX))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_AUX);
    outputQuotedEscaping(ctx, auxkey, RDB_bulkLen(p, auxkey));
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, auxval, RDB_bulkLen(p, auxval));

    return RDB_OK;
}

static RdbRes toJsonEndKey(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    if (jLevel(ctx, jTop(ctx)) < jLevel(ctx, JC_KEY))
        return invalidState(p, ctx, __func__);

    /* Close whatever containers this key's value left open, along with the
     * key marker itself. For scalar values only the marker is popped. */
    jUnwindTo(ctx, JC_KEY);

    RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return RDB_OK;
}

static RdbRes toJsonNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    RdbxToJson *ctx = userData;

    /* The key itself needs no closer - its single child (the value) closes
     * itself - so the frame is just a position marker. */
    if (unlikely(!jOpenUnder(ctx, JC_KEY)))
        return invalidState(p, ctx, __func__);

    ctx->keyCtx.key = RDB_bulkClone(p, key);
    ctx->keyCtx.info = *info;

    outputQuotedEscaping(ctx, key, RDB_bulkLen(p, key));
    fprintf(ctx->outfile, ":");

    return RDB_OK;
}

static RdbRes toJsonNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(db);
    RdbxToJson *ctx = userData;

    /* Close the previous DB (or the aux/func object) if open. In flatten mode
     * the DB frame prints nothing - it only scopes the keys, which then read
     * as direct children of the document. */
    if (!jOpenNext(ctx, JC_DB))
        return invalidState(p, ctx, __func__);

    ++ctx->count_db;
    return RDB_OK;
}

static RdbRes toJsonNewRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(rdbVersion);
    RdbxToJson *ctx = userData;

    /* parent 0 = the empty stack: nothing may be open yet */
    if (!jOpenUnder(ctx, JC_DOC))
        return invalidState(p, ctx, __func__);

    return RDB_OK;
}

static RdbRes toJsonEndRdb(RdbParser *p, void *userData) {
    RdbxToJson *ctx = userData;

    if (ctx->stackTop == 0 || jLevel(ctx, jTop(ctx)) > jLevel(ctx, JC_DB))
        return invalidState(p, ctx, __func__);

    if (ctx->stack[0].nItems == 0)
        RDB_log(p, RDB_LOG_WRN, "RDB is empty.");

    jUnwindTo(ctx, 0); /* close everything, document included */

    return RDB_OK;
}

static RdbRes toJsonModule(RdbParser *p, void *userData, RdbBulk moduleName, size_t serializedSize) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_KEY)
        return invalidState(p, ctx, __func__);

    fprintf(ctx->outfile, "\"<Content of Module '%s'. Occupies a serialized size of %zu bytes>\"",
            moduleName,
            serializedSize);

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toJsonString(RdbParser *p, void *userData, RdbBulk string) {
    UNUSED(p);
    RdbxToJson *ctx = userData;

    outputQuotedEscaping(ctx, string, RDB_bulkLen(p, string));

    return RDB_OK;
}

static RdbRes toJsonList(RdbParser *p, void *userData, RdbBulk item) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_LIST && /* first item: open the list's array */
        !jOpenUnder(ctx, JC_LIST))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_LIST);
    outputQuotedEscaping(ctx, item, RDB_bulkLen(p, item));

    return RDB_OK;
}

static RdbRes toJsonSet(RdbParser *p, void *userData, RdbBulk member) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_SET && /* first member: open the set's array */
        !jOpenUnder(ctx, JC_SET))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_SET);
    outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));

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

    if (jTop(ctx) != JC_ZSET && /* first member: open the zset's object */
        !jOpenUnder(ctx, JC_ZSET))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_ZSET);
    outputQuotedEscaping(ctx, member, RDB_bulkLen(p, member));
    fprintf(ctx->outfile, ":\"%.*s\"", len, scoreStr);

    return RDB_OK;
}

static RdbRes toJsonHash(RdbParser *p, void *userData, RdbBulk field,
                         RdbBulk value, int64_t expireAt)
{
    UNUSED(expireAt);
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_HASH && /* first field: open the hash's object */
        !jOpenUnder(ctx, JC_HASH))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_HASH);
    outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));

    return RDB_OK;
}

static RdbRes toJsonFunction(RdbParser *p, void *userData, RdbBulk func) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_FUNC && /* first function: close aux if open, open "func" */
        !jOpenNext(ctx, JC_FUNC))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_FUNC);
    fprintf(ctx->outfile, "    \"%sFunction_%d\":", jsonMetaPrefix, ++ctx->count_functions);
    outputQuotedEscaping( (RdbxToJson *) userData, func, RDB_bulkLen(p, func));
    ctx->count_functions++;
    return RDB_OK;
}

static RdbRes toJsonStreamItem(RdbParser *p, void *userData, RdbStreamID *id, RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JC_KEY) {
        jOpen(ctx, JC_STREAM);
        jOpen(ctx, JC_ENTRIES);
    }

    if (jTop(ctx) == JC_ENTRIES) {
        /* new entry: open its object and "items", then append the first field */
        jOpen(ctx, JC_ENTRY);
        fprintf(ctx->outfile, "\"id\":\"%" PRIu64 "-%" PRIu64 "\", ", id->ms, id->seq);
        jOpen(ctx, JC_ITEMS);
    } else if (jTop(ctx) != JC_ITEMS) {
        return invalidState(p, ctx, __func__);
    }

    jNewItem(ctx, JC_ITEMS);
    outputQuotedEscaping(ctx, field, RDB_bulkLen(p, field));
    fprintf(ctx->outfile, ":");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));

    if (!itemsLeft)
        jUnwindTo(ctx, JC_ENTRY);  /* close "items" and the entry object */
    return RDB_OK;
}

static RdbRes toJsonStreamMetadata(RdbParser *p, void *userData, RdbStreamMeta *meta) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JC_KEY) {  /* no entries recorded - emit empty array */
        jOpen(ctx, JC_STREAM);
        jNewItem(ctx, JC_STREAM);
        fprintf(ctx->outfile, "\n      \"entries\":[]");
    } else if (jTop(ctx) == JC_ENTRIES) {
        jUnwindTo(ctx, JC_ENTRIES);          /* close the entries array */
    } else {
        return invalidState(p, ctx, __func__);
    }
    jNewItem(ctx, JC_STREAM);
    fprintf(ctx->outfile, "\n      \"length\": %" PRIu64 ", ", meta->length);
    fprintf(ctx->outfile, "\n      \"entriesAdded\": %" PRIu64 ", ", meta->entriesAdded);
    fprintf(ctx->outfile, "\n      \"firstID\": \"%" PRIu64 "-%" PRIu64 "\", ", meta->firstID.ms, meta->firstID.seq);
    fprintf(ctx->outfile, "\n      \"lastID\": \"%" PRIu64 "-%" PRIu64 "\", ", meta->lastID.ms, meta->lastID.seq);
    fprintf(ctx->outfile, "\n      \"maxDelEntryID\": \"%" PRIu64 "-%" PRIu64 "\"", meta->maxDelEntryID.ms, meta->maxDelEntryID.seq);
    return RDB_OK;
}

static RdbRes toJsonStreamNewCGroup(RdbParser *p, void *userData, RdbBulk grpName, RdbStreamGroupMeta *meta) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JC_STREAM) {
        /* first group (metadata emitted): open the "groups" array */
        jOpen(ctx, JC_GROUPS);
    }

    /* close the previous group (and whatever it left open), open the next */
    if (!jOpenNext(ctx, JC_GROUP))
        return invalidState(p, ctx, __func__);
    jNewItem(ctx, JC_GROUP);
    fprintf(ctx->outfile, "\"name\": \"%s\", \"lastid\": \"%" PRIu64 "-%" PRIu64 "\", \"entriesRead\": %" PRIu64,
            grpName, meta->lastId.ms, meta->lastId.seq, meta->entriesRead);

    return RDB_OK;
}

static RdbRes toJsonStreamCGroupPendingEntry(RdbParser *p, void *userData, RdbStreamPendingEntry *pe) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_GPEL && /* first entry: open the group's "pending" array */
        !jOpenUnder(ctx, JC_GPEL))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_GPEL);
    fprintf(ctx->outfile, "\n           { \"sent\": %" PRIu64 ", \"id\":\"%" PRIu64 "-%" PRIu64 "\", \"count\": %" PRIu64 " }",
            pe->deliveryTime, pe->id.ms, pe->id.seq, pe->deliveryCount);
    return RDB_OK;
}

static RdbRes toJsonStreamNewConsumer(RdbParser *p, void *userData, RdbBulk consName, RdbStreamConsumerMeta *meta) {
    RdbxToJson *ctx = userData;

    /* first consumer: close the global PEL if open, then open "consumers" */
    if (!jIsOpen(ctx, JC_CONSUMERS) && !jOpenNext(ctx, JC_CONSUMERS))
        return invalidState(p, ctx, __func__);

    /* close the previous consumer (and its PEL), open the next */
    if (!jOpenNext(ctx, JC_CONSUMER))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_CONSUMER);
    fprintf(ctx->outfile, "\"name\": \"%s\", \"activeTime\": %lld, \"seenTime\": %lld",
            consName, meta->activeTime, meta->seenTime);

    return RDB_OK;
}

static RdbRes toJsonStreamConsumerPendingEntry(RdbParser *p, void *userData, RdbStreamID *streamId) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_CPEL && /* first entry: open the consumer's "pending" array */
        !jOpenUnder(ctx, JC_CPEL))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_CPEL);
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

    /* first entry: close the global PEL / consumers subtree, keep the group,
     * open "nacked" */
    if (jTop(ctx) != JC_NACKED &&
        !jOpenNext(ctx, JC_NACKED))
        return invalidState(p, ctx, __func__);
    jNewItem(ctx, JC_NACKED);
    fprintf(ctx->outfile, "\"%" PRIu64 "-%" PRIu64 "\"", id->ms, id->seq);
    return RDB_OK;
}

static RdbRes toJsonStreamIdmpMeta(RdbParser *p, void *userData, RdbStreamIdmpMeta *meta) {
    RdbxToJson *ctx = userData;

    /* Skip outputting IDMP section if there are no producers - it's effectively empty/default config */
    if (meta->numProducers == 0)
        return RDB_OK;

    /* "idmp" is a sibling of "entries"/"groups" under the stream object. */
    if (jTop(ctx) == JC_KEY) {
        /* No entries and handleStreamMetadata not registered: open stream object */
        jOpen(ctx, JC_STREAM);
    }

    /* close whatever child is open (entries array / groups subtree) */
    if (!jOpenNext(ctx, JC_IDMP))
        return invalidState(p, ctx, __func__);
    jNewItem(ctx, JC_IDMP);
    fprintf(ctx->outfile, "\n        \"duration\": %" PRIu64 ", \"maxEntries\": %" PRIu64 ", \"numProducers\": %" PRIu64,
            meta->duration, meta->maxEntries, meta->numProducers);

    return RDB_OK;
}

static RdbRes toJsonStreamIdmpProducer(RdbParser *p, void *userData, RdbStreamIdmpProducer *producer) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) == JC_IDMP) {
        /* first producer: open the "producers" array */
        jOpen(ctx, JC_PRODUCERS);
    }

    /* close the previous producer (and its entries), open the next */
    if (!jOpenNext(ctx, JC_PRODUCER))
        return invalidState(p, ctx, __func__);
    jNewItem(ctx, JC_PRODUCER);
    outputQuotedEscaping(ctx, producer->pid, RDB_bulkLen(p, producer->pid));
    fprintf(ctx->outfile, ", \"numEntries\": %" PRIu64, producer->numEntries);

    return RDB_OK;
}

static RdbRes toJsonStreamIdmpEntry(RdbParser *p, void *userData, RdbStreamIdmpEntry *entry) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_PENTRIES && /* first entry: open the producer's "entries" array */
        !jOpenUnder(ctx, JC_PENTRIES))
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_PENTRIES);
    fprintf(ctx->outfile, "{\"iid\": ");
    outputQuotedEscaping(ctx, entry->iid, RDB_bulkLen(p, entry->iid));
    fprintf(ctx->outfile, ", \"streamId\": \"%" PRIu64 "-%" PRIu64 "\"}", entry->streamId.ms, entry->streamId.seq);

    return RDB_OK;
}

static RdbRes toJsonArrayMetadata(RdbParser *p, void *userData, uint64_t count, uint64_t insertIdx) {
    UNUSED(p, count);
    RdbxToJson *ctx = userData;

    /* One combined frame for elements array + wrapper object; the delimiter
     * separates elements (nothing is ever appended at the wrapper level). */
    if (unlikely(!jOpenUnder(ctx, JC_ARRAY)))
        return invalidState(p, ctx, __func__);
    if (insertIdx != RDB_ARRAY_INSERT_IDX_NONE)
        fprintf(ctx->outfile, "\"insert_idx\":\"%" PRIu64 "\",", insertIdx);
    fprintf(ctx->outfile, "\"elements\":[");

    return RDB_OK;
}

static RdbRes toJsonArrayElement(RdbParser *p, void *userData, uint64_t idx, RdbBulk value) {
    RdbxToJson *ctx = userData;

    if (jTop(ctx) != JC_ARRAY)
        return invalidState(p, ctx, __func__);

    jNewItem(ctx, JC_ARRAY);
    fprintf(ctx->outfile, "{\"idx\":\"%" PRIu64 "\",\"val\":", idx);
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    fprintf(ctx->outfile, "}");

    return RDB_OK;
}

/*** Handling struct ***/

static RdbRes toJsonStruct(RdbParser *p, void *userData, RdbBulk value) {
    RdbxToJson *ctx = userData;

    fprintf(ctx->outfile, "[");
    outputQuotedEscaping(ctx, value, RDB_bulkLen(p, value));
    fprintf(ctx->outfile, "]");

    return RDB_OK;
}

static RdbRes toJsonStreamLP(RdbParser *p, void *userData, RdbBulk nodekey, RdbBulk streamLP) {
    RdbxToJson *ctx = userData;

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
    ctx->encfunc(ctx->outfile, frag, RDB_bulkLen(p, frag));
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
