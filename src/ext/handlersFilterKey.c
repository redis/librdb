#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include "common.h"

typedef struct FilterKeyCtx {
    regex_t regex_compiled;
    int regexInitialized;
    int regex_cflags;
    int filteroutKey;
    RdbRes cbReturnValue;
} FilterKeyCtx;

static void deleteFilterKeyCtx(RdbParser *p, void *data) {
    FilterKeyCtx *ctx = (FilterKeyCtx *) data;
    if (ctx->regexInitialized) {
        regfree(&ctx->regex_compiled);
    }

    RDB_free(p, ctx);
}

/*** Handling common ***/

static RdbRes filterHandlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, info);
    FilterKeyCtx *ctx = (FilterKeyCtx *) userData;
    ctx->cbReturnValue = (regexec(&ctx->regex_compiled, key, 0, NULL, 0)) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    return ctx->cbReturnValue;
}

static RdbRes filterHandlingEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

/*** Handling data ***/

static RdbRes filterHandlingString(RdbParser *p, void *userData, RdbBulk value) {
    UNUSED(p, value);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

static RdbRes filterHandlingList(RdbParser *p, void *userData, RdbBulk str) {
    UNUSED(p, str);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

/*** Handling struct ***/

static RdbRes filterHandlingQListNode(RdbParser *p, void *userData, RdbBulk listNode) {
    UNUSED(p, listNode);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

/*** Handling raw ***/

static RdbRes filterHandlingFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p, frag);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

static RdbRes filterHandlingRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p, size);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

static RdbRes filterHandlingRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((FilterKeyCtx *) userData)->cbReturnValue;
}

RdbHandlers *RDBX_createHandlersFilterKey(RdbParser *p,
                                            const char *keyRegex,
                                            uint32_t flags,
                                            RdbHandlersLevel lvl) {
    UNUSED(flags);

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));

    FilterKeyCtx *ctx = RDB_alloc(p, sizeof(FilterKeyCtx));
    ctx->regexInitialized = 0;

    // compile the regular expression
    if (regcomp(&ctx->regex_compiled, keyRegex, REG_EXTENDED) != 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_R2J_FAILED_COMPILING_REGEX,
                        "FilterKey: Error compiling regular expression");
        deleteFilterKeyCtx(p, ctx);
        return NULL;
    } else {
        ctx->regexInitialized = 1;
    }

    callbacks.common.handleNewKey = filterHandlingNewKey;
    callbacks.common.handleEndKey = filterHandlingEndKey;
    if (lvl == RDB_LEVEL_DATA) {
        callbacks.dataCb.handleStringValue = filterHandlingString;
        callbacks.dataCb.handleListElement = filterHandlingList;
        return RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteFilterKeyCtx);
    }

    if (lvl == RDB_LEVEL_STRUCT) {
        callbacks.structCb.handleStringValue = filterHandlingString;
        callbacks.structCb.handlerQListNode = filterHandlingQListNode;
        callbacks.structCb.handlerPlainNode = filterHandlingList;
        return RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteFilterKeyCtx);
    }

    /* else (lvl == RDB_LEVEL_RAW) */
    callbacks.rawCb.handleFrag = filterHandlingFrag;
    callbacks.rawCb.handleBegin = filterHandlingRawBegin;
    callbacks.rawCb.handleEnd = filterHandlingRawEnd;
    return RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteFilterKeyCtx);
}
