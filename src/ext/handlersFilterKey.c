#include <regex.h>
#include <string.h>
#include "common.h"

struct RdbxFilterKey {
    regex_t regex_compiled;
    int regexInitialized;
    int regex_cflags;
    int filteroutKey;
    RdbRes cbReturnValue;
};

static void deleteFilterKeyCtx(RdbParser *p, void *data) {
    RdbxFilterKey *ctx = (RdbxFilterKey *) data;
    if (ctx->regexInitialized) {
        regfree(&ctx->regex_compiled);
    }

    RDB_free(p, ctx);
}

/*** Handling common ***/

static RdbRes filterHandlingNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, info);
    RdbxFilterKey *ctx = userData;
    ctx->cbReturnValue = (regexec(&ctx->regex_compiled, key, 0, NULL, 0)) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    return ctx->cbReturnValue;
}

static RdbRes filterHandlingEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling data ***/

static RdbRes filterHandlingString(RdbParser *p, void *userData, RdbBulk value) {
    UNUSED(p, value);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHandlingList(RdbParser *p, void *userData, RdbBulk str) {
    UNUSED(p, str);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling struct ***/

static RdbRes filterHandlingQListNode(RdbParser *p, void *userData, RdbBulk listNode) {
    UNUSED(p, listNode);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling raw ***/

static RdbRes filterHandlingFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p, frag);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHandlingRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p, size);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHandlingRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

RdbxFilterKey *RDBX_createHandlersFilterKey(RdbParser *p,
                                            const char *keyRegex,
                                            uint32_t flags)
{
    RdbxFilterKey *ctx;
    UNUSED(flags);

    CallbacksUnion callbacks;
    memset (&callbacks, 0, sizeof(callbacks));

    if ( (ctx = RDB_alloc(p, sizeof(RdbxFilterKey))) == NULL)
        return NULL;

    ctx->regexInitialized = 0;

    // compile the regular expression
    if (regcomp(&ctx->regex_compiled, keyRegex, REG_EXTENDED) != 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_FILTER_FAILED_COMPILE_REGEX,
                        "FilterKey: Error compiling regular expression");
        deleteFilterKeyCtx(p, ctx);
        return NULL;
    } else {
        ctx->regexInitialized = 1;
    }

    callbacks.common.handleNewKey = filterHandlingNewKey;
    callbacks.common.handleEndKey = filterHandlingEndKey;

    if (RDB_getNumHandlers(p, RDB_LEVEL_DATA)>0) {
        callbacks.dataCb.handleStringValue = filterHandlingString;
        callbacks.dataCb.handleListElement = filterHandlingList;
        RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteFilterKeyCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_STRUCT)>0) {
        callbacks.structCb.handleStringValue = filterHandlingString;
        callbacks.structCb.handlerQListNode = filterHandlingQListNode;
        callbacks.structCb.handlerPlainNode = filterHandlingList;
        RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteFilterKeyCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_RAW)>0) {
        callbacks.rawCb.handleFrag = filterHandlingFrag;
        callbacks.rawCb.handleBegin = filterHandlingRawBegin;
        callbacks.rawCb.handleEnd = filterHandlingRawEnd;
        RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteFilterKeyCtx);
    }
    return ctx;
}
