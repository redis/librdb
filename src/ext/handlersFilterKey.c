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

static RdbRes filterNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, info);
    RdbxFilterKey *ctx = userData;
    ctx->cbReturnValue = (regexec(&ctx->regex_compiled, key, 0, NULL, 0)) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    return ctx->cbReturnValue;
}

static RdbRes filterEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling data ***/

static RdbRes filterString(RdbParser *p, void *userData, RdbBulk str) {
    UNUSED(p, str);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterList(RdbParser *p, void *userData, RdbBulk item) {
    UNUSED(p, item);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    UNUSED(p, field, value);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling struct ***/

static RdbRes filterListLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterListZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterListPlain(RdbParser *p, void *userData, RdbBulk listNode) {
    UNUSED(p, listNode);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHashLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHashZM(RdbParser *p, void *userData, RdbBulk zipmap) {
    UNUSED(p, zipmap);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHashZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterHashPlain(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    UNUSED(p, field, value);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

/*** Handling raw ***/

static RdbRes filterFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p, frag);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p, size);
    return ((RdbxFilterKey *) userData)->cbReturnValue;
}

static RdbRes filterRawEnd(RdbParser *p, void *userData) {
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

    callbacks.common.handleNewKey = filterNewKey;
    callbacks.common.handleEndKey = filterEndKey;

    if (RDB_getNumHandlers(p, RDB_LEVEL_DATA)>0) {
        callbacks.dataCb.handleStringValue = filterString;
        callbacks.dataCb.handleListItem = filterList;
        callbacks.dataCb.handleHashField = filterHash;
        RDB_createHandlersData(p, &callbacks.dataCb, ctx, deleteFilterKeyCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_STRUCT)>0) {
        callbacks.structCb.handleString = filterString;
        /* list */
        callbacks.structCb.handleListLP = filterListLP;
        callbacks.structCb.handleListZL = filterListZL;
        callbacks.structCb.handleListPlain = filterListPlain;
        /* hash */
        callbacks.structCb.handleHashPlain = filterHashPlain;
        callbacks.structCb.handleHashZL = filterHashZL;
        callbacks.structCb.handleHashLP = filterHashLP;
        callbacks.structCb.handleHashZM = filterHashZM;
        RDB_createHandlersStruct(p, &callbacks.structCb, ctx, deleteFilterKeyCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_RAW)>0) {
        callbacks.rawCb.handleFrag = filterFrag;
        callbacks.rawCb.handleBegin = filterRawBegin;
        callbacks.rawCb.handleEnd = filterRawEnd;
        RDB_createHandlersRaw(p, &callbacks.rawCb, ctx, deleteFilterKeyCtx);
    }
    return ctx;
}
