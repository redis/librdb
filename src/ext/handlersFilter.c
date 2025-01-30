#include <regex.h>
#include <string.h>
#include "../lib/defines.h" /* valid include since it brings only RDB_* defines */
#include "extCommon.h"

struct RdbxFilter {
    regex_t regex_compiled;
    int exclude;
    RdbRes cbReturnValue;
    RdbDataType opToType[256]; /* Mapping opcode to type. init only in case of filter types being used */

    int regexInitialized;  /* for filter keys */
    RdbDataType type;      /* for filter types */
    int isExpireFilter;   /* for filter expired */
    int dbnum;             /* for filter db */
};

static void deleteFilterCtx(RdbParser *p, void *data) {
    RdbxFilter *ctx = (RdbxFilter *) data;
    if (ctx->regexInitialized) {
        regfree(&ctx->regex_compiled);
    }
    RDB_free(p, ctx);
}

/*** filtering BY key, type or dbnum ***/

static RdbRes filterNewKeyByRegex(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, info);
    RdbxFilter *ctx = userData;
    if (regexec(&ctx->regex_compiled, key, 0, NULL, 0) == 0) /* if match */
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    else
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;
}

static RdbRes filterNewKeyByType(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, key);
    RdbxFilter *ctx = userData;

    if (info->dataType == (int) ctx->type)
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    else
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;
}

static RdbRes filterNewKeyByExpiry(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, key);
    RdbxFilter *ctx = userData;

    /* if persistent key */
    if (info->expiretime == -1)
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;

    struct timeval te;
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;

    if (info->expiretime > milliseconds)
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;

    return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK_DONT_PROPAGATE
                                               : RDB_OK;
}

static RdbRes filterNewDbByNumber(RdbParser *p, void *userData,  int dbnum) {
    UNUSED(p);
    RdbxFilter *ctx = userData;
    if (dbnum == ctx->dbnum) /* if match */
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    else
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;
}

/*** Handling common ***/

static RdbRes filterNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p, key, info);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterNewDb(RdbParser *p, void *userData,  int dbnum) {
    UNUSED(p, dbnum);
    return ((RdbxFilter *) userData)->cbReturnValue = RDB_OK; /* clean possible leftovers */
}

static RdbRes filterDbSize(RdbParser *p, void *userData, uint64_t db_size, uint64_t exp_size) {
    UNUSED(p, db_size, exp_size);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

/*** Handling data ***/

static RdbRes filterString(RdbParser *p, void *userData, RdbBulk str) {
    UNUSED(p, str);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterList(RdbParser *p, void *userData, RdbBulk item) {
    UNUSED(p, item);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value, int64_t expireAt) {
    UNUSED(p, field, value, expireAt);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamMetadata(RdbParser *p, void *userData, RdbStreamMeta *meta) {
    UNUSED(p, meta);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamItem(RdbParser *p, void *userData, RdbStreamID *id, RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    UNUSED(p, id, field, value, itemsLeft);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamNewCGroup(RdbParser *p, void *userData, RdbBulk grpName, RdbStreamGroupMeta *meta) {
    UNUSED(p, grpName, meta);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamCGroupPendingEntry(RdbParser *p, void *userData, RdbStreamPendingEntry *pendingEntry) {
    UNUSED(p, pendingEntry);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamNewConsumer(RdbParser *p, void *userData, RdbBulk consName, RdbStreamConsumerMeta *meta) {
    UNUSED(p, consName, meta);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamConsumerPendingEntry(RdbParser *p, void *userData, RdbStreamID *streamId) {
    UNUSED(p, streamId);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

/*** Handling struct ***/

static RdbRes filterListLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterListZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterListPlain(RdbParser *p, void *userData, RdbBulk listNode) {
    UNUSED(p, listNode);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashLPEx(RdbParser *p, void *userData, RdbBulk listpackEx) {
    UNUSED(p, listpackEx);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashZM(RdbParser *p, void *userData, RdbBulk zipmap) {
    UNUSED(p, zipmap);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashPlain(RdbParser *p, void *userData, RdbBulk field, RdbBulk value, int64_t expireAt) {
    UNUSED(p, field, value, expireAt);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterSetMember(RdbParser *p, void *userData, RdbBulk member) {
    UNUSED(p, member);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterZsetMember(RdbParser *p, void *userData, RdbBulk member, double score) {
    UNUSED(p, userData, member, score);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterSetPlain(RdbParser *p, void *userData, RdbBulk item) {
    UNUSED(p, item);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterSetIS(RdbParser *p, void *userData, RdbBulk intset) {
    UNUSED(p, intset);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterSetLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterZsetPlain(RdbParser *p, void *userData, RdbBulk item, double score) {
    UNUSED(p, item, score);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterZsetZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterZsetLP(RdbParser *p, void *userData, RdbBulk listpack) {
    UNUSED(p, listpack);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterFunction(RdbParser *p, void *userData, RdbBulk func) {
    UNUSED(p, func);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterModule(RdbParser *p, void *userData, RdbBulk moduleName, size_t serializedSize) {
    UNUSED(p, moduleName, serializedSize);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterStreamLP(RdbParser *p, void *userData, RdbBulk nodekey, RdbBulk streamLP) {
    UNUSED(p, nodekey, streamLP);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

/*** Handling raw ***/

static RdbRes filterFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p, frag);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p, size);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterRawEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

/*** common init ***/

static void defaultFilterDataCb(RdbHandlersDataCallbacks *dataCb) {
    static const RdbHandlersDataCallbacks defDataCb = {
        NULL,                               /*handleStartRdb*/
        NULL,                               /*handleEndRdb*/
        filterNewDb,                        /*handleNewDb*/
        filterDbSize,                       /*handleDbSize*/
        NULL,                               /*handleSlotInfo*/
        NULL,                               /*handleAuxField*/
        filterNewKey,                       /*handleNewKey*/
        filterEndKey,                       /*handleEndKey*/
        filterString,                       /*handleStringValue*/
        filterList,                         /*handleListItem*/
        filterHash,                         /*handleHashField*/
        filterSetMember,                    /*handleSetMember*/
        filterZsetMember,                   /*handleZsetMember*/
        filterFunction,                     /*handleFunction*/
        filterModule,                       /*handleModule*/
        filterStreamMetadata,               /*handleStreamMetadata*/
        filterStreamItem,                   /*handleStreamItem*/
        filterStreamNewCGroup,              /*handleStreamNewCGroup*/
        filterStreamCGroupPendingEntry,     /*handleStreamCGroupPendingEntry*/
        filterStreamNewConsumer,            /*handleStreamNewConsumer*/
        filterStreamConsumerPendingEntry,   /*handleStreamConsumerPendingEntry*/
    };
    *dataCb = defDataCb;
}

static void defaultFilterStructCb(RdbHandlersStructCallbacks *structCb) {
    static const RdbHandlersStructCallbacks defStructCb = {
        NULL,                               /*handleStartRdb*/
        NULL,                               /*handleEndRdb*/
        filterNewDb,                        /*handleNewDb*/
        filterDbSize,                       /*handleDbSize*/
        NULL,                               /*handleSlotInfo*/
        NULL,                               /*handleAuxField*/
        filterNewKey,                       /*handleNewKey*/
        filterEndKey,                       /*handleEndKey*/
        filterString,                       /*handleString*/
        filterListPlain,                    /*handleListPlain*/
        filterListZL,                       /*handleListZL*/
        filterListLP,                       /*handleListLP*/
        filterHashPlain,                    /*handleHashPlain*/
        filterHashZL,                       /*handleHashZL*/
        filterHashLP,                       /*handleHashLP*/
        filterHashLPEx,                     /*handleHashLPEx*/
        filterHashZM,                       /*handleHashZM*/
        filterSetPlain,                     /*handleSetPlain*/
        filterSetIS,                        /*handleSetIS*/
        filterSetLP,                        /*handleSetLP*/
        filterZsetPlain,                    /*handleZsetPlain*/
        filterZsetZL,                       /*handleZsetZL*/
        filterZsetLP,                       /*handleZsetLP*/
        filterFunction,                     /*handleFunction*/
        filterModule,                       /*handleModule*/
        filterStreamLP,                     /*handleStreamLP*/
    };
    *structCb = defStructCb;
}

static void defaultFilterRawCb(RdbHandlersRawCallbacks *rawCb) {
    static const RdbHandlersRawCallbacks defRawCb = {
        NULL,                               /*handleStartRdb*/
        NULL,                               /*handleEndRdb*/
        filterNewDb,                        /*handleNewDb*/
        filterDbSize,                       /*handleDbSize*/
        NULL,                               /*handleSlotInfo*/
        NULL,                               /*handleAuxField*/
        filterNewKey,                       /*handleNewKey*/
        filterEndKey,                       /*handleEndKey*/
        NULL,                               /*handleBeginModuleAux (Not part of keyspace)*/
        filterRawBegin,                     /*handleBegin*/
        filterFrag,                         /*handleFrag*/
        filterRawEnd                        /*handleEnd*/
    };
    *rawCb = defRawCb;
}

static RdbxFilter *createHandlersFilterCommon(RdbParser *p,
                                              const char *keyRegex,
                                              RdbDataType *type,
                                              int *dbnum,
                                              int isExpireFilter,
                                              uint32_t exclude) {
    RdbRes (*handleNewKey)(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) = filterNewKey;
    RdbRes (*handleNewDb)(RdbParser *p, void *userData,  int dbnum) = filterNewDb;
    RdbxFilter *ctx;

    if ( (ctx = RDB_alloc(p, sizeof(RdbxFilter))) == NULL)
        return NULL;
    memset(ctx, 0, sizeof(RdbxFilter));

    /* specific if-else init to filter regex/type/dbnum */
    if (keyRegex) {   /* filter keys by regex */
        int rc;
        /* compile the regular expression */
        if ( (rc = regcomp(&ctx->regex_compiled, keyRegex, REG_EXTENDED)) != 0) {
            char    buff[1024];
            regerror(rc, &ctx->regex_compiled, buff, sizeof(buff));
            RDB_reportError(p, (RdbRes) RDBX_ERR_FILTER_FAILED_COMPILE_REGEX,
                            "FilterKey: Error compiling regular expression: %s", buff);
            deleteFilterCtx(p, ctx);
            return NULL;
        }
        ctx->regexInitialized = 1;
        handleNewKey = filterNewKeyByRegex;
    } else if (type) { /* filter keys by type */
        ctx->type = *type;
        handleNewKey = filterNewKeyByType;
    } else if (isExpireFilter) {
        ctx->isExpireFilter = 1;
        handleNewKey = filterNewKeyByExpiry;
    } else {  /* filter by dbnum */
        ctx->dbnum = *dbnum;
        handleNewDb = filterNewDbByNumber;
    }

    ctx->exclude = exclude;
    ctx->cbReturnValue = RDB_OK;

    if (RDB_getNumHandlers(p, RDB_LEVEL_DATA)>0) {
        RdbHandlersDataCallbacks dataCb;
        defaultFilterDataCb(&dataCb);
        dataCb.handleNewKey = handleNewKey;
        dataCb.handleNewDb = handleNewDb;
        RDB_createHandlersData(p, &dataCb, ctx, deleteFilterCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_STRUCT)>0) {
        RdbHandlersStructCallbacks structCb;
        defaultFilterStructCb(&structCb);
        structCb.handleNewKey = handleNewKey;
        structCb.handleNewDb = handleNewDb;
        RDB_createHandlersStruct(p, &structCb, ctx, deleteFilterCtx);
    }

    if (RDB_getNumHandlers(p, RDB_LEVEL_RAW)>0) {
        RdbHandlersRawCallbacks rawCb;
        defaultFilterRawCb(&rawCb);
        rawCb.handleNewKey = handleNewKey;
        rawCb.handleNewDb = handleNewDb;
        RDB_createHandlersRaw(p, &rawCb, ctx, deleteFilterCtx);
    }
    return ctx;
}

/*** API ***/

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterKey(RdbParser *p, const char *keyRegex, uint32_t exclude) {
    return createHandlersFilterCommon(p, keyRegex, NULL, NULL, 0, exclude);
}

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterType(RdbParser *p, RdbDataType type, uint32_t exclude) {
    return createHandlersFilterCommon(p, NULL, &type, NULL, 0, exclude);
}

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterDbNum(RdbParser *p, int dbnum, uint32_t exclude) {
    return createHandlersFilterCommon(p, NULL, NULL, &dbnum, 0, exclude);
}

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterExpired(RdbParser *p, uint32_t exclude) {
    return createHandlersFilterCommon(p, NULL, NULL, NULL, 1, exclude);
}
