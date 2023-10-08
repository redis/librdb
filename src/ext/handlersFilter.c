#include <regex.h>
#include <string.h>
#include "../lib/defines.h" /* valid include since it brings only RDB_* defines */
#include "common.h"

struct RdbxFilter {
    regex_t regex_compiled;
    int exclude;
    RdbRes cbReturnValue;
    RdbDataType opToType[256]; /* Mapping opcode to type. init only in case of filter types being used */

    int regexInitialized;  /* for filter keys */
    RdbDataType type;      /* for filter types */
    int dbnum;             /* for filter db */
};

static void deleteFilterCtx(RdbParser *p, void *data) {
    RdbxFilter *ctx = (RdbxFilter *) data;
    if (ctx->regexInitialized) {
        regfree(&ctx->regex_compiled);
    }
    RDB_free(p, ctx);
}

/* mapping opcode to type */
static void initOpcodeToType(RdbxFilter *ctx) {
    memset(ctx->opToType, 0, sizeof(ctx->opToType));
    /*string*/
    ctx->opToType[RDB_TYPE_STRING] = RDB_DATA_TYPE_STRING;
    /*list*/
    ctx->opToType[RDB_TYPE_LIST] = RDB_DATA_TYPE_LIST;
    ctx->opToType[RDB_TYPE_LIST_ZIPLIST] = RDB_DATA_TYPE_LIST;
    ctx->opToType[RDB_TYPE_LIST_QUICKLIST] = RDB_DATA_TYPE_LIST;
    ctx->opToType[RDB_TYPE_LIST_QUICKLIST_2] = RDB_DATA_TYPE_LIST;
    /*set*/
    ctx->opToType[RDB_TYPE_SET] = RDB_DATA_TYPE_SET;
    ctx->opToType[RDB_TYPE_SET_INTSET] = RDB_DATA_TYPE_SET;
    ctx->opToType[RDB_TYPE_SET_LISTPACK] = RDB_DATA_TYPE_SET;
    /*zset*/
    ctx->opToType[RDB_TYPE_ZSET] = RDB_DATA_TYPE_ZSET;
    ctx->opToType[RDB_TYPE_ZSET_2] = RDB_DATA_TYPE_ZSET;
    ctx->opToType[RDB_TYPE_ZSET_ZIPLIST] = RDB_DATA_TYPE_ZSET;
    ctx->opToType[RDB_TYPE_ZSET_LISTPACK] = RDB_DATA_TYPE_ZSET;
    /*hash*/
    ctx->opToType[RDB_TYPE_HASH] = RDB_DATA_TYPE_HASH;
    ctx->opToType[RDB_TYPE_HASH_ZIPMAP] = RDB_DATA_TYPE_HASH;
    ctx->opToType[RDB_TYPE_HASH_ZIPLIST] = RDB_DATA_TYPE_HASH;
    ctx->opToType[RDB_TYPE_HASH_LISTPACK] = RDB_DATA_TYPE_HASH;
    /*module*/
    ctx->opToType[RDB_TYPE_MODULE_2] = RDB_DATA_TYPE_MODULE;
    ctx->opToType[RDB_OPCODE_MODULE_AUX] = RDB_DATA_TYPE_MODULE;
    /*stream*/
    ctx->opToType[RDB_TYPE_STREAM_LISTPACKS] = RDB_DATA_TYPE_STREAM;
    ctx->opToType[RDB_TYPE_STREAM_LISTPACKS_2] = RDB_DATA_TYPE_STREAM;
    ctx->opToType[RDB_TYPE_STREAM_LISTPACKS_3] = RDB_DATA_TYPE_STREAM;
    /*func*/
    ctx->opToType[RDB_OPCODE_FUNCTION2] = RDB_DATA_TYPE_FUNCTION;
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
    if (ctx->opToType[info->opcode] == ctx->type) /* if match */
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK_DONT_PROPAGATE : RDB_OK;
    else
        return ctx->cbReturnValue = (ctx->exclude) ? RDB_OK : RDB_OK_DONT_PROPAGATE;
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

static RdbRes filterHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    UNUSED(p, field, value);
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

static RdbRes filterHashZM(RdbParser *p, void *userData, RdbBulk zipmap) {
    UNUSED(p, zipmap);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashZL(RdbParser *p, void *userData, RdbBulk ziplist) {
    UNUSED(p, ziplist);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterHashPlain(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    UNUSED(p, field, value);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterSetMember(RdbParser *p, void *userData, RdbBulk member) {
    UNUSED(p, member);
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

static RdbRes filterFunction(RdbParser *p, void *userData, RdbBulk func) {
    UNUSED(p, func);
    return ((RdbxFilter *) userData)->cbReturnValue;
}

static RdbRes filterModule(RdbParser *p, void *userData, RdbBulk moduleName, size_t serializedSize) {
    UNUSED(p, moduleName, serializedSize);
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
    memset(dataCb, 0, sizeof(*dataCb));
    dataCb->handleNewKey = filterNewKey;
    dataCb->handleEndKey = filterEndKey;
    dataCb->handleNewDb = filterNewDb;
    dataCb->handleDbSize = filterDbSize;

    dataCb->handleStringValue = filterString;
    dataCb->handleListItem = filterList;
    dataCb->handleHashField = filterHash;
    dataCb->handleSetMember = filterSetMember;
    dataCb->handleFunction = filterFunction;
    dataCb->handleModule = filterModule;
}

static void defaultFilterStructCb(RdbHandlersStructCallbacks *structCb) {
    memset(structCb, 0, sizeof(*structCb));
    /* common */
    structCb->handleNewKey = filterNewKey;
    structCb->handleEndKey = filterEndKey;
    structCb->handleNewDb = filterNewDb;
    structCb->handleDbSize = filterDbSize;

    /* string */
    structCb->handleString = filterString;
    /* list */
    structCb->handleListLP = filterListLP;
    structCb->handleListZL = filterListZL;
    structCb->handleListPlain = filterListPlain;
    /* hash */
    structCb->handleHashPlain = filterHashPlain;
    structCb->handleHashZL = filterHashZL;
    structCb->handleHashLP = filterHashLP;
    structCb->handleHashZM = filterHashZM;

    /* set */
    structCb->handleSetPlain = filterSetPlain;
    structCb->handleHashZM = filterSetIS;
    structCb->handleSetLP = filterSetLP;

    /* func */
    structCb->handleFunction = filterFunction;
    /* module */
    structCb->handleModule = filterModule;
}

static void defaultFilterRawCb(RdbHandlersRawCallbacks *rawCb) {
    memset(rawCb, 0, sizeof(*rawCb));
    /* common */
    rawCb->handleNewKey = filterNewKey;
    rawCb->handleEndKey = filterEndKey;
    rawCb->handleNewDb = filterNewDb;
    rawCb->handleDbSize = filterDbSize;

    //callbacks.rawCb.handleBeginModuleAux  /* not part of keyspace */
    rawCb->handleBegin = filterRawBegin;
    rawCb->handleFrag = filterFrag;
    rawCb->handleEnd = filterRawEnd;
}

static RdbxFilter *createHandlersFilterCommon(RdbParser *p,
                                              const char *keyRegex,
                                              RdbDataType *type,
                                              int *dbnum,
                                              uint32_t exclude) {
    RdbRes (*handleNewKey)(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) = filterNewKey;
    RdbRes (*handleNewDb)(RdbParser *p, void *userData,  int dbnum) = filterNewDb;
    RdbxFilter *ctx;

    if ( (ctx = RDB_alloc(p, sizeof(RdbxFilter))) == NULL)
        return NULL;

    ctx->regexInitialized = 0;

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
        initOpcodeToType(ctx);
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
    return createHandlersFilterCommon(p, keyRegex, NULL, NULL, exclude);
}

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterType(RdbParser *p, RdbDataType type, uint32_t exclude) {
    return createHandlersFilterCommon(p, NULL, &type, NULL, exclude);
}

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterDbNum(RdbParser *p, int dbnum, uint32_t exclude) {
    return createHandlersFilterCommon(p, NULL, NULL, &dbnum, exclude);
}
