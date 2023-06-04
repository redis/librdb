/*
 * It is recommended to read the "Parser implementation notes" section
 * in the README.md file as an introduction to this file implementation.
 */

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../deps/redis/crc64.h"
#include "bulkAlloc.h"
#include "parser.h"
#include "defines.h"
#include "../../deps/redis/endianconv.h"
#include "../../deps/redis/utils.h"
#include "../../deps/redis/listpack.h"
#include "../../deps/redis/lzf.h"

#define DONE_FILL_BULK SIZE_MAX

struct ParsingElementInfo peInfo[PE_MAX] = {
        [PE_RDB_HEADER]       = {elementRdbHeader, "elementRdbHeader", "Start parsing RDB header"},
        [PE_NEXT_RDB_TYPE]    = {elementNextRdbType, "elementNextRdbType", "Parsing next RDB type"},
        [PE_AUX_FIELD]        = {elementAuxField, "elementAuxField", "Parsing auxiliary field" },
        [PE_SELECT_DB]        = {elementSelectDb, "elementSelectDb", "Parsing select-db"},
        [PE_RESIZE_DB]        = {elementResizeDb, "elementResizeDb", "Parsing resize-db"},
        [PE_EXPIRETIME]       = {elementExpireTime, "elementExpireTime", "Parsing expire-time"},
        [PE_EXPIRETIMEMSEC]   = {elementExpireTimeMsec, "elementExpireTimeMsec", "Parsing expire-time-msec"},

        /* parsing struct/data (RDB_LEVEL_STRUCT/RDB_LEVEL_DATA) */
        [PE_NEW_KEY]          = {elementNewKey, "elementNewKey", "Parsing new key-value"},
        [PE_END_KEY]          = {elementEndKey, "elementEndKey", "Parsing end key"},
        [PE_STRING]           = {elementString, "elementString", "Parsing string"},
        [PE_LIST]             = {elementList, "elementList", "Parsing list"},

        /* parsing raw data (RDB_LEVEL_RAW) */
        [PE_RAW_NEW_KEY]      = {elementRawNewKey, "elementRawNewKey", "Parsing new raw key-value"},
        [PE_RAW_END_KEY]      = {elementRawEndKey, "elementRawEndKey", "Parsing raw end key"},
        [PE_RAW_STRING]       = {elementRawString, "elementRawString", "Parsing raw string"},
        [PE_RAW_LIST]         = {elementRawList, "elementRawList", "Parsing raw list"},

        [PE_END_OF_FILE]      = {elementEndOfFile, "elementEndOfFile", "End parsing RDB file"},
};

/*** Environemnt Variables ***/
const char *ENV_VAR_SIM_WAIT_MORE_DATA = "LIBRDB_SIM_WAIT_MORE_DATA"; /* simulate RDB_STATUS_WAIT_MORE_DATA by RDB reader */
const char *ENV_VAR_DEBUG_DATA = "LIBRDB_DEBUG_DATA";  /* to print parsing-elements and theirs states */

/*** various static functions (declaration) ***/

/*** cache ***/
static inline void rollbackCache(RdbParser *p);

/*** release blocks on termination ***/
static void releaseReader(RdbParser *p);
static void releaseHandlers(RdbParser *p, RdbHandlers *h);

/*** parsing flow ***/
static RdbStatus finalizeConfig(RdbParser *p, int isParseFromBuff);
static RdbStatus parserMainLoop(RdbParser *p);

/*** misc ***/
static RdbHandlers *createHandlersCommon(RdbParser *p, void *userData, RdbFreeFunc f, RdbHandlersLevel level);
static void loggerCbDefault(RdbLogLevel l, const char *msg);
static inline RdbStatus updateStateAfterParse(RdbParser *p, RdbStatus status);
static void printParserState(RdbParser *p);

/*** RDB Reader function ***/
static RdbStatus readRdbFromReader(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo);
static RdbStatus readRdbFromBuff(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo);
static RdbStatus readRdbWaitMoreDataDbg(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo);

/*** LIB API functions ***/

_LIBRDB_API RdbParser *RDB_createParserRdb(RdbMemAlloc *memAlloc) {
    RdbParser *p;

    /* init default memory allocation */
    RdbMemAlloc mem = {
        .malloc=malloc,
        .realloc=realloc,
        .free=free,
        .bulkAllocType=RDB_BULK_ALLOC_STACK
    };

    if (memAlloc) mem = *memAlloc;

    if ( (p = mem.malloc(sizeof(RdbParser))) == NULL)
        return NULL;

    memset(p, 0, sizeof(RdbParser) );

    p->state = RDB_STATE_CONFIGURING;

    p->callSubElm.callerElm = PE_MAX;
    p->callSubElm.bulkResult.ref = NULL;

    p->mem = mem;
    p->reader = NULL;
    p->cache = NULL;
    p->errorMsg[0] = '\0';
    p->appCbCtx.numBulks = 0;
    p->loggerCb = loggerCbDefault;
    p->logLevel = RDB_LOG_DBG;
    p->maxRawLen = SIZE_MAX;
    p->errorCode = RDB_OK;
    p->handlers[RDB_LEVEL_RAW] = NULL;
    p->handlers[RDB_LEVEL_STRUCT] = NULL;
    p->handlers[RDB_LEVEL_DATA] = NULL;
    p->numHandlers[RDB_LEVEL_RAW] = 0;
    p->numHandlers[RDB_LEVEL_STRUCT] = 0;
    p->numHandlers[RDB_LEVEL_DATA] = 0;
    p->totalHandlers = 0;
    p->firstHandlers = NULL;

    for (int i = 0 ; i < RDB_TYPE_MAX ; ++i) {
        p->handleTypeObjByLevel[i] = RDB_LEVEL_MAX;
    }

    p->elmCtx.state = 0;
    p->parsingElement = PE_RDB_HEADER;

    p->elmCtx.key.info.expiretime = -1;
    p->elmCtx.key.info.lru_idle = -1;
    p->elmCtx.key.info.lfu_freq = -1;

    p->currOpcode = UINT32_MAX;
    p->deepIntegCheck = 1;
    p->ignoreChecksum = 0;

    /*** RDB_parseBuff related data ***/
    p->isParseFromBuff = 0;
    p->bytesRead = 0;
    p->parsebuffCtx.start = NULL;
    p->parsebuffCtx.size = 0;
    p->parsebuffCtx.at = NULL;
    p->parsebuffCtx.end = NULL;


    p->pauseInterval = 0;
    p->bytesToNextPause = SIZE_MAX;

    p->checksum = 0;
    p->rdbversion = 0;

    parserRawInit(p);

    return p;
}

_LIBRDB_API void RDB_deleteParser(RdbParser *p) {
    BulkPool *pool = p->cache;

    bulkUnmanagedFree(p, &p->callSubElm.bulkResult);

    parserRawRelease(p);

    /* release reader */
    releaseReader(p);

    /* release all handlers */
    releaseHandlers(p, p->firstHandlers);

    if (pool) bulkPoolRelease(p);
    p->mem.free(p);
}

_LIBRDB_API RdbStatus RDB_parse(RdbParser *p) {
    if (p->state == RDB_STATE_CONFIGURING)
        IF_NOT_OK_RETURN(finalizeConfig(p, 0));

    /* nothing special to do after pause */
    if (p->state == RDB_STATE_PAUSED)
        p->state = RDB_STATE_RUNNING;

    return parserMainLoop(p);
}

_LIBRDB_API RdbStatus RDB_parseBuff(RdbParser *p, unsigned char *buff, size_t size, int isEOF) {

    if (p->state == RDB_STATE_CONFIGURING)
        IF_NOT_OK_RETURN(finalizeConfig(p, 1));

    if (p->state != RDB_STATE_PAUSED)
    {
        /* track buffer consumption in parser context */
        p->parsebuffCtx.start = buff;
        p->parsebuffCtx.size = size;
        p->parsebuffCtx.at = buff;
        p->parsebuffCtx.end = buff + size;
    } else {
        /* after pause verify that given buff is exactly as before */
        if (buff != p->parsebuffCtx.start || p->parsebuffCtx.size != size) {
            RDB_reportError(p, RDB_ERR_PARSEBUF_AFTER_PAUSE_NOT_SAME_BUFF,
                "RDB_parseBuff(): Expected to continue parse same buffer that was parsed before the pause.");
            return RDB_STATUS_ERROR;
        }

        p->state = RDB_STATE_RUNNING;
    }

    RdbStatus status = parserMainLoop(p);

    if (isEOF) {
        if (status == RDB_STATUS_WAIT_MORE_DATA) {
            RDB_reportError(p, RDB_ERR_EXP_EOF_BUT_PARSER_WAIT_MORE_DATA,
                "RDB_parseBuff(): Expected EOF but parser return RDB_STATUS_WAIT_MORE_DATA");
            return RDB_STATUS_ERROR;
        }
    }

    return status;
}

_LIBRDB_API RdbReader *RDB_createReaderRdb(RdbParser *p, RdbReaderFunc r, void *readerData, RdbFreeFunc freeReaderData) {
    assert(p->state == RDB_STATE_CONFIGURING);

    /* if previously allocated reader, then release it first */
    releaseReader(p);

    /* alloc & register new reader in parser */
    p->reader = (RdbReader *) RDB_alloc(p, sizeof(RdbReader));
    memset(p->reader, 0, sizeof(RdbReader));
    p->reader->parser = p;
    p->reader->readFunc = r;
    p->reader->readerData = readerData;
    p->reader->destructor = freeReaderData;
    return p->reader;
}

_LIBRDB_API size_t RDB_bulkLen(RdbParser *p, RdbBulk b) {
    for (int i = 0 ; i < p->appCbCtx.numBulks ; ++i) {
        if (likely(p->appCbCtx.bulks[i]->ref == b))
            return p->appCbCtx.bulks[i]->len;
    }

    RDB_reportError(p, RDB_ERR_INVALID_BULK_LENGTH_REQUEST,
        "Invalid RDB_bulkLen() request. Couldn't find application-bulk with address: %p", b);

    return 0;
}

/* if app configured RDB_BULK_ALLOC_EXTERN_OPT, then let's just return reference
 * bulk when possible. In this case the application callbacks cannot make any
 * assumption about the allocated memory layout of RdbBulk. It can assist function
 * RDB_isRefBulk to resolve whether given bulk was allocated by its external
 * allocator or optimized with reference bulk.
 */
_LIBRDB_API int RDB_isRefBulk(RdbParser *p, RdbBulk b) {
    for (int i = 0 ; i < p->appCbCtx.numBulks ; ++i) {
        if (likely(p->appCbCtx.bulks[i]->ref == b))
            return p->appCbCtx.bulks[i]->bulkType == BULK_TYPE_REF;
    }

    RDB_reportError(p, RDB_ERR_INVALID_IS_REF_BULK,
        "Invalid RDB_isRefBulk() request. Couldn't find application-bulk with address: %p", b);
    return 0;
}

_LIBRDB_API RdbBulkCopy RDB_bulkClone(RdbParser *p, RdbBulk b) {

    for (int i = 0 ; i < p->appCbCtx.numBulks ; ++i) {
        if (likely(p->appCbCtx.bulks[i]->ref == b))
            return bulkClone(p, p->appCbCtx.bulks[i]);
    }

    RDB_reportError(p, RDB_ERR_INVALID_BULK_CLONE_REQUEST,
        "Invalid RDB_bulkClone() request. Couldn't find application-bulk with address: %p", b);

    return NULL;
}

_LIBRDB_API void RDB_setPauseInterval(RdbParser *p, size_t interval) {
    p->pauseInterval = interval;
}

_LIBRDB_API void RDB_pauseParser(RdbParser *p) {
    p->bytesToNextPause = p->bytesRead;
}

_LIBRDB_API void RDB_setLogger(RdbParser *p, RdbLoggerCB f) {
    p->loggerCb = f;
}

_LIBRDB_API void RDB_IgnoreChecksum(RdbParser *p) {
    p->ignoreChecksum = 1;
}

_LIBRDB_API void RDB_setMaxRawLenHandling(RdbParser *p, size_t size) {
    p->maxRawLen = size;
}

_LIBRDB_API void RDB_log(RdbParser *p, RdbLogLevel lvl, const char *format, ...) {
    if (lvl <= p->logLevel)
    {
        va_list args;
        va_start (args, format);
        char buffer[1024] = {0};
        vsnprintf(buffer, sizeof(buffer), format, args);
        p->loggerCb(lvl, buffer);
        va_end(args);
        return;
    }
}

_LIBRDB_API void RDB_setLogLevel(RdbParser *p, RdbLogLevel l) {
    p->logLevel = l;
}

_LIBRDB_API void RDB_setDeepIntegCheck(RdbParser *p, int deep) {
    p->deepIntegCheck = !!deep;
}

_LIBRDB_API size_t RDB_getBytesProcessed(RdbParser *p) {
    return p->bytesRead;
}

_LIBRDB_API int RDB_getRdbVersion(RdbParser *p) {
    return p->rdbversion;
}

_LIBRDB_API RdbState RDB_getState(RdbParser *p) {
    return p->state;
}

_LIBRDB_API int RDB_getNumHandlers(RdbParser *p, RdbHandlersLevel lvl) {
    return p->numHandlers[lvl];
}

_LIBRDB_API RdbRes RDB_getErrorCode(RdbParser *p) {
    return p->errorCode;
}

_LIBRDB_API void RDB_reportError(RdbParser *p, RdbRes e, const char *msg, ...) {
    int nchars = 0;
    p->errorCode = e;

    if (msg == NULL) {
        p->errorMsg[0] = '\0';
        return;
    }

    /* RDB_OK & RDB_OK_DONT_PROPAGATE - not a real errors to report */
    assert (e != RDB_OK && e != RDB_OK_DONT_PROPAGATE);

    if (p->state == RDB_STATE_RUNNING) {
        nchars = snprintf(p->errorMsg, MAX_ERROR_MSG, "[%s::State=%d] ",
                          peInfo[p->parsingElement].funcname,
                          p->elmCtx.state);
    }

    va_list args;
    va_start(args, msg);
    vsnprintf(p->errorMsg + nchars, MAX_ERROR_MSG - nchars, msg, args);
    va_end(args);

    RDB_log(p, RDB_LOG_ERROR, p->errorMsg);
}

_LIBRDB_API const char *RDB_getErrorMessage(RdbParser *p) {
    return p->errorMsg;
}

_LIBRDB_API void *RDB_alloc(RdbParser *p, size_t size) {
    return p->mem.malloc((size));
}

_LIBRDB_API void *RDB_realloc(RdbParser *p, void *ptr, size_t size) {
    return p->mem.realloc(ptr, size);
}

_LIBRDB_API void RDB_free(RdbParser *p, void *ptr) {
    p->mem.free(ptr);
}

_LIBRDB_API RdbHandlers *RDB_createHandlersRaw(RdbParser *p,
                                               RdbHandlersRawCallbacks *callbacks,
                                               void *userData,
                                               RdbFreeFunc freeUserData) {
    RdbHandlers *hndl = createHandlersCommon(p, userData, freeUserData, RDB_LEVEL_RAW);
    hndl->h.rdbRaw = *callbacks;
    return hndl;
}

_LIBRDB_API RdbHandlers *RDB_createHandlersStruct(RdbParser *p,
                                                  RdbHandlersStructCallbacks *callbacks,
                                                  void *userData,
                                                  RdbFreeFunc freeUserData) {
    RdbHandlers *hndl = createHandlersCommon(p, userData, freeUserData, RDB_LEVEL_STRUCT);
    hndl->h.rdbStruct = *callbacks;
    return hndl;
}

_LIBRDB_API RdbHandlers *RDB_createHandlersData(RdbParser *p,
                                                RdbHandlersDataCallbacks *callbacks,
                                                void *userData,
                                                RdbFreeFunc freeUserData) {
    RdbHandlers *hndl = createHandlersCommon(p, userData, freeUserData, RDB_LEVEL_DATA);
    hndl->h.rdbData = *callbacks;
    return hndl;
}

_LIBRDB_API void RDB_handleByLevel(RdbParser *p, RdbDataType type, RdbHandlersLevel lvl, unsigned int flags) {
    UNUSED(flags);
    switch (type) {
        case RDB_DATA_TYPE_STRING:
            p->handleTypeObjByLevel[RDB_TYPE_STRING] = lvl;
            break;
        case RDB_DATA_TYPE_LIST:
            p->handleTypeObjByLevel[RDB_TYPE_LIST] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_LIST_ZIPLIST] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_LIST_QUICKLIST] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_LIST_QUICKLIST_2] = lvl;
            break;
        case RDB_DATA_TYPE_SET:
            p->handleTypeObjByLevel[RDB_TYPE_SET] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_SET_INTSET] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_SET_LISTPACK] = lvl;
            break;
        case RDB_DATA_TYPE_ZSET:
            p->handleTypeObjByLevel[RDB_TYPE_ZSET] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_ZSET_2] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_ZSET_ZIPLIST] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_ZSET_LISTPACK] = lvl;
            break;
        case RDB_DATA_TYPE_HASH:
            p->handleTypeObjByLevel[RDB_TYPE_HASH] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_HASH_ZIPMAP] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_HASH_ZIPLIST] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_HASH_LISTPACK] = lvl;
            break;
        case RDB_DATA_TYPE_MODULE:
            p->handleTypeObjByLevel[RDB_TYPE_MODULE_2] = lvl;
            break;
        case RDB_DATA_TYPE_STREAM:
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS_2] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS_3] = lvl;
            break;
        default:
            assert(0);
    }

}

/*** various functions ***/

static const char *getStatusString(RdbStatus status) {
    switch ((int) status) {
        case RDB_STATUS_OK: return "RDB_STATUS_OK";
        case RDB_STATUS_WAIT_MORE_DATA: return "RDB_STATUS_WAIT_MORE_DATA";
        case RDB_STATUS_PAUSED: return "RDB_STATUS_PAUSED";
        case RDB_STATUS_ERROR: return "RDB_STATUS_ERROR";
        case RDB_STATUS_ENDED: return "(RDB_STATUS_ENDED)";  /* internal state. (Not part of API) */
        default: assert(0);
    }
}

static inline RdbStatus updateStateAfterParse(RdbParser *p, RdbStatus status) {
    /* update parser internal state according to returned status */
    switch ( (int)status) {
        case RDB_STATUS_PAUSED:
            rollbackCache(p);
            p->state = RDB_STATE_PAUSED;
            return RDB_STATUS_PAUSED;

        case RDB_STATUS_WAIT_MORE_DATA:
            rollbackCache(p);
            p->state = RDB_STATE_RUNNING;
            return RDB_STATUS_WAIT_MORE_DATA;

        case RDB_STATUS_ERROR:
            printParserState(p);
            p->state = RDB_STATE_ERROR;
            return RDB_STATUS_ERROR;

        case RDB_STATUS_ENDED:
            /* STATUS_ENDED is an internal value that is not exposed to the caller.
             * It saves us a condition in main loop. */

            /* fall-thru */
        case RDB_STATUS_OK:
            p->state = RDB_STATE_ENDED;
            RDB_log(p, RDB_LOG_INFO, "Parser done");
            return RDB_STATUS_OK;

        default:

            RDB_reportError(p, RDB_ERR_PARSER_RETURNED_INVALID_LIBRDB_STATUS,
                           "updateStateAfterParse() Parser returned invalid status: %d", status);
            return RDB_STATUS_ERROR;
    }
}

static RdbStatus parserMainLoop(RdbParser *p) {
    RdbStatus status;
    assert(p->state == RDB_STATE_RUNNING);

    p->bytesToNextPause = (p->pauseInterval == 0) ? SIZE_MAX : p->bytesRead + p->pauseInterval ;

    if (unlikely(p->debugData)) {
        while (1) {
            RDB_log(p, RDB_LOG_DBG, "[State=%d] %-20s ", p->elmCtx.state, peInfo[p->parsingElement].funcname);
            status = peInfo[p->parsingElement].func(p);
            RDB_log(p, RDB_LOG_DBG, "Return status=%s (next=%s)\n", getStatusString(status),
                   peInfo[p->parsingElement].funcname);
            if (status != RDB_STATUS_OK) break;
        }
    } else {
        /* If this loop become too much performance intensive, then we can optimize
         * certain transitions by avoiding passing through the main loop. It can be
         * done by flushing the cache with function bulkPoolFlush(), and then make
         * direct call to next state */
        while ((status = peInfo[p->parsingElement].func(p)) == RDB_STATUS_OK);
    }
    return updateStateAfterParse(p, status);
}

static inline void rollbackCache(RdbParser *p) {
    bulkPoolRollback(p);
}

static inline RdbStatus nextParsingElementKeyValue(RdbParser *p,
                                                   ParsingElementType peRawValue,
                                                   ParsingElementType peValue) {
    p->elmCtx.key.handleByLevel = p->handleTypeObjByLevel[p->currOpcode];

    if (p->handleTypeObjByLevel[p->currOpcode] == RDB_LEVEL_RAW) {
        p->elmCtx.key.valueType = peRawValue;
        return nextParsingElement(p, PE_RAW_NEW_KEY);
    } else {
        p->elmCtx.key.valueType = peValue;
        return nextParsingElement(p, PE_NEW_KEY);
    }
}

static RdbRes handleNewKeyPrintDbg(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(p,userData,info);
    UNUSED(key);
    RDB_log(p, RDB_LOG_DBG, "Key=%s, ", key);
    return RDB_OK;
}

static void chainHandlersAcrossLevels(RdbParser *p) {
    RdbHandlers *prev=NULL, *next;

    for (int lvl = 0; lvl < RDB_LEVEL_MAX ; ++lvl) {

        if (p->numHandlers[lvl] == 0)
            continue;

        p->totalHandlers += p->numHandlers[lvl];

        if (prev == NULL) {
            /* keep pointer to first handler in the chain */
            prev = p->firstHandlers = p->handlers[lvl];

            if(p->handlers[lvl]->next == NULL)
                continue;

            next = p->handlers[lvl]->next;
        } else {
            next = p->handlers[lvl];
        }

        /* found next handler in the chain. Connect it. And update before for next level iteration */
        prev->next = next;
        while (next->next != NULL) next=next->next;
        prev = next;
    }
}

static void resolveMultipleLevelsRegistration(RdbParser *p) {
    /* find the lowest level that handlers are registered */
    int lvl = (p->numHandlers[0]) ? RDB_LEVEL_RAW :
            (p->numHandlers[1]) ? RDB_LEVEL_STRUCT :
            RDB_LEVEL_DATA ;

    for (int i = 0 ; i < RDB_TYPE_MAX ; ++i) {
        /* check if not configured already by app */
        if (p->handleTypeObjByLevel[i] == RDB_LEVEL_MAX)
            p->handleTypeObjByLevel[i] = lvl;
    }
}

static RdbStatus finalizeConfig(RdbParser *p, int isParseFromBuff) {
    static int is_crc_init = 0;
    assert(p->state == RDB_STATE_CONFIGURING);

    RDB_log(p, RDB_LOG_INFO, "Finalizing parser configuration");

    if (!is_crc_init) {
        crc64_init();
        is_crc_init = 1;
    }

    if ((p->debugData = getEnvVar(ENV_VAR_DEBUG_DATA, 0)) != 0) {
        RDB_setLogLevel(p, RDB_LOG_DBG);
        RdbHandlersDataCallbacks cb = {.handleNewKey = handleNewKeyPrintDbg};
        RDB_createHandlersData(p, &cb, NULL, NULL);
    }

    p->isParseFromBuff = isParseFromBuff;

    if (isParseFromBuff) {
        assert (p->reader == NULL);
        p->readRdbFunc = readRdbFromBuff;
    }
    else {
        assert (p->reader != NULL);
        if (getEnvVar(ENV_VAR_SIM_WAIT_MORE_DATA, 0))
            p->readRdbFunc = readRdbWaitMoreDataDbg;
        else
            p->readRdbFunc = readRdbFromReader;
    }

    p->cache = bulkPoolInit(&p->mem);

    chainHandlersAcrossLevels(p);

    resolveMultipleLevelsRegistration(p);

    p->state = RDB_STATE_RUNNING;
    RDB_log(p, RDB_LOG_INFO, "Start processing RDB source");
    return RDB_STATUS_OK;
}

static void printParserState(RdbParser *p) {
    printf ("Parser error message:%s\n", RDB_getErrorMessage(p));
    printf ("Parser error code:%d\n", RDB_getErrorCode(p));
    printf ("Parser element func name: %s\n", peInfo[p->parsingElement].funcname);
    printf ("Parser element func description: %s\n", peInfo[p->parsingElement].funcname);
    printf ("Parser element state:%d\n", p->elmCtx.state);
    bulkPoolPrintDbg(p);
}

static void loggerCbDefault(RdbLogLevel l, const char *msg) {
    static char *logLevelStr[] = {
            [RDB_LOG_ERROR]    = ":: ERROR ::",
            [RDB_LOG_WARNNING] = ":: WARN  ::",
            [RDB_LOG_INFO]     = ":: INFO  ::",
            [RDB_LOG_DBG]      = ":: DEBUG ::",
    };
    printf("%s %s\n", logLevelStr[l], msg);
}

static void releaseReader(RdbParser *p) {
    RdbReader *r = p->reader;
    if (!r) return;
    if (r->destructor) r->destructor(p, r->readerData);
    RDB_free(p, r);
}

static void releaseHandlers(RdbParser *p, RdbHandlers *h) {
    while (h) {
        RdbHandlers *next = h->next;
        if (h->destructor && h->userData) h->destructor(p, h->userData);
        RDB_free(p, h);
        h = next;
    }
}

RdbStatus allocFromCache(RdbParser *p,
                         size_t len,
                         AllocTypeRq type,
                         char *refBuf,
                         BulkInfo **binfo)
{

    /* pool adds termination of '\0' */
    *binfo = bulkPoolAlloc(p, len, type, refBuf);

    if (unlikely( (*binfo)->ref == NULL)) {
        RDB_reportError(p, RDB_ERR_NO_MEMORY,
                           "allocFromCache() failed allocating %llu bytes (allocation type=%d)",
                           (unsigned long long)len,
                           type);

        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

static inline RdbStatus unpackList(RdbParser *p, unsigned char *lp) {
    char tmp = 'x';
    unsigned char *eptr;
    unsigned int vlen;
    long long vll;

    eptr = lpFirst( lp);
    while (eptr) {
        char *item = (char *)lpGetValue(eptr, &vlen, &vll);
        BulkInfo *binfo;
        if (item) {
            /* The callback function expects a native string that is terminated
             * with '\0'. However, the string we have is packed without
             * termination. To avoid allocating a new string, we can follow these
             * steps:
             * 1. Save the last character that comes at the end of the referenced
             *    string in a temporary char (tmp).
             * 2. allocFromCache(RQ_ALLOC_APP_BULK_REF) will:
             *    - Set last character '\0' to terminate the string.
             *    - Mark the string as a referenced bulk allocation (placement-new alloc)
             * 3. invoke CALL_HANDLERS_CB that will:
             *    - Supply the bulk to callbacks
             *    - Finalize by restoring original char (from tmp) */
            tmp = item[vlen];
            IF_NOT_OK_RETURN(allocFromCache(p, vlen, RQ_ALLOC_APP_BULK_REF, item, &binfo));

            /* if requested ref another memory but forced to allocate a new buffer,
             * (since configured RDB_BULK_ALLOC_EXTERN) then copy data to the new buffer */
            if (binfo->bulkType != BULK_TYPE_REF)
                memcpy(binfo->ref, item, vlen);

        } else {
            int buflen = 32;
            IF_NOT_OK_RETURN(allocFromCache(p, buflen, RQ_ALLOC_APP_BULK, NULL, &binfo));
            vlen = ll2string(binfo->ref, buflen, vll);
            binfo->len = vlen;  /* update len */
        }

        registerAppBulkForNextCb(p, binfo);
        CALL_HANDLERS_CB(p,
                         item[vlen] = tmp,   /* <<< finalize: restore modified char */
                         RDB_LEVEL_DATA,
                         rdbData.handleListElement,
                         binfo->ref);
        eptr = lpNext( lp, eptr);
    }
    return RDB_STATUS_OK;
}

static RdbHandlers *createHandlersCommon(RdbParser *p,
                                         void *userData,
                                         RdbFreeFunc f,
                                         RdbHandlersLevel level) {
    assert(p->state == RDB_STATE_CONFIGURING);
    /* alloc & register empty handlers in parser */
    RdbHandlers *h = (RdbHandlers *) RDB_alloc(p, sizeof(RdbHandlers));
    memset(h, 0, sizeof(RdbHandlers));
    h->userData = userData;
    h->destructor = f;
    h->level = level;
    h->parser = p;
    h->next = p->handlers[level];

    p->handlers[level] = h;
    p->numHandlers[level] += 1;
    return h;
}

/*** sub-element parsing ***/

RdbStatus subElementCall(RdbParser *p, ParsingElementType next, int returnState) {

    assert(p->callSubElm.callerElm == PE_MAX); /* prev sub-element flow ended */

    /* release bulk from previous flow of subElement */
    bulkUnmanagedFree(p, &p->callSubElm.bulkResult);

    p->callSubElm.callerElm = p->parsingElement;
    p->callSubElm.stateToReturn = returnState;
    return nextParsingElement(p, next);
}

RdbStatus subElementReturn(RdbParser *p, BulkInfo *bulkResult) {
    p->callSubElm.bulkResult = *bulkResult;
    return nextParsingElementState(p, p->callSubElm.callerElm, p->callSubElm.stateToReturn);
}

void subElementCallEnd(RdbParser *p, RdbBulk *bulkResult, size_t *len) {
    *bulkResult = p->callSubElm.bulkResult.ref;
    *len = p->callSubElm.bulkResult.len;
    p->callSubElm.callerElm = PE_MAX; /* mark as done */
}

/*** Parsing Elements ***/

RdbStatus elementRdbHeader(RdbParser *p) {
    BulkInfo *binfo;

    /* read REDIS signature and RDB version */
    IF_NOT_OK_RETURN(rdbLoad(p, 9, RQ_ALLOC, NULL, &binfo));

    /*** ENTER SAFE STATE ***/

    if (memcmp(binfo->ref, "REDIS", 5) != 0) {
        RDB_reportError(p, RDB_ERR_WRONG_FILE_SIGNATURE,
                           "Wrong signature trying to load DB from file");
        return RDB_STATUS_ERROR;
    }

    /* read rdb version */
    p->rdbversion = atoi(((char *) binfo->ref) + 5);
    if (p->rdbversion < 1 || p->rdbversion > RDB_VERSION) {
        RDB_reportError(p, RDB_ERR_UNSUPPORTED_RDB_VERSION,
            "Can't handle RDB format version: %d", p->rdbversion);
        return RDB_STATUS_ERROR;
    }

    RDB_log(p, RDB_LOG_INFO, "The parsed RDB file version is: %d", p->rdbversion);


    CALL_COMMON_HANDLERS_CB(p, handleNewRdb, p->rdbversion);

    RDB_log(p, RDB_LOG_INFO, "rdbversion=%d", p->rdbversion);

    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementAuxField(RdbParser *p) {
    BulkInfo *binfoAuxKey, *binfoAuxVal;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoAuxKey));
    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoAuxVal));

    /*** ENTER SAFE STATE ***/

    registerAppBulkForNextCb(p, binfoAuxKey);
    registerAppBulkForNextCb(p, binfoAuxVal);
    CALL_COMMON_HANDLERS_CB(p, handleAuxField, binfoAuxKey->ref, binfoAuxVal->ref);

    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementSelectDb(RdbParser *p) {
    uint64_t dbid;

    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dbid, NULL, NULL));

    /*** ENTER SAFE STATE ***/

    CALL_COMMON_HANDLERS_CB(p, handleNewDb, ((int) dbid));
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementResizeDb(RdbParser *p) {
    /* RESIZEDB: Hint about the size of the keys in the currently
     * selected data base, in order to avoid useless rehashing. */
    uint64_t db_size, expires_size;

    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &db_size, NULL, NULL));
    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &expires_size, NULL, NULL));

    /*** ENTER SAFE STATE ***/

    CALL_COMMON_HANDLERS_CB(p, handleDbSize, db_size, expires_size);

    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementNewKey(RdbParser *p) {
    BulkInfo *binfoKey;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoKey));

    /*** ENTER SAFE STATE ***/

    p->elmCtx.key.info.opcode = p->currOpcode; /* tell cb what is current opcode */

    registerAppBulkForNextCb(p, binfoKey);
    CALL_HANDLERS_CB(p, NOP, p->elmCtx.key.handleByLevel, common.handleNewKey, binfoKey->ref, &p->elmCtx.key.info);

    /* reset values for next key */
    p->elmCtx.key.info.expiretime = -1;
    p->elmCtx.key.info.lru_idle = -1;
    p->elmCtx.key.info.lfu_freq = -1;

    /* Read value */
    return nextParsingElement(p, p->elmCtx.key.valueType);
}

RdbStatus elementExpireTime(RdbParser *p) {
    BulkInfo *binfo;

    IF_NOT_OK_RETURN(rdbLoad(p, 4, RQ_ALLOC, NULL, &binfo));

    /*** ENTER SAFE STATE ***/

    p->elmCtx.key.info.expiretime =  ((time_t) *((int32_t *) binfo->ref)) * 1000;
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

/* This function loads a time from the RDB file. It gets the version of the
 * RDB because, unfortunately, before Redis 5 (RDB version 9), the function
 * failed to convert data to/from little endian, so RDB files with keys having
 * expires could not be shared between big endian and little endian systems
 * (because the expire time will be totally wrong). The fix for this is just
 * to call memrev64ifbe(), however if we fix this for all the RDB versions,
 * this call will introduce an incompatibility for big endian systems:
 * after upgrading to Redis version 5 they will no longer be able to load their
 * own old RDB files. Because of that, we instead fix the function only for new
 * RDB versions, and load older RDB versions as we used to do in the past,
 * allowing big endian systems to load their own old RDB files. */
RdbStatus elementExpireTimeMsec(RdbParser *p) {
    BulkInfo *binfo;

    IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC, NULL, &binfo));

    /*** ENTER SAFE STATE ***/

    if (p->rdbversion >= 9) /* Check the top comment of this function. */
        memrev64ifbe(((int64_t *) pRead)); /* Convert in big endian if the system is BE. */

    p->elmCtx.key.info.expiretime = (long long) binfo->ref;
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementNextRdbType(RdbParser *p) {
    BulkInfo *biType;

    /* Load a "type" in RDB format, that is a one byte unsigned integer */
    IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &biType));

    /*** ENTER SAFE STATE ***/

    p->currOpcode = *((unsigned char *)biType->ref);
    switch (p->currOpcode) {
        case RDB_OPCODE_EXPIRETIME:         return nextParsingElement(p, PE_EXPIRETIME);
        case RDB_OPCODE_EXPIRETIME_MS:      return nextParsingElement(p, PE_EXPIRETIMEMSEC);
        case RDB_OPCODE_AUX:                return nextParsingElement(p, PE_AUX_FIELD);
        case RDB_OPCODE_SELECTDB:           return nextParsingElement(p, PE_SELECT_DB);
        case RDB_OPCODE_RESIZEDB:           return nextParsingElement(p, PE_RESIZE_DB);

        case RDB_TYPE_STRING:               return nextParsingElementKeyValue(p, PE_RAW_STRING, PE_STRING);
        case RDB_TYPE_LIST_QUICKLIST:       return nextParsingElementKeyValue(p, PE_RAW_LIST, PE_LIST);
        case RDB_TYPE_LIST_QUICKLIST_2:     return nextParsingElementKeyValue(p, PE_RAW_LIST, PE_LIST);

        case RDB_OPCODE_EOF:                return nextParsingElement(p, PE_END_OF_FILE);

        case RDB_OPCODE_FREQ:
        case RDB_OPCODE_IDLE:
        case RDB_OPCODE_GFLAGS:
        case RDB_OPCODE_GCAS:
        case RDB_OPCODE_MODULE_AUX:
        case RDB_OPCODE_FUNCTION:
        case RDB_OPCODE_FUNCTION2:
        case RDB_TYPE_LIST:
        case RDB_TYPE_SET:
        case RDB_TYPE_ZSET:
        case RDB_TYPE_HASH:
        case RDB_TYPE_ZSET_2:
        case RDB_TYPE_MODULE_2:
        case RDB_TYPE_HASH_ZIPMAP:
        case RDB_TYPE_LIST_ZIPLIST:
        case RDB_TYPE_SET_INTSET:
        case RDB_TYPE_ZSET_ZIPLIST:
        case RDB_TYPE_HASH_ZIPLIST:
        case RDB_TYPE_STREAM_LISTPACKS:
        case RDB_TYPE_HASH_LISTPACK:
        case RDB_TYPE_ZSET_LISTPACK:
        case RDB_TYPE_STREAM_LISTPACKS_2:
        case RDB_TYPE_SET_LISTPACK:
        case RDB_TYPE_STREAM_LISTPACKS_3:
            RDB_reportError(p, RDB_ERR_NOT_SUPPORTED_RDB_ENCODING_TYPE,
                           "Not supported RDB encoding type: %d", p->currOpcode);
            return RDB_STATUS_ERROR;

        default:
            RDB_reportError(p, RDB_ERR_UNKNOWN_RDB_ENCODING_TYPE, "Unknown RDB encoding type");
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementEndKey(RdbParser *p) {
    /*** ENTER SAFE STATE ***/
    CALL_HANDLERS_CB(p, NOP, p->elmCtx.key.handleByLevel, common.handleEndKey);
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementString(RdbParser *p) {
    BulkInfo *binfoStr;
    RdbHandlersLevel lvl = p->elmCtx.key.handleByLevel;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoStr));

    /*** ENTER SAFE STATE ***/

    registerAppBulkForNextCb(p, binfoStr);
    if (lvl == RDB_LEVEL_STRUCT)
        CALL_HANDLERS_CB(p, NOP, lvl, rdbStruct.handleStringValue, binfoStr->ref);
    else
        CALL_HANDLERS_CB(p, NOP, lvl, rdbData.handleStringValue, binfoStr->ref);

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementList(RdbParser *p) {
    ElementCtx *ctx = &p->elmCtx;
    enum LIST_STATES {
        ST_LIST_HEADER=0, /*  Retrieve number of nodes */
        ST_LIST_NEXT_NODE /* Process next node and callback to app (Iterative) */
    } ;

    switch (ctx->state) {
        case ST_LIST_HEADER:
            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &(ctx->list.numNodes), NULL, NULL));

            /*** ENTER SAFE STATE ***/

            updateElementState(p, ST_LIST_NEXT_NODE); /* fall-thru */

        case ST_LIST_NEXT_NODE: {
            uint64_t container;
            BulkInfo *binfoNode;

            /* is end of list */
            if (ctx->list.numNodes == 0)
                return nextParsingElement(p, PE_END_KEY);

            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &container, NULL, NULL));

            if (container != QUICKLIST_NODE_CONTAINER_PACKED &&
                container != QUICKLIST_NODE_CONTAINER_PLAIN) {
                RDB_reportError(p, RDB_ERR_QUICK_LIST_INTEG_CHECK, "elementList(1): Quicklist integrity check failed");
                return RDB_STATUS_ERROR;
            }

            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoNode));

            /* ****************************** ENTER SAFE STATE *********************************
             * STARTING FROM THIS POINT, UP-TO END OF STATE, WON'T BE ANY MORE READS FROM RDB, *
             * SO IT IS SAFE NOW TO CALL HANDLERS CALLBACKS WITHOUT THE RISK OF ROLLBACK DUE   *
             * TO `RDB_STATUS_WAIT_MORE_DATA` (WE CAN ADD LOCK VERIFICATION BY NEED).           *
             ***********************************************************************************/

            if (container == QUICKLIST_NODE_CONTAINER_PLAIN) {
                RdbHandlersLevel lvl = p->elmCtx.key.handleByLevel;

                registerAppBulkForNextCb(p, binfoNode);
                if (lvl == RDB_LEVEL_STRUCT)
                    CALL_HANDLERS_CB(p, NOP, lvl, rdbStruct.handlerPlainNode, binfoNode->ref);
                else
                    CALL_HANDLERS_CB(p, NOP, lvl, rdbData.handleListElement, binfoNode->ref);

                return RDB_STATUS_OK;
            }

            unsigned char *lp = (unsigned char *) binfoNode->ref;

            if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2) {
                if (!lpValidateIntegrity(lp, binfoNode->len, p->deepIntegCheck, NULL, NULL)) {
                    RDB_reportError(p, RDB_ERR_QUICK_LIST_INTEG_CHECK,
                                   "elementList(2): Quicklist integrity check failed");
                    return RDB_STATUS_ERROR;
                }
            } else {
                /* TODO: elementList() - ziplistValidateIntegrity */
                assert(0);
            }

            /* Silently skip empty listpack */
            if (lpLength(lp) == 0) return RDB_STATUS_OK;

            if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
                registerAppBulkForNextCb(p, binfoNode);
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handlerQListNode, binfoNode->ref);
            } else {
                /* unpackList makes multiple callbacks. all data in ctx.lp */
                IF_NOT_OK_RETURN(unpackList(p, lp));
            }

            /* Update context (context update must being made only from safe state. For sure won't be rollback) */
            --ctx->list.numNodes;

            return updateElementState(p, ST_LIST_NEXT_NODE);
        }

        default:
            RDB_reportError(p, RDB_ERR_QUICK_LIST_INVALID_STATE,
                           "elementList() : invalid parsing element state");
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementEndOfFile(RdbParser *p) {
    /* Verify the checksum if RDB version is >= 5 */
    if (p->rdbversion >= 5) {
        BulkInfo *bulkInfo;
        uint64_t cksum;
        uint64_t evaluated = p->checksum;


        IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC, NULL, &bulkInfo));
        cksum = *((uint64_t *) bulkInfo->ref);

        if (!p->ignoreChecksum) {
            memrev64ifbe(&cksum);
            if (cksum == 0) {
                RDB_log(p, RDB_LOG_WARNNING, "RDB file was saved with checksum disabled: no check performed.");
            } else if (cksum != evaluated) {
                RDB_reportError(p, RDB_ERR_CHECKSUM_FAILURE, "Wrong RDB checksum checksum=%lx, evaluated=%lx",
                               (unsigned long long) cksum,
                               (unsigned long long) p->checksum);
                return RDB_STATUS_ERROR;
            }
        }
    }

    CALL_COMMON_HANDLERS_CB(p, handleEndRdb);
    return RDB_STATUS_ENDED; /* THE END */
}

/*** Loaders from RDB ***/

RdbStatus rdbLoadInteger(RdbParser *p, int enctype, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    long long val;

    if (enctype == RDB_ENC_INT8) {
        IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, binfo));
        val = ((unsigned char *) (*binfo)->ref)[0];
    } else if (enctype == RDB_ENC_INT16) {
        uint16_t v;
        IF_NOT_OK_RETURN(rdbLoad(p, 2, RQ_ALLOC, NULL, binfo));
        v = ((uint32_t) ((unsigned char *) (*binfo)->ref)[0])|
            ((uint32_t)((unsigned char *) (*binfo)->ref)[1]<<8);
        val = (int16_t)v;
    } else if (enctype == RDB_ENC_INT32) {
        uint32_t v;
        IF_NOT_OK_RETURN(rdbLoad(p, 4, RQ_ALLOC, NULL, binfo));
        v = ((uint32_t)((unsigned char *) (*binfo)->ref)[0])|
            ((uint32_t)((unsigned char *) (*binfo)->ref)[1]<<8)|
            ((uint32_t)((unsigned char *) (*binfo)->ref)[2]<<16)|
            ((uint32_t)((unsigned char *) (*binfo)->ref)[3]<<24);
        val = (int32_t)v;
    } else {
        RDB_log(p, RDB_LOG_ERROR, "Unknown RDB integer encoding type %d", enctype);
        RDB_reportError(p, RDB_ERR_INVALID_INT_ENCODING, NULL);
        return RDB_STATUS_ERROR;
    }

    char buf[LONG_STR_SIZE];
    int len = ll2string(buf,sizeof(buf),val);

    IF_NOT_OK_RETURN(allocFromCache(p, len, type, refBuf, binfo));
    memcpy((*binfo)->ref, buf, len);
    return RDB_STATUS_OK;
}

/* Load an encoded length. Read length is set to '*lenptr'. If instead the
 * loaded length describes a special encoding that follows, then '*isencoded'
 * is set to 1 and the encoding format is stored at '*lenptr'.
 *
 * outbuff is optional, in case you want the raw encoded data too, and should
 * have room for at least 9 bytes for worse case.
 * outbufflen should be pre-zeroed by the caller.
 *
 * The function returns -1 on error, 0 on success. */
RdbStatus rdbLoadLen(RdbParser *p, int *isencoded, uint64_t *lenptr, unsigned char* outbuff, int *outbufflen) {
    unsigned char buf[2];
    BulkInfo *binfo;
    int type;

    if (isencoded) *isencoded = 0;

    /* Load a "type" in RDB format, that is a one byte unsigned integer */
    IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &binfo));
    buf[0] = *((unsigned char *) binfo->ref);

    if (outbuff) outbuff[0] = buf[0], (*outbufflen)++;
    type = (buf[0]&0xC0)>>6;
    if (type == RDB_ENCVAL) {
        /* Read a 6 bit encoding type. */
        if (isencoded) *isencoded = 1;
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_6BITLEN) {
        /* Read a 6 bit len. */
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_14BITLEN) {
        /* Read a 14 bit len. */
        IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &binfo));
        buf[1] = *((unsigned char *) binfo->ref);
        if (outbuff) outbuff[1] = buf[1], (*outbufflen)++;
        *lenptr = ((buf[0]&0x3F)<<8)|buf[1];
    } else if (buf[0] == RDB_32BITLEN) {
        /* Read a 32 bit len. */
        IF_NOT_OK_RETURN(rdbLoad(p, 4, RQ_ALLOC, NULL, &binfo));
        if (outbuff) memcpy(outbuff+1, binfo->ref, 4), (*outbufflen)+=4;
        *lenptr = ntohl( (*((uint32_t *)binfo->ref)));
    } else if (buf[0] == RDB_64BITLEN) {
        /* Read a 64 bit len. */
        IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC, NULL, &binfo));
        if (outbuff) memcpy(outbuff+1, &binfo->ref, 8), (*outbufflen)+=8;
        *lenptr = ntohu64(*((uint64_t *)binfo->ref));
    } else {
        RDB_reportError(p, RDB_ERR_INVALID_LEN_ENCODING, "Unknown length encoding %d in rdbLoadLen()",type);
        return RDB_STATUS_ERROR;
    }
    return RDB_STATUS_OK;
}

RdbStatus rdbLoadLzfString(RdbParser *p, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    BulkInfo *binfoComp;
    uint64_t len, clen;

    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &clen, NULL, NULL));
    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &len, NULL, NULL));

    /* Load the compressed representation */
    IF_NOT_OK_RETURN(rdbLoad(p, clen, RQ_ALLOC, NULL, &binfoComp));

    /* Allocate our target according to the uncompressed size. */
    IF_NOT_OK_RETURN(allocFromCache(p, len, type, refBuf, binfo));

    /*  and uncompress it to target */
    if (lzf_decompress(binfoComp->ref, clen, (*binfo)->ref, len) != len) {
        RDB_reportError(p, RDB_ERR_STRING_INVALID_LZF_COMPRESSED,
                       "rdbLoadLzfString(): Invalid LZF compressed string");
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

/* eq. to redis fork: rdbGenericLoadStringObject() */
RdbStatus rdbLoadString(RdbParser *p, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    int isencoded;
    uint64_t len;

    IF_NOT_OK_RETURN(rdbLoadLen(p, &isencoded, &len, NULL, NULL));

    if (isencoded) {
        switch(len) {
            case RDB_ENC_INT8:
            case RDB_ENC_INT16:
            case RDB_ENC_INT32:
                return rdbLoadInteger(p, len, type, refBuf, binfo);

            case RDB_ENC_LZF:
                return rdbLoadLzfString(p, type, refBuf, binfo);
            default:
                RDB_reportError(p, RDB_ERR_STRING_UNKNOWN_ENCODING_TYPE,
                               "rdbLoadString(): Unknown RDB string encoding type: %llu",len);
                return RDB_STATUS_ERROR;
        }
    }

    return rdbLoad(p, len, type, refBuf, binfo);
}

/*** RDB Reader functions ***/

/* simulate WAIT_MORE_DATA for each new read from RDB reader */
static RdbStatus readRdbWaitMoreDataDbg(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    if (bulkPoolIsNewNextAllocDbg(p)) {
        static uint64_t waitMoreDataCounterDbg = 0;
        if (++waitMoreDataCounterDbg % 2) {
            return RDB_STATUS_WAIT_MORE_DATA;
        }
    }

    return readRdbFromReader(p, len, type, refBuf, binfo);
}

static RdbStatus readRdbFromReader(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    RdbStatus res;

    IF_NOT_OK_RETURN(allocFromCache(p, len, type, refBuf, binfo));

    /* if either first time to read, or filled only partially last time */
    if (likely(len > (*binfo)->written)) {
        size_t bytesToFill = len - (*binfo)->written;
        p->bytesRead += bytesToFill; /* likely */

        /* if needed to read less due to pause interval */
        if (unlikely(p->bytesRead > p->bytesToNextPause)) {
            /* correct the values */
            size_t overflow = p->bytesRead - p->bytesToNextPause;
            bytesToFill -= overflow;
            p->bytesRead -= overflow;

            res = p->reader->readFunc(p, p->reader->readerData,
                                      ((char *) (*binfo)->ref) + (*binfo)->written, bytesToFill);
            (*binfo)->written += bytesToFill;
            if (res != RDB_STATUS_OK) goto not_ok;
            return RDB_STATUS_PAUSED;
        } else { /* fill up entire item */

            res = p->reader->readFunc(p, p->reader->readerData,
                                      ((char *) (*binfo)->ref) + (*binfo)->written, bytesToFill);
            if (unlikely(res != RDB_STATUS_OK)) {
                (*binfo)->written += bytesToFill;
                goto not_ok;
            }

            /* done read entirely. Eval crc of entire read */
            (*binfo)->written = DONE_FILL_BULK;
            p->checksum = crc64(p->checksum, (unsigned char *) (*binfo)->ref, len);
            return res;
        }
    } else {
        if (likely(len == (*binfo)->written)) {
            /* Got last time WAIT_MORE_DATA. assumed async read filled it up */

            /* After WAIT_MORE_DATA we cannot eval crc. Update it now. */
            p->checksum = crc64(p->checksum, (unsigned char *) (*binfo)->ref, len);
            (*binfo)->written = DONE_FILL_BULK;
        }
        return RDB_STATUS_OK;
    }

not_ok:
    if (res == RDB_STATUS_ERROR) {
        /* verify reader reported an error. Otherwise set such one */
        if (p->errorCode == RDB_OK) {
            p->errorCode = RDB_ERR_FAILED_READ_RDB_FILE;
            RDB_log(p, RDB_LOG_WARNNING, "Reader returned error indication but didn't RDB_reportError()");
        }
    } else {
        /* reader can return only ok, wait-more-data or error */
        assert(res == RDB_STATUS_WAIT_MORE_DATA);
    }
    return res;
}

static RdbStatus readRdbFromBuff(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **binfo) {
    size_t toFillBeforePause, leftInBuff, leftToFillItem;

    IF_NOT_OK_RETURN(allocFromCache(p, len, type, refBuf, binfo));

    /* if bulk-info was already filled (due to parser rollback). Nothing to do. */
    if (unlikely((*binfo)->written >= len))
        return RDB_STATUS_OK;

    leftInBuff = p->parsebuffCtx.end - p->parsebuffCtx.at;
    leftToFillItem = len - (*binfo)->written;

    if  (likely(leftToFillItem <= leftInBuff)) { /* enough to fill item */
        p->bytesRead += leftToFillItem;

        /* if needed to read less due to pause interval */
        if (unlikely(p->bytesRead > p->bytesToNextPause)) {
            size_t overflow = p->bytesRead - p->bytesToNextPause;
            p->bytesRead -= overflow;
            toFillBeforePause = leftToFillItem - overflow;

            memcpy(((char *) (*binfo)->ref) + (*binfo)->written,
                   p->parsebuffCtx.at,
                   toFillBeforePause);
            p->parsebuffCtx.at += toFillBeforePause;
            (*binfo)->written += toFillBeforePause;
            return RDB_STATUS_PAUSED;
        } else {
            memcpy(((char *) (*binfo)->ref) + (*binfo)->written,
                   p->parsebuffCtx.at,
                   leftToFillItem);
            p->checksum = crc64(p->checksum, (*binfo)->ref, len);
            p->parsebuffCtx.at += leftToFillItem;

            (*binfo)->written = DONE_FILL_BULK;
            return RDB_STATUS_OK;
        }
    } else { /* not enough to fill item */
        p->bytesRead += leftInBuff;

        /* if needed to read less due to pause interval */
        if (unlikely(p->bytesRead > p->bytesToNextPause)) {
            size_t overflow = p->bytesRead - p->bytesToNextPause;
            p->bytesRead -= overflow;
            toFillBeforePause = leftInBuff - overflow;

            memcpy(((char *) (*binfo)->ref) + (*binfo)->written,
                   p->parsebuffCtx.at,
                   toFillBeforePause);
            p->parsebuffCtx.at += toFillBeforePause;
            (*binfo)->written += toFillBeforePause;
            return RDB_STATUS_PAUSED;
        } else {
            memcpy(((char *) (*binfo)->ref) + (*binfo)->written,
                   p->parsebuffCtx.at,
                   leftInBuff);
            p->parsebuffCtx.at += leftInBuff;
            (*binfo)->written += leftInBuff;
            return RDB_STATUS_WAIT_MORE_DATA;
        }
    }
}
