/* parser.c - implementation of core parser (LEVEL1/2) & API
 *
 * This file includes:
 * - implementation of most of the core API (librdb-api.h)
 * - Main parsing-elements loop of the parser. See parserMainLoop().
 * - Holds the parsing-element lookup table (peInfo[]) of the state machine.
 * - Parsing LEVEL1 (RDB data-structures) and LEVEL2 (Redis data-types).
 *   Parsing of LEVEL0 (raw data) is implemented at file parserRaw.c
 *   (Description of the 3 levels available in README.md.)
 *
 * It is recommended to read the "Parser implementation notes" section
 * in the README.md file as an introduction to this file implementation.
 */

#include <endian.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include "../../deps/redis/crc64.h"
#include "bulkAlloc.h"
#include "parser.h"
#include "version.h"
#include "defines.h"
#include "../../deps/redis/endianconv.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/listpack.h"
#include "../../deps/redis/ziplist.h"
#include "../../deps/redis/zipmap.h"
#include "../../deps/redis/intset.h"
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
        [PE_FREQ]             = {elementFreq, "elementFreq", "Parsing LFU frequency"},
        [PE_IDLE]             = {elementIdle, "elementIdle", "Parsing LRU idle time"},

        [PE_NEW_KEY]          = {elementNewKey, "elementNewKey", "Parsing new key-value"},
        [PE_END_KEY]          = {elementEndKey, "elementEndKey", "Parsing end key"},

        [PE_END_OF_FILE]      = {elementEndOfFile, "elementEndOfFile", "End parsing RDB file"},

        /*** parsing struct/data (RDB_LEVEL_STRUCT/RDB_LEVEL_DATA) ***/
        /* string */
        [PE_STRING]           = {elementString, "elementString", "Parsing string"},
        /* list */
        [PE_LIST]             = {elementList, "elementList", "Parsing list"},
        [PE_QUICKLIST]        = {elementQuickList, "elementQuickList", "Parsing list"},
        [PE_LIST_ZL]          = {elementListZL, "elementListZL", "Parsing Ziplist"},
        /* hash */
        [PE_HASH]             = {elementHash, "elementHash", "Parsing Hash"},
        [PE_HASH_ZL]          = {elementHashZL, "elementHashZL", "Parsing hash Ziplist"},
        [PE_HASH_LP]          = {elementHashLP, "elementHashLP", "Parsing hash Listpack"},
        [PE_HASH_ZM]          = {elementHashZM, "elementHashZM", "Parsing hash Zipmap"},
        /* set */
        [PE_SET]              = {elementSet, "elementSet", "Parsing set"},
        [PE_SET_IS]           = {elementSetIS, "elementSetIS", "Parsing set Intset"},
        [PE_SET_LP]           = {elementSetLP, "elementSetLP", "Parsing set Listpack"},
        /* zset */
        [PE_ZSET]             = {elementZset, "elementZset", "Parsing zset"},
        [PE_ZSET_2]           = {elementZset, "elementZset", "Parsing zset_2"},
        [PE_ZSET_ZL]          = {elementZsetZL, "elementZsetZL", "Parsing zset Ziplist"},
        [PE_ZSET_LP]          = {elementZsetLP, "elementZsetLP", "Parsing zset Listpack"},
        [PE_FUNCTION]         = {elementFunction, "elementFunction", "Parsing Function"},
        [PE_MODULE]           = {elementModule, "elementModule", "Parsing silently Module element"},
        [PE_MODULE_AUX]       = {elementModule, "elementModule", "Parsing silently Module Auxiliary data"},

        /*** parsing raw data (RDB_LEVEL_RAW) ***/

        [PE_RAW_NEW_KEY]      = {elementRawNewKey, "elementRawNewKey", "Parsing new raw key-value"},
        [PE_RAW_END_KEY]      = {elementRawEndKey, "elementRawEndKey", "Parsing raw end key"},

        /* string */
        [PE_RAW_STRING]       = {elementRawString, "elementRawString", "Parsing raw string"},
        /* list */
        [PE_RAW_LIST]         = {elementRawList, "elementRawList", "Parsing raw list (legacy)"},
        [PE_RAW_QUICKLIST]    = {elementRawQuickList, "elementRawQuickList", "Parsing raw list"},
        [PE_RAW_LIST_ZL]      = {elementRawListZL, "elementRawListZL", "Parsing raw list ZL (zip list)"},
        /* hash */
        [PE_RAW_HASH]         = {elementRawHash, "elementRawHash", "Parsing raw Hash"},
        [PE_RAW_HASH_ZL]      = {elementRawHashZL, "elementRawHashZL", "Parsing raw hash Ziplist"},
        [PE_RAW_HASH_LP]      = {elementRawHashLP, "elementRawHashLP", "Parsing raw hash Listpack"},
        [PE_RAW_HASH_ZM]      = {elementRawHashZM, "elementRawHashZM", "Parsing raw hash Zipmap"},
        /* set */
        [PE_RAW_SET]          = {elementRawSet, "elementRawSet", "Parsing raw set"},
        [PE_RAW_SET_IS]       = {elementRawSetIS, "elementRawSetIS", "Parsing raw set Intset"},
        [PE_RAW_SET_LP]       = {elementRawSetLP, "elementRawSetLP", "Parsing raw set Listpack"},
        /* zset */
        [PE_RAW_ZSET]         = {elementRawZset, "elementRawZset", "Parsing raw zset"},
        [PE_RAW_ZSET_2]       = {elementRawZset, "elementRawZset", "Parsing raw zset_2"},
        [PE_RAW_ZSET_ZL]      = {elementRawZsetZL, "elementRawZsetZL", "Parsing raw zset Ziplist"},
        [PE_RAW_ZSET_LP]      = {elementRawZsetLP, "elementRawZsetLP", "Parsing raw zset Listpack"},
        /* module */
        [PE_RAW_MODULE]       = {elementRawModule, "elementRawModule", "Parsing raw Module element"},
        [PE_RAW_MODULE_AUX]   = {elementRawModule, "elementRawModule(aux)", "Parsing Module Auxiliary data"},
};

/* Strings in ziplist/listpacks are embedded without '\0' termination. To avoid
 * allocating a new memory just for passing it to CALL_HANDLERS_CB, we
 * can follow these steps:
 *
 * 1. Save the last character that comes after the end of the packed
 *    value in a temporary char (endCh). This is valid and not beyond
 *    the size of the allocation since in ZP/LP it is guaranteed to have
 *    a terminating byte at the end, which makes it safe.
 *
 * 2. Then allocate from cache `RQ_ALLOC_APP_BULK_REF` which will:
 *    - Set last character '\0' to terminate the value.
 *    - And mark the value as a referenced bulk allocation
 *      (Note, iF app expects APP_BULK, then it is not possible to return
 *      a reference and a new memory will be allocated instead with proper
 *      termination of '\0').
 *
 *      First two steps are achieved by calling function allocEmbeddedBulk()
 *
 * 3. It is the caller responsibility to restore original char right after
 *    calling CALL_HANDLERS_CB, simply by calling restoreEmbeddedBulk().
 *    Otherwise ZP/LP will be left corrupted!
 */
typedef struct {
    BulkInfo *binfo;
    unsigned char endCh;  /* stores value of last char that was overriden with '\0' */
    unsigned char *pEndCh; /* stores ref to last char that was overriden with '\0' */
} EmbeddedBulk;

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

static inline void restoreEmbeddedBulk(EmbeddedBulk *embeddedBulk);
BulkInfo *allocEmbeddedBulk(RdbParser *p,
                                    unsigned char *str,
                                    unsigned int slen,
                                    long long sval,
                                    EmbeddedBulk *embeddedBulk);

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
    p->maxRawSize = SIZE_MAX;
    p->errorCode = RDB_OK;
    p->handlers[RDB_LEVEL_RAW] = NULL;
    p->handlers[RDB_LEVEL_STRUCT] = NULL;
    p->handlers[RDB_LEVEL_DATA] = NULL;
    p->numHandlers[RDB_LEVEL_RAW] = 0;
    p->numHandlers[RDB_LEVEL_STRUCT] = 0;
    p->numHandlers[RDB_LEVEL_DATA] = 0;
    p->totalHandlers = 0;
    p->firstHandlers = NULL;

    for (int i = 0 ; i < RDB_OPCODE_MAX ; ++i) {
        p->handleTypeObjByLevel[i] = RDB_LEVEL_MAX;
    }

    p->elmCtx.state = 0;
    p->parsingElement = PE_RDB_HEADER;

    p->elmCtx.key.info.expiretime = -1;
    p->elmCtx.key.info.lruIdle = -1;
    p->elmCtx.key.info.lfuFreq = -1;
    p->elmCtx.key.numItemsHint = -1;

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

_LIBRDB_API void RDB_setMaxRawSize(RdbParser *p, size_t size) {
    p->maxRawSize = size;
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

_LIBRDB_API int64_t RDB_getNumItemsHint(RdbParser *p) {
    return p->elmCtx.key.numItemsHint;
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

    RDB_log(p, RDB_LOG_ERR, p->errorMsg);
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
            p->handleTypeObjByLevel[RDB_OPCODE_MODULE_AUX] = lvl;
            break;
        case RDB_DATA_TYPE_STREAM:
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS_2] = lvl;
            p->handleTypeObjByLevel[RDB_TYPE_STREAM_LISTPACKS_3] = lvl;
            break;
        case RDB_DATA_TYPE_FUNCTION:
            p->handleTypeObjByLevel[RDB_OPCODE_FUNCTION2] = lvl;
            break;
        default:
            assert(0);
    }

}

_LIBRDB_API const char *RDB_getLibVersion(int *major, int *minor, int *patch) {
    if (major) *major = LIBRDB_MAJOR_VERSION;
    if (minor) *minor = LIBRDB_MINOR_VERSION;
    if (patch) *patch = LIBRDB_PATCH_VERSION;
    return LIBRDB_VERSION_STRING;
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
            RDB_log(p, RDB_LOG_INF, "Parser done");
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
            RDB_log(p, RDB_LOG_DBG, "[Opcode=%d] %s(State=%d)",
                    p->currOpcode,
                    peInfo[p->parsingElement].funcname,
                    p->elmCtx.state);
            status = peInfo[p->parsingElement].func(p);
            RDB_log(p, RDB_LOG_DBG, "Return status=%s next %s(State=%d)\n", getStatusString(status),
                    peInfo[p->parsingElement].funcname,
                    p->elmCtx.state);
            if (status != RDB_STATUS_OK) break;

            /* if RDB_STATUS_OK then the parser completed a state and the cache is empty */
            bulkPoolAssertFlushedDbg(p);
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

    for (int i = 0 ; i < RDB_OPCODE_MAX ; ++i) {
        /* check if not configured already by app */
        if (p->handleTypeObjByLevel[i] == RDB_LEVEL_MAX)
            p->handleTypeObjByLevel[i] = lvl;
    }
}

static RdbStatus finalizeConfig(RdbParser *p, int isParseFromBuff) {
    static int is_crc_init = 0;
    assert(p->state == RDB_STATE_CONFIGURING);

    RDB_log(p, RDB_LOG_INF, "Finalizing parser configuration");

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
    RDB_log(p, RDB_LOG_INF, "Start processing RDB source");
    return RDB_STATUS_OK;
}

static void printParserState(RdbParser *p) {
    RDB_log(p, RDB_LOG_ERR, "Parser error message: %s", RDB_getErrorMessage(p));
    RDB_log(p, RDB_LOG_ERR, "Parser error code: %d", RDB_getErrorCode(p));
    RDB_log(p, RDB_LOG_ERR, "Parser element func name: %s", peInfo[p->parsingElement].funcname);
    RDB_log(p, RDB_LOG_ERR, "Parser element func description: %s", peInfo[p->parsingElement].description);
    RDB_log(p, RDB_LOG_ERR, "Parser element state:%d", p->elmCtx.state);
    //bulkPoolPrintDbg(p);
}

static void loggerCbDefault(RdbLogLevel l, const char *msg) {
    static char *logLevelStr[] = {
            [RDB_LOG_ERR]  = ":: ERROR ::",
            [RDB_LOG_WRN]  = ":: WARN  ::",
            [RDB_LOG_INF]  = ":: INFO  ::",
            [RDB_LOG_DBG]  = ":: DEBUG ::",
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
    unsigned char *eptr, *item;
    unsigned int itemLen;
    long long itemVal;

    eptr = lpFirst( lp);
    while (eptr) {
        EmbeddedBulk embBulk;

        item = lpGetValue(eptr, &itemLen, &itemVal);

        if (!allocEmbeddedBulk(p, item, itemLen, itemVal, &embBulk))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk), /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleListItem,
                         embBulk.binfo->ref);

        eptr = lpNext( lp, eptr);
    }
    return RDB_STATUS_OK;
}

/* return either RDB_STATUS_OK or RDB_STATUS_ERROR */
static RdbStatus listListpackItem(RdbParser *p, BulkInfo *lpInfo) {

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, lpInfo);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleListLP, lpInfo->ref);
    } else {
        /* unpackList makes multiple callbacks. all data in ctx.lp */
        IF_NOT_OK_RETURN(unpackList(p, lpInfo->ref));
    }
    return RDB_STATUS_OK;
}

/* return either RDB_STATUS_OK or RDB_STATUS_ERROR */
static RdbStatus listZiplistItem(RdbParser *p, BulkInfo *ziplistBulk) {

    int ret = ziplistValidateIntegrity(ziplistBulk->ref, ziplistBulk->len, p->deepIntegCheck, NULL, NULL);

    if (unlikely(!ret)) {
        RDB_reportError(p, RDB_ERR_LIST_ZL_INTEG_CHECK, "listZiplistItem(): Ziplist integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, ziplistBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleListZL, ziplistBulk->ref);
        return RDB_STATUS_OK;
    }

    unsigned char *offsetZL = ziplistIndex(ziplistBulk->ref, 0);
    while (offsetZL != NULL) {
        unsigned char *item;
        unsigned int itemLen;
        long long itemVal;
        EmbeddedBulk embBulk;

        ziplistGet(offsetZL, &item, &itemLen, &itemVal);
        offsetZL = ziplistNext(ziplistBulk->ref, offsetZL);

        if (!allocEmbeddedBulk(p, item, itemLen, itemVal, &embBulk))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk);, /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleListItem,
                         embBulk.binfo->ref);
    }
    return RDB_STATUS_OK;
}

/* Used by LP or ZL integrity check */
static int counterCallback(unsigned char *ptr, unsigned int head_count, void *userdata) {
    UNUSED(ptr, head_count)
    size_t *numElm = (size_t *) userdata;
    (*numElm)++;
    return 1;
}

static inline void restoreEmbeddedBulk(EmbeddedBulk *embeddedBulk) {
    *(embeddedBulk->pEndCh) = embeddedBulk->endCh;
}

BulkInfo *allocEmbeddedBulk(RdbParser *p,
                                    unsigned char *str,
                                    unsigned int slen,
                                    long long sval,
                                    EmbeddedBulk *embeddedBulk)
{
    RdbStatus res;
    if (str) {
        unsigned char *strEnd = str + slen;
        embeddedBulk->endCh = *strEnd;
        embeddedBulk->pEndCh = strEnd;
        res = allocFromCache(p, slen, RQ_ALLOC_APP_BULK_REF, (char *) str, &(embeddedBulk->binfo));
        if (unlikely(res!=RDB_STATUS_OK)) return NULL;
    } else {
        static unsigned char dummy;
        embeddedBulk->pEndCh = &dummy;
        int buflen = 32;
        res = allocFromCache(p, buflen, RQ_ALLOC_APP_BULK, NULL, &(embeddedBulk->binfo));
        if (unlikely(res!=RDB_STATUS_OK)) return NULL;
        embeddedBulk->binfo->len = ll2string(embeddedBulk->binfo->ref, buflen, sval);
    }
    return embeddedBulk->binfo;
}

RdbStatus hashZiplist(RdbParser *p, BulkInfo *ziplistBulk) {
    size_t items = 0;

    if (unlikely(0 == ziplistValidateIntegrity(ziplistBulk->ref, ziplistBulk->len, p->deepIntegCheck, counterCallback, &items))) {
        RDB_reportError(p, RDB_ERR_SSTYPE_INTEG_CHECK,
                        "hashZiplist(): Ziplist integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (unlikely((items & 1))) {
        RDB_reportError(p, RDB_ERR_SSTYPE_INTEG_CHECK,
                        "hashZiplist(): Ziplist integrity check failed. Uneven number of items.");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, ziplistBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleHashZL, ziplistBulk->ref);
        return RDB_STATUS_OK;
    }

    p->elmCtx.key.numItemsHint = items;
    unsigned char *iterZL = ziplistIndex(ziplistBulk->ref, 0);
    while (iterZL != NULL) {
        unsigned char *field, *value;
        unsigned int fieldLen, valueLen;
        long long fieldVal, valueVal;
        EmbeddedBulk embBulk1, embBulk2;

        ziplistGet(iterZL, &field, &fieldLen, &fieldVal);
        iterZL = ziplistNext(ziplistBulk->ref, iterZL);
        ziplistGet(iterZL, &value, &valueLen, &valueVal);
        iterZL = ziplistNext(ziplistBulk->ref, iterZL);

        if (!allocEmbeddedBulk(p, field, fieldLen, fieldVal, &embBulk1))
            return RDB_STATUS_ERROR;

        if (!allocEmbeddedBulk(p, value, valueLen, valueVal, &embBulk2))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk1.binfo);
        registerAppBulkForNextCb(p, embBulk2.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk1); restoreEmbeddedBulk(&embBulk2);, /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleHashField,
                         embBulk1.binfo->ref,
                         embBulk2.binfo->ref);
    }
    return RDB_STATUS_OK;
}

RdbStatus hashListPack(RdbParser *p, BulkInfo *lpBulk) {
    size_t items = 0;

    if (unlikely(0 == lpValidateIntegrity(lpBulk->ref, lpBulk->len, p->deepIntegCheck, counterCallback, &items))) {
        RDB_reportError(p, RDB_ERR_HASH_LP_INTEG_CHECK,
                        "hashListPack(): Listpack integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (unlikely((items & 1))) {
        RDB_reportError(p, RDB_ERR_HASH_LP_INTEG_CHECK,
                        "hashListPack(): Listpack integrity check failed. Uneven number of items.");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, lpBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleHashLP, lpBulk->ref);
        return RDB_STATUS_OK;
    }

    p->elmCtx.key.numItemsHint = items;
    unsigned char *iterLP = lpFirst(lpBulk->ref);
    while (iterLP) {
        unsigned char *field, *value;
        unsigned int fieldLen, valueLen;
        long long fieldVal, valueVal;
        EmbeddedBulk embBulk1, embBulk2;

        field = lpGetValue(iterLP, &fieldLen, &fieldVal);
        iterLP = lpNext(lpBulk->ref, iterLP);
        value = lpGetValue(iterLP, &valueLen, &valueVal);
        iterLP = lpNext(lpBulk->ref, iterLP);

        if (!allocEmbeddedBulk(p, field, fieldLen, fieldVal, &embBulk1))
            return RDB_STATUS_ERROR;

        if (!allocEmbeddedBulk(p, value, valueLen, valueVal, &embBulk2))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk1.binfo);
        registerAppBulkForNextCb(p, embBulk2.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk1); restoreEmbeddedBulk(&embBulk2);, /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleHashField,
                         embBulk1.binfo->ref,
                         embBulk2.binfo->ref);
    }
    return RDB_STATUS_OK;
}

RdbStatus hashZipMap(RdbParser *p, BulkInfo *zpBulk) {
    unsigned char *field, *value;
    unsigned int fieldLen, valueLen;

    if (unlikely(0 == zipmapValidateIntegrity(zpBulk->ref, zpBulk->len, p->deepIntegCheck))) {
        RDB_reportError(p, RDB_ERR_HASH_ZM_INTEG_CHECK,
                        "hashZipMap(): Zipmap integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, zpBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleHashZM, zpBulk->ref);
        return RDB_STATUS_OK;
    }

    unsigned char *zmIter = zipmapRewind(zpBulk->ref);
    p->elmCtx.key.numItemsHint = zipmapLen(zpBulk->ref);

    while ((zmIter = zipmapNext(zmIter, &field, &fieldLen, &value, &valueLen)) != NULL) {
        EmbeddedBulk embBulk1, embBulk2;

        if (!allocEmbeddedBulk(p, field, fieldLen, 0, &embBulk1))
            return RDB_STATUS_ERROR;

        if (!allocEmbeddedBulk(p, value, valueLen, 0, &embBulk2))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk1.binfo);
        registerAppBulkForNextCb(p, embBulk2.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk1); restoreEmbeddedBulk(&embBulk2);, /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleHashField,
                         embBulk1.binfo->ref,
                         embBulk2.binfo->ref);
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

/* Turn module ID into a type name. For more information, lookup file module.c in Redis repo) */
void moduleTypeNameByID(char *name, uint64_t moduleid) {
    static const char *ModuleTypeNameCharSet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_";
    const char *cset = ModuleTypeNameCharSet;

    name[9] = '\0';
    char *p = name+8;
    moduleid >>= 10;
    for (int j = 0; j < 9; j++) {
        *p-- = cset[moduleid & 63];
        moduleid >>= 6;
    }
}

/* return either RDB_STATUS_OK or RDB_STATUS_ERROR */
static RdbStatus zsetZiplistItem(RdbParser *p, BulkInfo *ziplistBulk) {

    int ret = ziplistValidateIntegrity(ziplistBulk->ref, ziplistBulk->len, p->deepIntegCheck, NULL, NULL);

    if (unlikely(!ret)) {
        RDB_reportError(p, RDB_ERR_ZSET_ZL_INTEG_CHECK, "zsetZiplistItem(): Ziplist integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, ziplistBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleZsetZL, ziplistBulk->ref);
        return RDB_STATUS_OK;
    }

    unsigned char *offsetZL = ziplistIndex(ziplistBulk->ref, 0);
    while (offsetZL != NULL) {
        unsigned char *item1, *item2;
        unsigned int item1Len, item2Len;
        long long item1Val, item2Val;
        double score;
        EmbeddedBulk embBulk;

        ziplistGet(offsetZL, &item1, &item1Len, &item1Val);
        offsetZL = ziplistNext(ziplistBulk->ref, offsetZL);

        ziplistGet(offsetZL, &item2, &item2Len, &item2Val);
        offsetZL = ziplistNext(ziplistBulk->ref, offsetZL);

        score = item2 ? zzlStrtod(item2, item2Len) : (double) item2Val;

        if (!allocEmbeddedBulk(p, item1, item1Len, item1Val, &embBulk))
            return RDB_STATUS_ERROR;

        registerAppBulkForNextCb(p, embBulk.binfo);
        CALL_HANDLERS_CB(p,
                         restoreEmbeddedBulk(&embBulk);, /*finalize*/
                         RDB_LEVEL_DATA,
                         rdbData.handleZsetMember,
                         embBulk.binfo->ref,
                         score);
    }
    return RDB_STATUS_OK;
}

/*** Parsing Common Elements ***/

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
    if (p->rdbversion < 1 || p->rdbversion > MAX_RDB_VER_SUPPORT) {
        RDB_reportError(p, RDB_ERR_UNSUPPORTED_RDB_VERSION,
                        "Can't handle RDB format version: %d", p->rdbversion);
        return RDB_STATUS_ERROR;
    }

    RDB_log(p, RDB_LOG_INF, "The parsed RDB file version is: %d", p->rdbversion);


    CALL_COMMON_HANDLERS_CB(p, handleStartRdb, p->rdbversion);

    RDB_log(p, RDB_LOG_INF, "rdbversion=%d", p->rdbversion);

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
    p->elmCtx.key.info.lruIdle = -1;
    p->elmCtx.key.info.lfuFreq = -1;
    p->elmCtx.key.numItemsHint = -1;

    /* Read value */
    return nextParsingElement(p, p->elmCtx.key.valueType);
}

/* load an expire-time, associated with the next key to load. */
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
        memrev64ifbe(((int64_t *) binfo->ref)); /* Convert in big endian if the system is BE. */

    p->elmCtx.key.info.expiretime = *((int64_t *) binfo->ref);
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
        case RDB_OPCODE_FREQ:               return nextParsingElement(p, PE_FREQ);
        case RDB_OPCODE_IDLE:               return nextParsingElement(p, PE_IDLE);

        /* string */
        case RDB_TYPE_STRING:               return nextParsingElementKeyValue(p, PE_RAW_STRING, PE_STRING);
        /* list */
        case RDB_TYPE_LIST:                 return nextParsingElementKeyValue(p, PE_RAW_LIST, PE_LIST);
        case RDB_TYPE_LIST_QUICKLIST:       return nextParsingElementKeyValue(p, PE_RAW_QUICKLIST, PE_QUICKLIST);
        case RDB_TYPE_LIST_QUICKLIST_2:     return nextParsingElementKeyValue(p, PE_RAW_QUICKLIST, PE_QUICKLIST);
        case RDB_TYPE_LIST_ZIPLIST:         return nextParsingElementKeyValue(p, PE_RAW_LIST_ZL, PE_LIST_ZL);
        /* hash */
        case RDB_TYPE_HASH:                 return nextParsingElementKeyValue(p, PE_RAW_HASH, PE_HASH);
        case RDB_TYPE_HASH_ZIPLIST:         return nextParsingElementKeyValue(p, PE_RAW_HASH_ZL, PE_HASH_ZL);
        case RDB_TYPE_HASH_LISTPACK:        return nextParsingElementKeyValue(p, PE_RAW_HASH_LP, PE_HASH_LP);
        case RDB_TYPE_HASH_ZIPMAP:          return nextParsingElementKeyValue(p, PE_RAW_HASH_ZM, PE_HASH_ZM);
        /* set */
        case RDB_TYPE_SET:                  return nextParsingElementKeyValue(p, PE_RAW_SET, PE_SET);
        case RDB_TYPE_SET_LISTPACK:         return nextParsingElementKeyValue(p, PE_RAW_SET_LP, PE_SET_LP);
        case RDB_TYPE_SET_INTSET:           return nextParsingElementKeyValue(p, PE_RAW_SET_IS, PE_SET_IS);
        /* module */
        case RDB_TYPE_MODULE_2:             return nextParsingElementKeyValue(p, PE_RAW_MODULE, PE_MODULE);

        case RDB_OPCODE_MODULE_AUX:         if (p->handleTypeObjByLevel[RDB_OPCODE_MODULE_AUX] == RDB_LEVEL_RAW)
                                                return nextParsingElement(p, PE_RAW_MODULE_AUX);
                                            else
                                                return nextParsingElement(p, PE_MODULE_AUX);
        /* function */
        case RDB_OPCODE_FUNCTION2:          return nextParsingElement(p, PE_FUNCTION);

        case RDB_OPCODE_EOF:                return nextParsingElement(p, PE_END_OF_FILE);

        /* zset (TBD) */
        case RDB_TYPE_ZSET:                 return nextParsingElementKeyValue(p, PE_RAW_ZSET, PE_ZSET);
        case RDB_TYPE_ZSET_2:               return nextParsingElementKeyValue(p, PE_RAW_ZSET, PE_ZSET);
        case RDB_TYPE_ZSET_ZIPLIST:         return nextParsingElementKeyValue(p, PE_RAW_ZSET_ZL, PE_ZSET_ZL);
        case RDB_TYPE_ZSET_LISTPACK:        return nextParsingElementKeyValue(p, PE_RAW_ZSET_LP, PE_ZSET_LP);

        /* stream (TBD) */
        case RDB_TYPE_STREAM_LISTPACKS:
        case RDB_TYPE_STREAM_LISTPACKS_2:
        case RDB_TYPE_STREAM_LISTPACKS_3:
            RDB_reportError(p, RDB_ERR_NOT_SUPPORTED_RDB_ENCODING_TYPE,
                            "Not supported RDB encoding type: %d", p->currOpcode);
            return RDB_STATUS_ERROR;

        case RDB_OPCODE_FUNCTION:
            RDB_reportError(p, RDB_ERR_PRERELEASE_FUNC_FORMAT_NOT_SUPPORTED,
                            "Pre-release function format not supported.");
            return RDB_STATUS_ERROR;

        default:
            RDB_reportError(p, RDB_ERR_UNKNOWN_RDB_ENCODING_TYPE, "Unknown RDB encoding type");
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementEndKey(RdbParser *p) {
    /*** ENTER SAFE STATE ***/
    CALL_HANDLERS_CB_NO_ARGS(p, NOP, p->elmCtx.key.handleByLevel, common.handleEndKey);

    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementFreq(RdbParser *p) {
    BulkInfo *binfoFreq;
    IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &binfoFreq));

    /*** ENTER SAFE STATE ***/

    p->elmCtx.key.info.lfuFreq =  *((int8_t *) binfoFreq->ref);
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

RdbStatus elementIdle(RdbParser *p) {
    uint64_t lruIdle;
    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &lruIdle, NULL, NULL));
    /*** ENTER SAFE STATE ***/
    p->elmCtx.key.info.lruIdle = lruIdle;
    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

/*** Parsing data-types Elements ***/

RdbStatus elementString(RdbParser *p) {
    BulkInfo *binfoStr;
    RdbHandlersLevel lvl = p->elmCtx.key.handleByLevel;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoStr));

    /*** ENTER SAFE STATE ***/

    registerAppBulkForNextCb(p, binfoStr);
    if (lvl == RDB_LEVEL_STRUCT)
        CALL_HANDLERS_CB(p, NOP, lvl, rdbStruct.handleString, binfoStr->ref);
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
            BulkInfo *binfoNode;
            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoNode));

            /*** ENTER SAFE STATE ***/

            registerAppBulkForNextCb(p, binfoNode);
            if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT)
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleListPlain, binfoNode->ref);
            else
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleListItem, binfoNode->ref);

            return (--ctx->list.numNodes) ? updateElementState(p, ST_LIST_NEXT_NODE) : nextParsingElement(p, PE_END_KEY);
        }
        default:
            RDB_reportError(p, RDB_ERR_PLAIN_LIST_INVALID_STATE,
                            "elementList() : invalid parsing element state: %d", ctx->state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementQuickList(RdbParser *p) {
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
            uint64_t container = QUICKLIST_NODE_CONTAINER_PACKED;
            BulkInfo *binfoNode;

            if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2) {
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &container, NULL, NULL));

                if (container != QUICKLIST_NODE_CONTAINER_PACKED &&
                    container != QUICKLIST_NODE_CONTAINER_PLAIN) {
                    RDB_reportError(p, RDB_ERR_QUICK_LIST_INTEG_CHECK,
                                    "elementQuickList(1): Quicklist integrity check failed");
                    return RDB_STATUS_ERROR;
                }
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
                    CALL_HANDLERS_CB(p, NOP, lvl, rdbStruct.handleListPlain, binfoNode->ref);
                else
                    CALL_HANDLERS_CB(p, NOP, lvl, rdbData.handleListItem, binfoNode->ref);

            } else {

                unsigned char *lp = (unsigned char *) binfoNode->ref;

                if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2) {
                    if (!lpValidateIntegrity(lp, binfoNode->len, p->deepIntegCheck, NULL, NULL)) {
                        RDB_reportError(p, RDB_ERR_QUICK_LIST_INTEG_CHECK,
                                        "elementQuickList(2): Quicklist integrity check failed");
                        return RDB_STATUS_ERROR;
                    }
                    IF_NOT_OK_RETURN(listListpackItem(p, binfoNode));
                } else {
                    if (RDB_STATUS_ERROR == listZiplistItem(p, binfoNode))
                        return RDB_STATUS_ERROR;
                }
            }

            return (--ctx->list.numNodes) ? updateElementState(p, ST_LIST_NEXT_NODE) : nextParsingElement(p, PE_END_KEY);
        }

        default:
            RDB_reportError(p, RDB_ERR_QUICK_LIST_INVALID_STATE,
                            "elementQuickList() : invalid parsing element state: %d", ctx->state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementListZL(RdbParser *p) {
    BulkInfo *ziplistBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &ziplistBulk));

    /*** ENTER SAFE STATE ***/

    if (RDB_STATUS_ERROR == listZiplistItem(p, ziplistBulk))
        return RDB_STATUS_ERROR;

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementHash(RdbParser *p) {
    ElementCtx *ctx = &p->elmCtx;
    enum HASH_STATES {
        ST_HASH_HEADER=0, /* Retrieve number fields */
        ST_HASH_NEXT /* Process next field and callback to app (Iterative) */
    };

    switch (ctx->state) {
        case ST_HASH_HEADER:
            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &(ctx->hash.numFields), NULL, NULL));

            ctx->key.numItemsHint = ctx->hash.numFields;
            ctx->hash.visitingField = 0;

            /*** ENTER SAFE STATE ***/

            updateElementState(p, ST_HASH_NEXT); /* fall-thru */

        case ST_HASH_NEXT: {
            BulkInfo *binfoField, *binfoValue;

            if (ctx->hash.visitingField == ctx->hash.numFields)
                return nextParsingElement(p, PE_END_KEY);

            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoField));
            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoValue));

            /*** ENTER SAFE STATE ***/

            registerAppBulkForNextCb(p, binfoField);
            registerAppBulkForNextCb(p, binfoValue);
            if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleHashPlain,
                                 binfoField->ref,
                                 binfoValue->ref);
            }
            else {
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleHashField,
                                 binfoField->ref,
                                 binfoValue->ref);
            }

            ++ctx->hash.visitingField;
            return updateElementState(p, ST_HASH_NEXT);
        }

        default:
            RDB_reportError(p, RDB_ERR_PLAIN_HASH_INVALID_STATE,
                            "elementHash() : invalid parsing element state: %d", ctx->state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementHashZL(RdbParser *p) {
    BulkInfo *ziplistBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &ziplistBulk));

    /*** ENTER SAFE STATE ***/

    if (RDB_STATUS_ERROR == hashZiplist(p, ziplistBulk))
        return RDB_STATUS_ERROR;

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementHashLP(RdbParser *p) {
    BulkInfo *listpackBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &listpackBulk));

    /*** ENTER SAFE STATE ***/

    if (RDB_STATUS_ERROR == hashListPack(p, listpackBulk))
        return RDB_STATUS_ERROR;

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementHashZM(RdbParser *p) {
    BulkInfo *zipmapBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &zipmapBulk));

    /*** ENTER SAFE STATE ***/

    if (RDB_STATUS_ERROR == hashZipMap(p, zipmapBulk))
        return RDB_STATUS_ERROR;

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementSet(RdbParser *p) {
    ElementCtx *ctx = &p->elmCtx;
    enum SET_STATES {
        ST_SET_HEADER=0, /*  Retrieve number of nodes */
        ST_SET_NEXT_ITEM /* Process next node and callback to app (Iterative) */
    } ;
    switch (ctx->state) {
        case ST_SET_HEADER:
            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, (uint64_t *) &(ctx->key.numItemsHint), NULL, NULL));

            /*** ENTER SAFE STATE ***/

            ctx->set.left = ctx->key.numItemsHint;

            updateElementState(p, ST_SET_NEXT_ITEM); /* fall-thru */

        case ST_SET_NEXT_ITEM: {
            BulkInfo *binfoItem;
            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoItem));

            /*** ENTER SAFE STATE ***/

            registerAppBulkForNextCb(p, binfoItem);
            if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT)
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleSetPlain, binfoItem->ref);
            else
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleSetMember, binfoItem->ref);

            return (--ctx->set.left) ? updateElementState(p, ST_SET_NEXT_ITEM) : nextParsingElement(p, PE_END_KEY);
        }
        default:
            RDB_reportError(p, RDB_ERR_PLAIN_SET_INVALID_STATE,
                            "elementSet() : invalid parsing element state: %d", ctx->state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementSetIS(RdbParser *p) {
    BulkInfo *intsetBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &intsetBulk));

    /*** ENTER SAFE STATE ***/

    if (unlikely(!intsetValidateIntegrity(intsetBulk->ref, intsetBulk->len, p->deepIntegCheck))) {
        RDB_reportError(p, RDB_ERR_SET_IS_INTEG_CHECK, "elementSetIS(): INTSET integrity check failed");
        return RDB_STATUS_ERROR;
    }

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, intsetBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleSetIS, intsetBulk->ref);
    } else {
        p->elmCtx.key.numItemsHint = intsetLen((const intset *) intsetBulk->ref);
        int64_t intele;

        for (int iter = 0; intsetGet(intsetBulk->ref, iter, &intele) != 0; ++iter) {
            BulkInfo *bulkInt;
            int buflen = 32;
            IF_NOT_OK_RETURN(allocFromCache(p, buflen, RQ_ALLOC_APP_BULK, NULL, &bulkInt));

            bulkInt->len = ll2string(bulkInt->ref, buflen, intele);

            registerAppBulkForNextCb(p, bulkInt);
            CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleSetMember, bulkInt->ref);
        }
    }

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementSetLP(RdbParser *p) {
    unsigned char *iterator, *item;
    BulkInfo *listpackBulk;
    unsigned int itemLen;
    long long itemVal;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &listpackBulk));

    /*** ENTER SAFE STATE ***/

    /* Doesn't check for duplication */
    if (!lpValidateIntegrity(listpackBulk->ref, listpackBulk->len, p->deepIntegCheck, NULL, 0)) {
        RDB_reportError(p, RDB_ERR_SET_LP_INTEG_CHECK, "elementSetLP(): LISTPACK integrity check failed");
        return RDB_STATUS_ERROR;
    }

    /* TODO: handle empty listpack */
    p->elmCtx.key.numItemsHint = lpLength(listpackBulk->ref);

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, listpackBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleSetLP, listpackBulk->ref);
    } else {
        iterator = lpFirst(listpackBulk->ref);
        while (iterator) {
            EmbeddedBulk embBulk;
            item = lpGetValue(iterator, &itemLen, &itemVal);

            if (!allocEmbeddedBulk(p, item, itemLen, itemVal, &embBulk))
                return RDB_STATUS_ERROR;

            registerAppBulkForNextCb(p, embBulk.binfo);
            CALL_HANDLERS_CB(p,
                             restoreEmbeddedBulk(&embBulk);, /*finalize*/
                             RDB_LEVEL_DATA,
                             rdbData.handleSetMember,
                             embBulk.binfo->ref);

            iterator = lpNext(listpackBulk->ref, iterator);
        }
    }
    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementZset(RdbParser *p) {
    ElementCtx *ctx = &p->elmCtx;
    enum ZSET_STATES {
        ST_ZSET_HEADER=0, /*  Retrieve number of nodes */
        ST_ZSET_NEXT_ITEM /* Process next node and callback to app (Iterative) */
    };
    switch (ctx->state) {
        case ST_ZSET_HEADER:
            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, (uint64_t *) &(ctx->key.numItemsHint), NULL, NULL));

            /*** ENTER SAFE STATE ***/

            ctx->zset.left = ctx->key.numItemsHint;

            updateElementState(p, ST_ZSET_NEXT_ITEM); /* fall-thru */

        case ST_ZSET_NEXT_ITEM: {
            double score;
            BulkInfo *binfoItem;


            IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoItem));

            if (p->currOpcode == RDB_TYPE_ZSET_2) {
                IF_NOT_OK_RETURN(rdbLoadBinaryDoubleValue(p, &score));
            } else {
                IF_NOT_OK_RETURN(rdbLoadDoubleValue(p, &score));
            }

            /*** ENTER SAFE STATE ***/

            registerAppBulkForNextCb(p, binfoItem);
            if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT)
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleZsetPlain, binfoItem->ref, score);
            else
                CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleZsetMember, binfoItem->ref, score);

            return (--ctx->zset.left) ? updateElementState(p, ST_ZSET_NEXT_ITEM) : nextParsingElement(p, PE_END_KEY);
        }
        default:
            RDB_reportError(p, RDB_ERR_PLAIN_ZSET_INVALID_STATE,
                            "elementZset(): invalid parsing element state: %d", ctx->state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementZsetZL(RdbParser *p) {
    BulkInfo *ziplistBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &ziplistBulk));

    /*** ENTER SAFE STATE ***/

    if (RDB_STATUS_ERROR == zsetZiplistItem(p, ziplistBulk))
        return RDB_STATUS_ERROR;

    return nextParsingElement(p, PE_END_KEY);
}

RdbStatus elementZsetLP(RdbParser *p) {
    unsigned char *iterator, *item1, *item2;
    unsigned int item1Len, item2Len;
    long long item1Val, item2Val;
    BulkInfo *listpackBulk;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &listpackBulk));

    /*** ENTER SAFE STATE ***/

    /* Doesn't check for duplication */
    if (!lpValidateIntegrity(listpackBulk->ref, listpackBulk->len, p->deepIntegCheck, NULL, 0)) {
        RDB_reportError(p, RDB_ERR_ZSET_LP_INTEG_CHECK, "elementZsetLP(): LISTPACK integrity check failed");
        return RDB_STATUS_ERROR;
    }

    p->elmCtx.key.numItemsHint = lpLength(listpackBulk->ref);

    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT) {
        registerAppBulkForNextCb(p, listpackBulk);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleZsetLP, listpackBulk->ref);
    } else {
        iterator = lpFirst(listpackBulk->ref);
        while (iterator) {
            double score;
            EmbeddedBulk embBulk;

            item1 = lpGetValue(iterator, &item1Len, &item1Val);
            iterator = lpNext(listpackBulk->ref, iterator);
            item2 = lpGetValue(iterator, &item2Len, &item2Val);

            score = item2 ? zzlStrtod(item2, item2Len) : (double) item2Val;

            if (!allocEmbeddedBulk(p, item1, item1Len, item1Val, &embBulk))
                return RDB_STATUS_ERROR;

            registerAppBulkForNextCb(p, embBulk.binfo);
            CALL_HANDLERS_CB(p,
                             restoreEmbeddedBulk(&embBulk);, /*finalize*/
                             RDB_LEVEL_DATA,
                             rdbData.handleZsetMember,
                             embBulk.binfo->ref,
                             score);

            iterator = lpNext(listpackBulk->ref, iterator);
        }
    }
    return nextParsingElement(p, PE_END_KEY);
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
                RDB_log(p, RDB_LOG_WRN, "RDB file was saved with checksum disabled: no check performed.");
            } else if (cksum != evaluated) {
                RDB_reportError(p, RDB_ERR_CHECKSUM_FAILURE, "Wrong RDB checksum checksum=%lx, evaluated=%lx",
                                (unsigned long long) cksum,
                                (unsigned long long) p->checksum);
                return RDB_STATUS_ERROR;
            }
        }
    }

    CALL_COMMON_HANDLERS_CB_NO_ARGS(p, handleEndRdb);
    return RDB_STATUS_ENDED; /* THE END */
}

/*** function ***/

RdbStatus elementFunction(RdbParser *p) {
    BulkInfo *binfoFunc;

    IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC_APP_BULK, NULL, &binfoFunc));

    /*** ENTER SAFE STATE ***/

    registerAppBulkForNextCb(p, binfoFunc);
    if (p->handleTypeObjByLevel[p->currOpcode] == RDB_LEVEL_DATA)
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleFunction, binfoFunc->ref);
    else
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleFunction, binfoFunc->ref);

    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
}

/*** module ***/

/* Silently digest module or module-aux. Only level 0 propagates it to handlers */
RdbStatus elementModule(RdbParser *p) {
    ElementCtx *ctx = &p->elmCtx;
    enum MODULE_STATES {
        ST_MODULE_START=0,
        /* Following enums are aligned to module-opcodes to save mapping. Static assert below. */
        ST_MODULE_OPCODE_SINT=RDB_MODULE_OPCODE_SINT,
        ST_MODULE_OPCODE_UINT=RDB_MODULE_OPCODE_UINT,
        ST_MODULE_OPCODE_FLOAT=RDB_MODULE_OPCODE_FLOAT,
        ST_MODULE_OPCODE_DOUBLE=RDB_MODULE_OPCODE_DOUBLE,
        ST_MODULE_OPCODE_STRING=RDB_MODULE_OPCODE_STRING,

        ST_MODULE_NEXT_OPCODE,
    };

    while (1)
    {
        switch (ctx->state) {
            case ST_MODULE_START: {
                int hdrSize = 9;  /* moduleid size 8+1 bytes (Take care to update ctx only in safe state) */
                uint64_t when_opcode, when;
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &(ctx->module.moduleId), NULL, NULL));
                if (p->currOpcode == RDB_OPCODE_MODULE_AUX) {
                    hdrSize += 2; /* when_op and when are of size 1 byte each */
                    /* Load module data that is not related to the Redis key space. Such data can
                     * be potentially be stored both before and after the RDB keys-values section. */
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &when_opcode, NULL, NULL));
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &when, NULL, NULL));
                    if (unlikely(when_opcode != RDB_MODULE_OPCODE_UINT)) {
                        RDB_reportError(p, RDB_ERR_MODULE_INVALID_WHEN_OPCODE,
                            "elementModule() : Invalid when opcode: %d.", when_opcode);
                        return RDB_STATUS_ERROR;
                    }
                }
                /*** ENTER SAFE STATE ***/
                ctx->module.startBytesRead = p->bytesRead - hdrSize ;
                updateElementState(p, ST_MODULE_NEXT_OPCODE);
                break;
            }
            case ST_MODULE_OPCODE_SINT:
            case ST_MODULE_OPCODE_UINT: {
                uint64_t val; /*UNUSED*/
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &val, NULL, NULL));
                /*** ENTER SAFE STATE ***/
                updateElementState(p, ST_MODULE_NEXT_OPCODE);
                break;
            }
            case ST_MODULE_OPCODE_FLOAT: {
                float val; /*UNUSED*/
                IF_NOT_OK_RETURN(rdbLoadFloatValue(p, &val));
                /*** ENTER SAFE STATE ***/
                updateElementState(p, ST_MODULE_NEXT_OPCODE);
                break;
            }
            case ST_MODULE_OPCODE_DOUBLE: {
                double val; /*UNUSED*/
                IF_NOT_OK_RETURN(rdbLoadBinaryDoubleValue(p, &val));
                /*** ENTER SAFE STATE ***/
                updateElementState(p, ST_MODULE_NEXT_OPCODE);
                break;
            }
            case ST_MODULE_OPCODE_STRING: {
                BulkInfo *bInfo; /*UNUSED*/
                IF_NOT_OK_RETURN(rdbLoadString(p, RQ_ALLOC, NULL, &bInfo));
                /*** ENTER SAFE STATE ***/
                updateElementState(p, ST_MODULE_NEXT_OPCODE);
                break;
            }
            case ST_MODULE_NEXT_OPCODE: {
                uint64_t opcode = 0;
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &opcode, NULL, NULL));

                /*** ENTER SAFE STATE ***/

                if ((int) opcode != RDB_MODULE_OPCODE_EOF) {
                    /* Valid cast. Took care to align opcode with module states */
                    updateElementState(p, (int) opcode);
                    break;
                }

                /* EOF module/module-aux object */
                if (p->currOpcode == RDB_OPCODE_MODULE_AUX)
                    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
                else {
                    BulkInfo *bulkName;
                    IF_NOT_OK_RETURN(allocFromCache(p, 9, RQ_ALLOC_APP_BULK, NULL, &bulkName));

                    moduleTypeNameByID(bulkName->ref, p->elmCtx.module.moduleId);
                    size_t serializedSize = p->bytesRead - p->elmCtx.module.startBytesRead;

                    registerAppBulkForNextCb(p, bulkName);
                    if (p->elmCtx.key.handleByLevel == RDB_LEVEL_STRUCT)
                        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_STRUCT, rdbStruct.handleModule,
                                         bulkName->ref, serializedSize);
                    else
                        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_DATA, rdbData.handleModule,
                                         bulkName->ref, serializedSize);

                    return nextParsingElement(p, PE_END_KEY);
                }
            }
            default:
                /* if reached here, most probably because read invalid opcode from RDB */
                RDB_reportError(p, RDB_ERR_MODULE_INVALID_STATE,
                    "elementModule() : Invalid parsing element state: %d.", ctx->state);
                return RDB_STATUS_ERROR;
        }
    }
}

/*** Loaders from RDB ***/

RdbStatus rdbLoadFloatValue(RdbParser *p, float *val) {
    BulkInfo *binfo;
    IF_NOT_OK_RETURN(rdbLoad(p, sizeof(*val), RQ_ALLOC, NULL, &binfo));
    *val = *((float*) binfo->ref);
    memrev32ifbe(val);
    return RDB_STATUS_OK;
}

RdbStatus rdbLoadBinaryDoubleValue(RdbParser *p, double *val) {
    BulkInfo *binfo;
    IF_NOT_OK_RETURN(rdbLoad(p, sizeof(*val), RQ_ALLOC, NULL, &binfo));
    *val = *((double*) binfo->ref);
    memrev64ifbe(val);
    return RDB_STATUS_OK;
}

/*
 * For RDB_TYPE_ZSET, doubles are saved as strings prefixed by an unsigned
 * 8 bit integer specifying the length of the representation.
 * This 8 bit integer has special values in order to specify the following
 * conditions:
 * 253: not a number
 * 254: + inf
 * 255: - inf
 */
RdbStatus rdbLoadDoubleValue(RdbParser *p, double *val) {
    unsigned char len;
    BulkInfo *binfo;

    IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &binfo));
    len = *((unsigned char*)binfo->ref);

    switch (len) {
        case 255: *val = -INFINITY; return RDB_STATUS_OK;
        case 254: *val = INFINITY; return RDB_STATUS_OK;
        case 253: *val = NAN; return RDB_STATUS_OK;
        default:
            IF_NOT_OK_RETURN(rdbLoad(p, len, RQ_ALLOC, NULL, &binfo));
            if (sscanf(binfo->ref, "%lg", val) != 1)
                return RDB_STATUS_ERROR;

            return RDB_STATUS_OK;
    }
}

/* Try to read double value and then copy it to the destination including one
 * byte prefix. See rdbLoadDoubleValue() for details. */
RdbStatus rdbLoadDoubleValueToDest(RdbParser *p, char *dst, int *written) {
    double val;
    unsigned char len;
    BulkInfo *binfo;

    IF_NOT_OK_RETURN(rdbLoad(p, 1, RQ_ALLOC, NULL, &binfo));
    len = *((unsigned char*)binfo->ref);

    *dst++ = len;
    *written = 1;

    switch (len) {
        case 255:  /* -INFINITY */
        case 254:  /* INFINITY */
        case 253:  /* NAN */
            return RDB_STATUS_OK;
        default:
            IF_NOT_OK_RETURN(rdbLoad(p, len, RQ_ALLOC, NULL, &binfo));
            if (sscanf(binfo->ref, "%lg", &val) != 1)
                return RDB_STATUS_ERROR;

            memcpy(dst, binfo->ref, len);
            *written += len;
            return RDB_STATUS_OK;
    }
}

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
        RDB_log(p, RDB_LOG_ERR, "Unknown RDB integer encoding type %d", enctype);
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
        if (outbuff) memcpy(outbuff+1, binfo->ref, 8), (*outbufflen)+=8;
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

            /* Verify bigger than 0 (non-standard readers might fail on it) */
            if (likely(bytesToFill)) {
                res = p->reader->readFunc(p->reader->readerData,
                                          ((char *) (*binfo)->ref) + (*binfo)->written, bytesToFill);
                (*binfo)->written += bytesToFill;
                if (res != RDB_STATUS_OK) goto not_ok;
            }
            return RDB_STATUS_PAUSED;
        } else { /* fill up entire item */

            res = p->reader->readFunc(p->reader->readerData,
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
            RDB_log(p, RDB_LOG_WRN, "Reader returned error indication but didn't RDB_reportError()");
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
