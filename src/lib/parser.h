#ifndef LIBRDB_PARSER_H
#define LIBRDB_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include "defines.h"
#include "../../api/librdb-api.h"

#define MAX_ERROR_MSG 1024
#define MAX_APP_BULKS 2
#define NOP /*no-op*/
#define IF_NOT_OK_RETURN(cmd) do {RdbStatus s; s = cmd; if (unlikely(s!=RDB_STATUS_OK)) return s;} while (0)

/* parser internal status value. Not exposed at to the caller.
 * Saves us another stopping condition in main loop. */
#define RDB_STATUS_ENDED 999

#define RAW_AGG_FIRST_STATIC_BUFF_LEN (1024*32)

#define UNUSED(...) unused( (void *) NULL, ##__VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}

/* Used by the parser to call all registered handlers, across levels */
#define CALL_COMMON_HANDLERS_CB(p, callback, ...)  \
    __CALL_COMMON_HANDLERS_CB(p, callback, h->userData, ##__VA_ARGS__)
#define CALL_COMMON_HANDLERS_CB_NO_ARGS(p, callback) \
    __CALL_COMMON_HANDLERS_CB(p, callback, h->userData)
#define __CALL_COMMON_HANDLERS_CB(p, callback, ...) \
  do { \
    for (RdbHandlers *h = p->firstHandlers; h ; h = h->next) { \
        if (h->h.common.callback) { \
            p->errorCode = h->h.common.callback(p, ##__VA_ARGS__); \
            if (unlikely(p->errorCode != RDB_OK)) { \
                if (p->errorCode == RDB_OK_DONT_PROPAGATE) { \
                    p->errorCode = RDB_OK; \
                    /* skip all handlers until next level */ \
                    RdbHandlersLevel currLevel = h->level; \
                    while ( (h->next) && (h->next->level == currLevel) ) h = h->next; \
                    continue; \
                } \
                return RDB_STATUS_ERROR; \
            } \
        } \
    } \
    p->appCbCtx.numBulks = 0; \
  } while (0)

/* Used by the parser to call all registered handlers, for given level */
#define CALL_HANDLERS_CB(p, finalize_cmd, lvl,level_and_callback, ...) \
    __CALL_HANDLERS_CB(p, finalize_cmd, lvl,level_and_callback, h->userData, ##__VA_ARGS__)
#define CALL_HANDLERS_CB_NO_ARGS(p, finalize_cmd, lvl,level_and_callback) \
    __CALL_HANDLERS_CB(p, finalize_cmd, lvl,level_and_callback, h->userData)
#define __CALL_HANDLERS_CB(p, finalize_cmd, lvl,level_and_callback, ...) \
  do { \
    RdbHandlers *h = p->handlers[lvl]; \
    for (int ii = 0 ; ii < p->numHandlers[lvl] ; ++ii) { \
        if (h->h.level_and_callback) { \
            p->errorCode = h->h.level_and_callback(p, ##__VA_ARGS__);\
            if (unlikely(p->errorCode != RDB_OK)) { \
                if (p->errorCode == RDB_OK_DONT_PROPAGATE) { \
                    p->errorCode = RDB_OK; \
                    break; /* Don't propagate to next handler */ \
                } \
                finalize_cmd; \
                return RDB_STATUS_ERROR; \
            } \
        } \
        h = h->next; \
    } \
    p->appCbCtx.numBulks = 0; \
    finalize_cmd; \
  } while (0)

typedef enum BulkType {
    BULK_TYPE_STACK,    /* from stack bulk */
    BULK_TYPE_HEAP,     /* from heap bulk */
    BULK_TYPE_EXTERN,   /* from external allocator */
    BULK_TYPE_REF,      /* Reference another memory bulk */
    BULK_TYPE_MAX
} BulkType;

typedef struct BulkInfo {
    BulkType bulkType;
    void *ref;
    size_t len;    /* allocation size, not including '\0' at the end */
    size_t written;
    struct BulkInfo *next;
} BulkInfo;

/* Allocation requests from the parser to BulkPool */
typedef enum {
    /* Allocate for internal use of the parser */
    RQ_ALLOC,
    RQ_ALLOC_REF, /*placement-new*/
    /* Allocate RdbBulk in order to pass it to app callbacks */
    RQ_ALLOC_APP_BULK,
    RQ_ALLOC_APP_BULK_REF,
    RQ_ALLOC_MAX
} AllocTypeRq;

/* Unmanaged allocation requests from the parser */
typedef enum {
    /* Allocate for internal use of the parser */
    UNMNG_RQ_ALLOC,
    UNMNG_RQ_ALLOC_REF,
    /* Allocate RdbBulk in order to pass it to app callbacks */
    UNMNG_RQ_ALLOC_APP_BULK,
    UNMNG_RQ_ALLOC_APP_BULK_REF,
    UNMNG_RQ_ALLOC_MAX
} AllocUnmngTypeRq;

typedef enum ParsingElementType {
    /* Common elements */
    PE_RDB_HEADER,
    PE_NEXT_RDB_TYPE,
    PE_AUX_FIELD,
    PE_SELECT_DB,
    PE_RESIZE_DB,
    PE_EXPIRETIME,
    PE_EXPIRETIMEMSEC,
    PE_FREQ,
    PE_IDLE,

    PE_NEW_KEY,
    PE_END_KEY,

    /* parsing data types */
    PE_STRING,
    PE_LIST,
    PE_QUICKLIST,
    PE_LIST_ZL,
    PE_HASH,
    PE_HASH_ZL,
    PE_HASH_LP,
    PE_HASH_ZM,
    PE_SET,
    PE_SET_IS,
    PE_SET_LP,

    /* parsing raw data types */
    PE_RAW_NEW_KEY,
    PE_RAW_END_KEY,
    PE_RAW_STRING,
    PE_RAW_LIST,
    PE_RAW_QUICKLIST,
    PE_RAW_LIST_ZL,
    PE_RAW_HASH,
    PE_RAW_HASH_ZL,
    PE_RAW_HASH_LP,
    PE_RAW_HASH_ZM,
    PE_RAW_SET,
    PE_RAW_SET_IS,
    PE_RAW_SET_LP,

    PE_END_OF_FILE,
    PE_MAX
} ParsingElementType;

typedef struct BulkPool BulkPool; /* fwd decl */

typedef RdbStatus (*ParsingElementFunc) (RdbParser *p);
typedef RdbStatus (*ReadRdbFunc)(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **out);

typedef struct ParsingElementInfo {
    ParsingElementFunc func;
    const char *funcname;
    const char *description;
} ParsingElementInfo;

typedef struct {
    uint64_t numNodes;
} ElementListCtx;

typedef struct {
    uint64_t left;
} ElementSetCtx;

typedef struct {
    uint64_t numFields;
    uint64_t visitingField;
} ElementHashCtx;

typedef struct {
    RdbKeyInfo info;
    ParsingElementType valueType;
    RdbHandlersLevel handleByLevel;
    int64_t numItemsHint; /* hint for the total number of items in the current parsed key. -1 if unknown */
} ElementKeyCtx;

typedef struct {
    unsigned char **buff;
    uint64_t len, clen, uclen, encoding;
    int isencoded;
} ElementRawStringCtx;

typedef struct {
    uint64_t numNodes;
    uint64_t container;
} ElementRawListCtx;

typedef struct {
    uint64_t numItems;
} ElementRawSetCtx;

typedef struct {
    uint64_t numFields;
    uint64_t  visitField;
} ElementRawHashCtx;

typedef struct ElementCtx {
    ElementKeyCtx key;
    ElementListCtx list;
    ElementSetCtx set;
    ElementHashCtx hash;

    /* raw elements context */
    ElementRawStringCtx rawString;
    ElementRawListCtx rawList;
    ElementRawSetCtx rawSet;
    ElementRawHashCtx rawHash;

    int state;  /* parsing-element state */
} ElementCtx;

/* The parser can handle one level of nested parsing-elements (PE), whereby a PE
 * may be called by another PE and control is returned to the caller once the
 * parsing of sub-element is complete. Currently, this functionality is only
 * utilized by the raw list PE, which calls upon the raw string PE to parse
 * individual string elements. */
typedef struct ParsingSubElement {

    /* let callee knows which element and state to callback once done */
    ParsingElementType callerElm;
    int stateToReturn;

    BulkInfo bulkResult;  /* unmanaged bulk (Callee alloc -> caller release) */
} ParsingSubElement;

typedef struct AppCallbackCtx {
    /* The array bulks[] keep RdbBulks metadata out of band and available by need
     * for operations by next callback, such as bulk length, or how to clone,
     * etc. Note that keeping bulks metadata out-of-band (i.e. not sequentially
     * in memory with a preceding header) is essential in case when bulkAllocType
     * is set to external since external allocations expect to receive only bare
     * data. It is also essential when referenced another memory in order to
     * avoid yet another allocation. */
    BulkInfo *bulks[MAX_APP_BULKS];
    int numBulks;  /* reset to 0 after each HANDLERS_CB */
} AppCallbackCtx;

typedef struct RawContext {

    /* aggType - The parser encounters difficulty determining the size of
     * certain types during their parsing because they lack a preceding header
     * that would indicate their size. This creates a problem when implementing
     * callback handlers for executing RESP2 RESTORE commands on a live server,
     * which requires the type's size to be sent at the beginning. To resolve
     * this issue, the parser gathers all payload data for these types and only
     * provides it to callback handlers once it reaches the end of the type and
     * knows its total size. However, for types like strings, whose sizes are
     * already known at the beginning, the parser will not aggregate the entire
     * payload if it is large enough, but stream it to handleFrag callback. */
    enum {
        AGG_TYPE_UNINIT,
        AGG_TYPE_ENTIRE_DATA,
        AGG_TYPE_PARTIALLY
    } aggType;

    char staticBulk[RAW_AGG_FIRST_STATIC_BUFF_LEN];
    BulkInfo *bulkArray;  /* exp-growth */

    char *at;
    int curBulkIndex;
    size_t totalSize;
} RawContext;

struct RdbParser {

    RdbState state;                /* internal state */
    int currOpcode;                    /* current RDB opcode */
    ParsingElementType parsingElement; /* current PE (parsing element) */
    ParsingSubElement callSubElm;

    /*** parser handlers ***/
    /* Maintain a chain of Handlers to each level. Each Handlers embed in it pointer to `next` handlers */
    RdbHandlers *handlers[RDB_LEVEL_MAX];
    int numHandlers[RDB_LEVEL_MAX];
    int totalHandlers;
    RdbHandlers *firstHandlers;
    RdbHandlersLevel handleTypeObjByLevel[RDB_TYPE_MAX];

    /*** configuration ***/
    RdbMemAlloc mem;
    int deepIntegCheck;
    int ignoreChecksum;
    RdbLoggerCB loggerCb;
    RdbLogLevel logLevel;
    size_t maxRawSize;

    /*** context ***/
    ElementCtx elmCtx;       /* parsing-element context */
    AppCallbackCtx appCbCtx; /* Trace bulks that will be given to next app cb. Cleared after each cb */
    RawContext rawCtx;

    /*** caching ***/
    BulkPool *cache;   /* Cleared after each parsing-element state change */

    /*** error reporting ***/
    RdbRes errorCode;
    char errorMsg[MAX_ERROR_MSG];

    /*** read RDB from reader VS read RDB from buffer ***/

    int isParseFromBuff;     /* bool */
    size_t bytesRead;
    RdbReader *reader;
    struct {
        unsigned char *start;
        unsigned char *end;
        unsigned char *at;
        size_t size;
    } parsebuffCtx;

    /* points to: readRdbFromBuff / readRdbFromReader / readRdbWaitMoreDataDbg */
    ReadRdbFunc readRdbFunc;

    /*** pause interval ***/
    /* pauseInterval - At least number of bytes to process before pausing. App can configure
     * it via RDB_setPauseInterval(). In addition, if handler's callback wishes to suspend
     * immediately because some condition has met, then it need to call RDB_pauseParser(). */
    size_t pauseInterval;
    size_t bytesToNextPause;

    /*** misc ***/
    int rdbversion;       /* keep aside RDB version */
    uint64_t checksum;
    int debugData;      /* if envvar LIBRDB_DEBUG_DATA=1 then print state machine transitions */
};

/* reader base struct */
struct RdbReader {
    void *readerData;
    RdbReaderFunc readFunc;
    RdbParser *parser;
    RdbFreeFunc destructor; /* destructor for "derived structs" of RdbReader */
};

typedef struct HandlersCommonCallbacks {
    HANDLERS_COMMON_CALLBACKS
} HandlersCommonCallbacks;

/* RDB Handlers base struct */
struct RdbHandlers {
    void *userData;

    RdbHandlers *next;   /* next handlers in the parser's stack (at level: level)  */
    RdbHandlersLevel level; /* handlers registered at what level of the parser (bluk/struct/data) */
    RdbFreeFunc destructor; /* destructor for derived structs of this struct */
    RdbParser *parser;

    union {
        HandlersCommonCallbacks common;

        RdbHandlersRawCallbacks rdbRaw;
        RdbHandlersStructCallbacks rdbStruct;
        RdbHandlersDataCallbacks rdbData;
    } h;
};

/*** inline functions ***/

/* before each handler's callback with RdbBulk, need to register its corresponding
 * BulkInfo (See comment at struct AppCallbackCtx) */
static inline void registerAppBulkForNextCb(RdbParser *p, BulkInfo *binfo) {
    assert(p->appCbCtx.numBulks < MAX_APP_BULKS);
    p->appCbCtx.bulks[p->appCbCtx.numBulks++] = binfo;
}

extern void bulkPoolFlush(RdbParser *p); /* avoid cyclic headers inclusion */

static inline RdbStatus updateElementState(RdbParser *p, int newState) {
    bulkPoolFlush(p);
    p->elmCtx.state = newState;
    return RDB_STATUS_OK;
}

static inline RdbStatus nextParsingElementState(RdbParser *p, ParsingElementType next, int st) {
    bulkPoolFlush(p);
    p->elmCtx.state = st;
    p->parsingElement = next;
    return RDB_STATUS_OK;
}

static inline RdbStatus nextParsingElement(RdbParser *p, ParsingElementType next) {
    bulkPoolFlush(p);
    p->elmCtx.state = 0;
    p->parsingElement = next;
    return RDB_STATUS_OK;
}

/*** sub-element parsing ***/
RdbStatus subElementCall(RdbParser *p, ParsingElementType next, int returnState);
RdbStatus subElementReturn(RdbParser *p, BulkInfo *bulkResult);
void subElementCallEnd(RdbParser *p, RdbBulk *bulkResult, size_t *len);

/*** Loaders from RDB ***/
RdbStatus rdbLoadLen(RdbParser *p, int *isencoded, uint64_t *lenptr, unsigned char* outbuff, int *outbufflen);
RdbStatus rdbLoadInteger(RdbParser *p, int enctype, AllocTypeRq type, char *refBuf, BulkInfo **out);
RdbStatus rdbLoadString(RdbParser *p, AllocTypeRq type, char *refBuf, BulkInfo **out);
RdbStatus rdbLoadLzfString(RdbParser *p, AllocTypeRq type, char *refBuf, BulkInfo **out);
static inline RdbStatus rdbLoad(RdbParser *p, size_t len, AllocTypeRq type, char *refBuf, BulkInfo **out) {
    return p->readRdbFunc(p, len, type, refBuf, out);
}

/*** raw data parsing ***/
void parserRawInit(RdbParser *p);
void parserRawRelease(RdbParser *p);

/*** Common Parsing Elements ***/
RdbStatus elementNewKey(RdbParser *p);
RdbStatus elementEndKey(RdbParser *p);
RdbStatus elementEndOfFile(RdbParser *p);
RdbStatus elementRdbHeader(RdbParser *p);
RdbStatus elementNextRdbType(RdbParser *p);
RdbStatus elementAuxField(RdbParser *p);
RdbStatus elementSelectDb(RdbParser *p);
RdbStatus elementResizeDb(RdbParser *p);
RdbStatus elementExpireTime(RdbParser *p);
RdbStatus elementExpireTimeMsec(RdbParser *p);
RdbStatus elementFreq(RdbParser *p);
RdbStatus elementIdle(RdbParser *p);

/*** Struct/Data Parsing Elements ***/
RdbStatus elementString(RdbParser *p);
RdbStatus elementList(RdbParser *p);
RdbStatus elementQuickList(RdbParser *p);
RdbStatus elementListZL(RdbParser *p);
RdbStatus elementHash(RdbParser *p);
RdbStatus elementHashZL(RdbParser *p);
RdbStatus elementHashLP(RdbParser *p);
RdbStatus elementHashZM(RdbParser *p);
RdbStatus elementSet(RdbParser *p);
RdbStatus elementSetIS(RdbParser *p);
RdbStatus elementSetLP(RdbParser *p);

/*** Raw Parsing Elements ***/
RdbStatus elementRawNewKey(RdbParser *p);
RdbStatus elementRawEndKey(RdbParser *p);
RdbStatus elementRawList(RdbParser *p);
RdbStatus elementRawQuickList(RdbParser *p);
RdbStatus elementRawString(RdbParser *p);
RdbStatus elementRawListZL(RdbParser *p);
RdbStatus elementRawHash(RdbParser *p);
RdbStatus elementRawHashZL(RdbParser *p);
RdbStatus elementRawHashLP(RdbParser *p);
RdbStatus elementRawHashZM(RdbParser *p);
RdbStatus elementRawSet(RdbParser *p);
RdbStatus elementRawSetIS(RdbParser *p);
RdbStatus elementRawSetLP(RdbParser *p);



#endif /*LIBRDB_PARSER_H*/