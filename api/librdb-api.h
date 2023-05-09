#ifndef LIBRDB_API_H
#define LIBRDB_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _LIBRDB_API
#define _LIBRDB_API
#endif

/****************************************************************
 * Incomplete structures for compiler checks but opaque access
 ****************************************************************/

typedef char *RdbBulk;
typedef char *RdbBulkCopy;

typedef struct RdbReader RdbReader;
typedef struct RdbParser RdbParser;
typedef struct RdbHandlers RdbHandlers;
typedef struct RdbMemAlloc RdbMemAlloc;

/****************************************************************
 * Enums & Typedefs
 ****************************************************************/

typedef enum RdbRes {

    RDB_OK=0,

    /* RDB_OK_DONT_PROPAGATE - allowed to be returned only by handlers
     * callbacks to prevent propagation of the data to the next
     * Handlers in-line (of the same callback type). It can be useful to
     * implement sets of Handlers as Filters. As reference, see
     * implementation RDBX_createHandlersFilterKey */
    RDB_OK_DONT_PROPAGATE,

    /* Handlers callbacks can indicate to cancel parsing immediately */
    RDB_ERR_CANCEL_PARSING,

    /*** error codes - reported by parser's blocks ***/

    RDB_ERR_GENERAL,

    RDB_ERR_FAILED_OPEN_LOG_FILE,
    RDB_ERR_FAILED_READ_RDB_FILE,
    RDB_ERR_NO_MEMORY,
    RDB_ERR_FAILED_OPEN_RDB_FILE,
    RDB_ERR_WRONG_FILE_SIGNATURE,
    RDB_ERR_WRONG_FILE_VERSION,
    RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE,
    RDB_ERR_PARSER_RETURNED_INVALID_LIBRDB_STATUS,
    RDB_ERR_INVALID_LEN_ENCODING,
    RDB_ERR_INVALID_INT_ENCODING,
    RDB_ERR_STRING_INVALID_LZF_COMPRESSED,
    RDB_ERR_STRING_UNKNOWN_ENCODING_TYPE,
    RDB_ERR_NOT_SUPPORTED_RDB_ENCODING_TYPE,
    RDB_ERR_UNKNOWN_RDB_ENCODING_TYPE,
    RDB_ERR_QUICK_LIST_INTEG_CHECK,
    RDB_ERR_STRING_INVALID_STATE,
    RDB_ERR_QUICK_LIST_INVALID_STATE,
    RDB_ERR_INVALID_BULK_ALLOC_TYPE,
    RDB_ERR_INVALID_BULK_CLONE_REQUEST,
    RDB_ERR_INVALID_BULK_LENGTH_REQUEST,
    RDB_ERR_BULK_ALLOC_INVALID_TYPE,
    RDB_ERR_INVALID_IS_REF_BULK,
    RDB_ERR_EXP_EOF_BUT_PARSER_WAIT_MORE_DATA,
    RDB_ERR_EXP_WAIT_MORE_DATA_BUT_PARSER_EOF,
    RDB_ERR_CHECKSUM_FAILURE,
    RDB_ERR_PARSEBUF_AFTER_PAUSE_NOT_SAME_BUFF,
    RDB_ERR_MAX_RAW_LEN_EXCEEDED_FOR_KEY,
    RDB_ERR_EXCLUSIVE_RAW_HANDLERS,

    /*** api-ext error codes (see file: rp-ext-api.h) ***/
    _RDB_ERR_EXTENSION_FIRST = 0x1000,

    /*** user-defined error codes - reported by user-defined handlers or reader ***/
    _RDB_ERR_USER_DEFINED_FIRST = 0x2000,

} RdbRes;

typedef enum RdbState {
    RDB_STATECONFIGURING=0,
    RDB_STATERUNNING,
    RDB_STATEPAUSED,
    RDB_STATEENDED,
    RDB_STATEERROR,
} RdbState;

typedef enum RdbStatus {
    RDB_STATUS_OK = 0,
    RDB_STATUS_WAIT_MORE_DATA,
    RDB_STATUS_PAUSED,
    RDB_STATUS_ERROR
} RdbStatus;

typedef enum RdbHandlersLevel {
    RDB_LEVEL_RAW=0,  /* A set of handlers that get raw data */
    RDB_LEVEL_STRUCT, /* A set of handlers that get "low level" RDB data structures */
    RDB_LEVEL_DATA,   /* A set of handlers that get "high level" Redis data types */
    RDB_LEVEL_MAX,
} RdbHandlersLevel;

typedef enum RdbLogLevel {
    RDB_LOG_ERROR,
    RDB_LOG_WARNNING,
    RDB_LOG_INFO,
    RDB_LOG_DBG
} RdbLogLevel;

/* for explanation, read "Memory management" section below */
typedef enum RdbBulkAllocType {
    RDB_BULK_ALLOC_STACK,
    RDB_BULK_ALLOC_HEAP,
    RDB_BULK_ALLOC_EXTERN,
    RDB_BULK_ALLOC_EXTERN_OPT,
    RDB_BULK_ALLOC_MAX,
} RdbBulkAllocType;

typedef struct RdbKeyInfo {
    long long expiretime;
    uint64_t lru_idle;
    int lfu_freq;
} RdbKeyInfo;

/* misc function pointer typedefs */
typedef RdbStatus (*RdbReaderFunc) (RdbParser *p, void *readerData, void *buf, size_t len);
typedef void (*RdbFreeFunc) (RdbParser *p, void *obj);
typedef void (*RdbLoggerCB) (RdbLogLevel l, const char *msg);

/****************************************************************
 * Handlers callbacks struct
 ****************************************************************/

/* TODO: Pass "RdbParser *p" for each cb? User can hold it as well in "userData" */

/* avoid nested structures */
#define HANDLERS_COMMON_CALLBACKS \
    RdbRes (*handleModuleDatatype)(RdbParser *p, void *userData, RdbBulk value); \
    RdbRes (*handleNewDb)(RdbParser *p, void *userData,  int db); \
    RdbRes (*handleEndRdb)(RdbParser *p, void *userData); \
    RdbRes (*handleDbSize)(RdbParser *p, void *userData, uint64_t db_size, uint64_t exp_size); \
    RdbRes (*handleAuxField)(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval); \
    RdbRes (*handleNewKey)(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info); \
    RdbRes (*handleEndKey)(RdbParser *p, void *userData);

typedef struct RdbHandlersRawCallbacks {
    HANDLERS_COMMON_CALLBACKS
    RdbRes (*handleBegin)(RdbParser *p, void *userData, size_t size);
    RdbRes (*handleFrag)(RdbParser *p, void *userData, RdbBulk frag);
    RdbRes (*handleEnd)(RdbParser *p, void *userData);
//    RdbRes (*handleBeginModuleAux)(RdbParser *p, void *userData, RdbBulk name, int encver, int when);
} RdbHandlersRawCallbacks;

typedef struct RdbHandlersStructCallbacks {
    HANDLERS_COMMON_CALLBACKS
    RdbRes (*handleStringValue)(RdbParser *p, void *userData, RdbBulk str);
    RdbRes (*handlerQListNode)(RdbParser *p, void *userData, RdbBulk listNode);
    RdbRes (*handlerPlainNode)(RdbParser *p, void *userData, RdbBulk node);
    /* ... TBD ... */
} RdbHandlersStructCallbacks;

typedef struct RdbHandlersDataCallbacks {
    HANDLERS_COMMON_CALLBACKS
    RdbRes (*handleStringValue)(RdbParser *p, void *userData, RdbBulk str);
    RdbRes (*handleListElement)(RdbParser *p, void *userData, RdbBulk str);
//    RdbRes (*handleSetElement)(RdbParser *p, void *userData, RdbBulk str, unsigned long sizeHint);
//    RdbRes (*handleZsetElement)(RdbParser *p, void *userData, RdbBulk str, double score, unsigned long sizeHint);
//    RdbRes (*handleHashElement)(RdbParser *p, void *userData, RdbBulk field, RdbBulk value, unsigned long sizeHint);
    /* ... TBD ... */
} RdbHandlersDataCallbacks;

/****************************************************************
 * Parser creation and deletion
 ****************************************************************/
_LIBRDB_API RdbParser *RDB_createParserRdb(RdbMemAlloc *memAlloc);
_LIBRDB_API void RDB_deleteParser(RdbParser *p);

/****************************************************************
 * Execute parser
 ****************************************************************/
_LIBRDB_API RdbStatus RDB_parse(RdbParser *p);

/* parse in mem buffers without a reader */
_LIBRDB_API RdbStatus RDB_parseBuff(RdbParser *p,
                                    unsigned char *buff,
                                    size_t size, int isEOF);

/****************************************************************
 * Create Reader
 * Used by:   RDBX_createReaderFile
 *           <user-defined-reader>
 ****************************************************************/
_LIBRDB_API RdbReader *RDB_createReaderRdb(RdbParser *p,
                                           RdbReaderFunc r,
                                           void *readerData,
                                           RdbFreeFunc freeReaderData);

/****************************************************************
 * Create Handlers
 *
 * Create set of handlers, at requested level (lvl), to be filled up with
 * callback handlers.
 *
 * Used by:  RDBX_createHandlersRdb2Json
 *           RDBX_createHandlersFilterKey
 *           <user-defined-handlers>
 ****************************************************************/
_LIBRDB_API RdbHandlers *RDB_createHandlersRaw(RdbParser *p,
                                               RdbHandlersRawCallbacks *callbacks,
                                               void *userData,
                                               RdbFreeFunc freeUserData);

_LIBRDB_API RdbHandlers *RDB_createHandlersStruct(RdbParser *p,
                                                  RdbHandlersStructCallbacks *callbacks,
                                                  void *userData,
                                                  RdbFreeFunc freeUserData);

_LIBRDB_API RdbHandlers *RDB_createHandlersData(RdbParser *p,
                                                RdbHandlersDataCallbacks *callbacks,
                                                void *userData,
                                                RdbFreeFunc freeUserData);

/****************************************************************
 * Handlers prevent data propagation
 *
 * When Handlers is being called by the parser, it can decide not to propagate
 * the data to the next Handlers in-line. It can  be useful to implement sets of
 * Handlers as Filters. Use this function only from inside Handlers callbacks.
 * As reference, see implementation of RDBX_createHandlersFilterKey
 ****************************************************************/
 _LIBRDB_API void RDB_dontPropagate(RdbParser *p);

/****************************************************************
 * Parser setters & getters
 ****************************************************************/

_LIBRDB_API void RDB_setMaxRawLenHandling(RdbParser *p, size_t size);
_LIBRDB_API void RDB_setDeepIntegCheck(RdbParser *p, int deep);
_LIBRDB_API size_t RDB_getBytesProcessed(RdbParser *p);
_LIBRDB_API RdbState RDB_getState(RdbParser *p);
_LIBRDB_API void RDB_IgnoreChecksum(RdbParser *p);

/* logger */
_LIBRDB_API void RDB_setLogLevel(RdbParser *p, RdbLogLevel l);
_LIBRDB_API void RDB_setLogger(RdbParser *p, RdbLoggerCB f);
_LIBRDB_API void RDB_log(RdbParser *p, RdbLogLevel lvl, const char *format, ...);

/****************************************************************
 * Pause the Parser
 *
 * the parser can be configured with a pause interval that specifies the number
 * of bytes to be processed before pausing. This means that each time the parser
 * is invoked, it will continue parsing until it has processed a number of bytes
 * equal to or greater than the configured interval, at which point it will
 * automatically pause and return 'RDB_STATUS_PAUSED' in order to allow the
 * application to perform other tasks. It is also possible to pause the parser
 * by the callbacks by calling RDB_pauseParser()
 ****************************************************************/
_LIBRDB_API void RDB_setPauseInterval(RdbParser *p, size_t interval);

_LIBRDB_API void RDB_pauseParser(RdbParser *p);

/****************************************************************
 * Error Handling
 *
 * If the parser, or attached built-in handlers or reader got failed, they will
 * make an internal call to `RDB_reportError` to keep the error. The way to the
 * app to retrieve the error is via `RDB_getErrorCode` and `RDB_getErrorMessage`.
 *
 * Likewise, if one of the app's callback handlers got failed, it should report
 * the error to the parser by function `RDB_reportError` and also can provide
 * description to the error. Either way, app's callbaack must return the error
 * code. (See RdbRes enum for valid range of user-defined error-code to app to
 * report).
 ****************************************************************/
_LIBRDB_API RdbRes RDB_getErrorCode(RdbParser *p);
_LIBRDB_API const char *RDB_getErrorMessage(RdbParser *p);
_LIBRDB_API void RDB_reportError(RdbParser *p, RdbRes e, const char *msg, ...);

/****************************************************************
 * Memory management
 *
 * User can configure his own set of malloc/free functions via structure
 * RdbMemAlloc
 *
 * If library is used in a multi-threaded application, then functions must be
 * thread safe. In that case, library is thread-safe as well.
 *
 * When functions are not set or set to NULL then, they are set to internal
 * routines that use the standard library functions malloc() and free()
 *
 * Optimizing Bulk Allocation
 *
 * On callback, sometimes the client application need to receive the processed
 * payload wrapped in specific structure, such as, with additional header. To
 * save the extra copy, the app can provide the parser its own allocator only
 * for RdbBulk (and specify that bulkAllocType is of type RDB_BULK_ALLOC_EXTERN).
 * In that case the parser will allocate with provided allocation function and
 * copy the plain payload along with '\0' termination (without any headers or
 * trailers). Note that actual allocation sometimes might be larger than than
 * RDB_bulkLen + 1 (Plus one for the termination character).
 *
 * On the other hand, if the parser heap allocation is sufficient, and the
 * client application doesn't care about the wrapping structure of RdbBulk,
 * then set bulkAllocType to RDB_BULK_ALLOC_HEAP. Note that `RDB_bulkClone` in
 * that case will only increment refcount.
 *
 * If the client app not going to use too much `RDB_bulkClone` (cloning bulks.
 * See below.) then it is better to set RDB_BULK_ALLOC_STACK, such that, when
 * possible allocation quickly be made on internal stack.
 *
 * As mentioned above, RDB_BULK_ALLOC_EXTERN can help to avoid redundant copies
 * of bulks. Yet, there are some cases that the parser can avoid bulk allocation
 * of any type because the data is already available in memory, either because
 * data prefetched, preceding in-memory decompress chunk of data, etc. If the
 * application wants to optimize those cases as well along with external
 * allocator, it can configure bulkAllocType to RDB_BULK_ALLOC_EXTERN_OPT. But
 * then not all the given RdbBulk to callbacks will be allocated by provided
 * allocation function and the app's callback cannot make any assumption about
 * RdbBulk allocation. To decide in this case if given RdbBulk is actually
 * allocated by configured external allocator or only reference another section
 * of memory, the callback will need to assist function `RDB_isRefBulk`.
 * TODO: Mark callbacks that might return referenced bulk
 ****************************************************************/
struct RdbMemAlloc {
    void *(*malloc)(size_t size);
    void *(*realloc)(void *ptr, size_t size);
    void (*free)(void *ptr);

    RdbBulkAllocType bulkAllocType;

    /* appBulk is relevant only if bulkAllocType equals RDB_BULK_ALLOC_EXTERN or
     * RDB_BULK_ALLOC_EXTERN_OPT */
    struct {
        void *(*alloc)(size_t size);
        void *(*clone)(void *ptr, size_t size);
        void (*free)(void *ptr);
    } appBulk;
};

/* Memory allocation functions to be used by Reader & Handlers extensions */
void *RDB_alloc(RdbParser *p, size_t size);
void *RDB_realloc(RdbParser *p, void *ptr, size_t size);
void RDB_free(RdbParser *p, void *ptr);

/****************************************************************
 * RdbBulk - native c-string alike
 *
 * The purpose of RdbBulk is to give native c-string feeling, yet hiding whether
 * it actually allocated behind on stack, heap, reference another memory, or
 * externally allocated by user supplied RdbBulk allocation function.
 *
 * In order to process the string behind the current call-stack,  function
 * `RDB_bulkClone()` is the way to clone a string, within callback context only!
 * If bulk allocated on stack (default of bulkAllocType) or reference another
 * memory, then the function will malloc memory on heap and return a copy to the
 * user. If allocated on heap, then just a refcount will be incremented.
 *
 * IF configured external allocator, then corresponding clone callback will be
 * made, giving the opportunity to the application client to clone in its own
 * way. In that mode the parser will only copy afterward the plain payload along
 * with '\0' termination (It might seem like redundant to application to clone
 * something that it knows to work with natively, but it is still required for
 * 3rd party handlers that only familiar with the parser API).
 *
 * Note that the returned value of RDB_bulkClone has a distinct typedef, called
 * RdbBulkCopy, in order to differentiate the functions that are allowed to apply
 * on RdbBulk than the one allowed to apply on RdbBulkCopy.
 ****************************************************************/
_LIBRDB_API  RdbBulkCopy RDB_bulkClone(RdbParser *p, RdbBulk b);

_LIBRDB_API  void RDB_bulkFree(RdbParser *p, RdbBulkCopy b);

_LIBRDB_API  size_t RDB_bulkLen(RdbParser *p, RdbBulk b);

int RDB_isRefBulk(RdbParser *p, RdbBulk b);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_H
