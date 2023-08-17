#include <sys/time.h>
#include <sys/uio.h>
#include "librdb-api.h"
#ifndef LIBRDB_API_EXT_H
#define LIBRDB_API_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Incomplete structures */
typedef struct RdbxRespFileWriter RdbxRespFileWriter;
typedef struct RdbxReaderFile RdbxReaderFile;
typedef struct RdbxReaderFileDesc RdbxReaderFileDesc;
typedef struct RdbxFilterKey RdbxFilterKey;
typedef struct RdbxToJson RdbxToJson;
typedef struct RdbxToResp RdbxToResp;
typedef struct RdbxRespToRedisLoader RdbxRespToRedisLoader;

/****************************************************************
* Error codes
****************************************************************/

typedef enum {
    RDBX_ERR_READER_FILE_GENERAL_ERROR = _RDB_ERR_EXTENSION_FIRST,
    RDBX_ERR_RESP_FAILED_ALLOC,

    /* rdb2json errors */
    RDBX_ERR_FAILED_OPEN_FILE,
    RDBX_ERR_R2J_INVALID_STATE,

    /* HandlersFilterKey errors */
    RDBX_ERR_FILTER_FAILED_COMPILE_REGEX,

    /* rdb2resp errors */

    /* resp writer/loader */
    RDBX_ERR_RESP_WRITE,
    RDBX_ERR_RESP_READ,
    RDBX_ERR_RESP2REDIS_CREATE_SOCKET,
    RDBX_ERR_RESP2REDIS_INVALID_ADDRESS,
    RDBX_ERR_RESP2REDIS_FAILED_CONNECT,
    RDBX_ERR_RESP2REDIS_FAILED_READ,
    RDBX_ERR_RESP2REDIS_FAILED_WRITE,
    RDBX_ERR_RESP2REDIS_CONN_CLOSE,
    RDBX_ERR_RESP2REDIS_MAX_RETRIES,
} RdbxRes;

/****************************************************************
 * Create RDB Reader
 ****************************************************************/

_LIBRDB_API RdbxReaderFile *RDBX_createReaderFile(RdbParser *parser, const char *filename);

_LIBRDB_API RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int closeWhenDone);

/****************************************************************
 * Create RDB to JSON Handlers
 ****************************************************************/

typedef enum RdbxToJsonEnc {
    RDBX_CONV_JSON_ENC_PLAIN,
    RDBX_CONV_JSON_ENC_BASE64
} RdbxToJsonEnc;

typedef struct RdbxToJsonConf {
    RdbHandlersLevel level;
    RdbxToJsonEnc encoding;
    int skipAuxField;
    int flatten; /* 0=db hirarchy preserved 1=flatten json */
} RdbxToJsonConf;

_LIBRDB_API RdbxToJson *RDBX_createHandlersToJson(RdbParser *p,
                                                  const char *filename,
                                                  RdbxToJsonConf *c);

/****************************************************************
 * Create Filter Handlers
 ****************************************************************/

_LIBRDB_API RdbxFilterKey *RDBX_createHandlersFilterKey(RdbParser *p,
                                                        const char *keyRegex,
                                                        uint32_t flags);

/****************************************************************
 * Create RDB to RESP Handlers
 *
 * The RDB to RESP handlers (RdbxToResp) provide a way to generate a stream of
 * redis protocol commands. The output of if it will be consumed
 * by an instance of type RESP writer (RdbxRespWriter. Explained below).
 ****************************************************************/

typedef struct RdbxToRespConf {
    /* TODO: support the option of expire, del, select db */

    /* If supportRestore, then data-types will be translated to RESTORE with
     * raw data instead of data-types commands. This is a performance optimization
     * that requires to be version aligned. */
    int supportRestore;

    /* TODO: support rdb2resp del key before write */
    int delKeyBeforeWrite;
    int skipAuxField;
    int applySelectDbCmds;

    /* relevant only if supportRestore is set. */
    struct {
        /* It is required to verify that the target (consumer) of the RESP payload
         * is aligned with the version of the source RDB file. Otherwise, restore
         * won't be respected */

        /* Configure what is target RDB version. if equals 0, then the value
         * will be resolved by the value of dstRedisVersion. */
        int dstRdbVersion;

        /* an alternative configuration to dstRdbVersion */
        char *dstRedisVersion;
    } restore;

} RdbxToRespConf;

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *, RdbxToRespConf *);

/****************************************************************
 * Attach RESP writer
 *
 * Create instance for writing RDB to RESP stream.
 *
 * Used by:  RDBX_createRespToRedisTcp
 *           RDBX_createRespToRedisFd
 *           RDBX_createRespFileWriter
 *           <user-defined-handlers>
 ****************************************************************/

typedef struct RdbxRespWriter {
    void *ctx;
    void (*delete)(void *ctx);

    /* return 0 on success. Otherwise 1 */
    int (*writev) (void *ctx, struct iovec *ioVec, int count, int startCmd, int endCmd);
    int (*flush) (void *ctx);
} RdbxRespWriter;

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer);


/****************************************************************
 * Create RESP File Writer
 *
 * If provided path is NULL then write stdout
 ****************************************************************/
_LIBRDB_API RdbxRespFileWriter *RDBX_createRespFileWriter(RdbParser *p,
                                                          RdbxToResp *rdbToResp,
                                                          const char* filepath);

/****************************************************************
 * Create RESP to Redis TCP connection
 *
 * Can configure pipeline depth of transmitted RESP commands. Set
 * to 0 if to use default.
 ****************************************************************/
_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            const char *hostname,
                                                            int port);

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisFd(RdbParser *p,
                                                          RdbxToResp *rdbToResp,
                                                          int fd);

_LIBRDB_API void RDBX_setPipelineDepth(RdbxRespToRedisLoader *r2r, int depth);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
