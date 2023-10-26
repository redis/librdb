#include <sys/time.h>
#include <sys/uio.h>
#include "librdb-api.h"
#ifndef LIBRDB_API_EXT_H
#define LIBRDB_API_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Incomplete structures */
typedef struct RdbxRespToFileWriter RdbxRespToFileWriter;
typedef struct RdbxReaderFile RdbxReaderFile;
typedef struct RdbxReaderFileDesc RdbxReaderFileDesc;
typedef struct RdbxFilter RdbxFilter;
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
    RDBX_ERR_R2J_INVALID_LEVEL,

    /* HandlersFilterKey errors */
    RDBX_ERR_FILTER_FAILED_COMPILE_REGEX,
    RDBX_ERR_FAILED_CREATE_FILTER,

    /* rdb2resp errors */
    RDBX_ERR_STREAM_DUPLICATE_PEL,
    RDBX_ERR_STREAM_INTEG_CHECK,

    /* resp writer/loader */
    RDBX_ERR_RESP_WRITE,
    RDBX_ERR_RESP_INVALID_TARGET_VERSION,
    RDBX_ERR_RESP_READ,
    RDBX_ERR_RESP2REDIS_CREATE_SOCKET,
    RDBX_ERR_RESP2REDIS_CONF_NONBLOCK_SOCKET,
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
    RdbHandlersLevel level;  /* Parsing depth (raw, structures or data-types) */
    RdbxToJsonEnc encoding;  /* Encoding format for the resulting JSON */
    int includeAuxField;     /* Set to include auxiliary fields in JSON output */
    int includeFunc;         /* Set to include functions in JSON output */
    int includeStreamMeta;   /* Set to include Stream metadata in JSON output */
    int flatten;             /* Set to create a flattened JSON structure */
} RdbxToJsonConf;

_LIBRDB_API RdbxToJson *RDBX_createHandlersToJson(RdbParser *p,
                                                  const char *filename,
                                                  RdbxToJsonConf *c);

/****************************************************************
 * Create Filter Handlers
 ****************************************************************/

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterKey(RdbParser *p,
                                                        const char *keyRegex,
                                                        uint32_t exclude);

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterType(RdbParser *p,
                                                      RdbDataType type,
                                                      uint32_t exclude);

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterDbNum(RdbParser *p,
                                                       int dbnum,
                                                       uint32_t exclude);

/****************************************************************
 * Create RDB to RESP Handlers
 *
 * The RDB to RESP handlers (RdbxToResp) provide a way to generate a stream of
 * redis protocol commands. The output of if it will be consumed
 * by an instance of type RESP writer (RdbxRespWriter. Explained below).
 ****************************************************************/

typedef struct RdbxToRespConf {
    /* delKeyBeforeWrite - will add preceding DEL command before each new key. If
     * the keys are created with RESTORE commands, then instead of sending another
     * DEL command, it will be optimized by attaching `REPLACE` flag to the
     * RESTORE command. */
    int delKeyBeforeWrite;

    /* If supportRestore, then data-types will be translated to RESTORE with
     * raw data instead of data-types commands. This is a performance optimization
     * that requires to be version aligned. */
    int supportRestore;

    /* dstRedisVersion - Helps the parser to determine which commands and flags
     * can be safely applied to the Redis target. It is recommended to configure
     * this version whenever it is known. This becomes particularly crucial when
     * setting the 'supportRestore' flag, as data serialization is closely tied
     * to specific RDB versions. If the source RDB version isn't align with the
     * target version, the parser will generate higher-level commands as a
     * workaround. */
     const char *dstRedisVersion; /* "<major>.<minor>[.<patch>]" */

    /* Redis OSS does not support restoring module auxiliary data. This feature
     * is currently available only in Redis Enterprise. There are plans to bring
     * this functionality to Redis OSS in the near future. */
     int supportRestoreModuleAux;

} RdbxToRespConf;

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *, RdbxToRespConf *);

/****************************************************************
 * RESP writer
 *
 * Interface to create writer instance for RDB to RESP stream.
 *
 * Imp by:   RDBX_createRespToRedisTcp
 *           RDBX_createRespToRedisFd
 *           RDBX_createRespToFileWriter
 *           <user-defined-writer>
 ****************************************************************/

/* On start command pass command info. NULL otherwise.  */
typedef struct RdbxRespWriterStartCmd {
    /* Redis Command name (Ex: "SET", "RESTORE"). Owned by the caller. It is
     * constant static string and Valid for ref behind the duration of the call. */
    const char *cmd;
    /* If key available as part of command. Else empty string.
     * Owned by the caller. */
    const char *key;
} RdbxRespWriterStartCmd;

typedef struct RdbxRespWriter {
    void *ctx;
    void (*delete)(void *ctx);

    /* return 0 on success. Otherwise 1 */
    int (*writev) (void *ctx,
                   struct iovec *ioVec,              /* Standard C scatter/gather IO array */
                   int iovCnt,                       /* Number of iovec elements */
                   RdbxRespWriterStartCmd *startCmd, /* If start of RESP command then not NULL. Owned by
                                                      * the caller. Valid for the duration of the call. */
                   int endCmd);                      /* 1, if this is end of RESP command, 0 otherwise */

    int (*flush) (void *ctx);
} RdbxRespWriter;

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer);


/****************************************************************
 * Create RESP to File Writer
 *
 * If provided path is NULL then write to stdout
 ****************************************************************/
_LIBRDB_API RdbxRespToFileWriter *RDBX_createRespToFileWriter(RdbParser *p,
                                                          RdbxToResp *rdbToResp,
                                                          const char* filepath);

/****************************************************************
 * Create RESP to Redis TCP/FD connection
 *
 * Can configure pipeline depth of transmitted RESP commands. Set
 * to 0 to use default.
 ****************************************************************/
typedef struct RdbxRedisAuth {
    const char *pwd;
    const char *user;

    /* alternative auth-cmd. Args must remain valid throughout the parser's lifetime. */
    struct {
        int argc;
        char **argv;
    } cmd;
} RdbxRedisAuth;

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                             RdbxToResp *rdbToResp,
                                                             RdbxRedisAuth *auth, /*opt*/
                                                             const char *hostname,
                                                             int port);

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisFd(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            RdbxRedisAuth *auth, /*opt*/
                                                            int fd);

_LIBRDB_API void RDBX_setPipelineDepth(RdbxRespToRedisLoader *r2r, int depth);

/****************************************************************
 * Debugging RESP to Redis
 *
 * This section provides debugging assistance for analyzing Redis server failures
 * when attempting to stream multiple RESP commands. This analysis can be particularly
 * challenging in the following scenarios:
 *
 * - When using pipeline mode, which involves multiple concurrent pending commands
 *   at any given moment.
 * - When not using the `delKeyBeforeWrite` flag and Redis server is not empty.
 * - In a production environments with real-world loads.
 *
 * The following two debug functions are designed to help with the analysis of a given
 * RDB file:
 *
 * RDBX_enumerateCmds
 *   Enumerates commands by preceding any RESP command with an additional trivial
 *   RESP command of the type 'echo <cmd-number>'. This can be especially useful since
 *   the RESP-to-Redis instance prints the command number in case of a failure.
 *
 * RDBX_writeFromCmdNumber
 *   Writing commands starting from specified command-number and onward as part
 *   of reproducing effort. Once the problem was resolved, it might be also useful
 *   to continue uploading the redis server from the point it got failed.
 ****************************************************************/
_LIBRDB_API void RDBX_enumerateCmds(RdbxToResp *rdbToResp);

_LIBRDB_API void RDBX_writeFromCmdNumber(RdbxToResp *rdbToResp, size_t cmdNum);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
