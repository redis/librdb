#include <sys/time.h>
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

/****************************************************************
* Error codes
****************************************************************/

typedef enum {
    RDBX_ERR_READER_FILE_GENERAL_ERROR = _RDB_ERR_EXTENSION_FIRST,

    /* rdb2json errors */
    RDBX_ERR_FAILED_OPEN_FILE,
    RDBX_ERR_R2J_INVALID_STATE,

    /* HandlersFilterKey errors */
    RDBX_ERR_FILTER_FAILED_COMPILE_REGEX,

    /* rdb2resp errors */
    RDBX_ERR_RESP_INVALID_CONN_TYPE,
    RDBX_ERR_RESP_FAILED_ALLOC,
    RDBX_ERR_RESP_INIT_CONN_ERROR,
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

_LIBRDB_API RdbxToJson *RDBX_createHandlersToJson(RdbParser *p,
                                                RdbxToJsonEnc encoding,
                                                const char *filename,
                                                RdbHandlersLevel lvl);

/****************************************************************
 * Create Filters extensions
 ****************************************************************/

_LIBRDB_API RdbxFilterKey *RDBX_createHandlersFilterKey(RdbParser *p,
                                                        const char *keyRegex,
                                                        uint32_t flags);

/****************************************************************
 * Create RDB to RESP Handlers
 ****************************************************************/

typedef struct RdbxRespWriter {
    void *ctx;
    size_t (*write)(void *ctx, char *str, int len, int endCmd);
    size_t (*writeBulk)(void *context, RdbBulk bulk, int endCmd);
    void (*delete)(void *ctx);
} RdbxRespWriter;

typedef struct RdbxToRespConfig {
    const char* targetRedisVer;
} RdbxToRespConfig;

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConfig *config);

/* Either Creation of RdbxRespFileWriter will register or create customized one */
_LIBRDB_API void RDB_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer);

/****************************************************************
 * Create RESP writer
 ****************************************************************/

/* if filePath is NULL then STDOUT will be used */
_LIBRDB_API RdbxRespFileWriter *RDBX_createRespFileWriter(RdbParser *p,
                                                          RdbxToResp *rdbToResp,
                                                          const char* filepath);

long RDBX_getRespFileWriterCmdCount(RdbxRespFileWriter *wr);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
