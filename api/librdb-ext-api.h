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
typedef struct RdbxRespWriter RdbxRespWriter;

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

    /* resp writer */
    RDBX_ERR_RESP_WRITE,
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
    /* todo: support the option of expire, del, select db */

    /* If supportRestore, then data-types will be translated to RESTORE with
     * raw data instead of data-types commands. This is a performance, version
     * (specific) aligned, optimization */
    int supportRestore;

    /* relevant only if supportRestore is set. */
    struct {
        /* It is required to verify that the target (consumer) of the RESP payload
         * is aligned with the version of the source RDB file. Otherwise, restore
         * won't be respected */

        /* Configure what is target RDB version. if equals 0, then the value
         * will be resolved by the value of dstRedisVersion. */
        int dstRdbVersion;

        /* an alternative configuration to dstRdbVersion */
        const char *dstRedisVersion;
    } restore;

} RdbxToRespConf;

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *, RdbxToRespConf *);

/****************************************************************
 * Attach RESP writer
 *
 * Create instance for writing RDB to RESP stream.
 *
 * Used by:  RDBX_createRespFileWriter
 *           <user-defined-handlers>
 ****************************************************************/

struct RdbxRespWriter {
    void *ctx;
    size_t (*write)(void *ctx, char *str, int len, int endCmd);
    size_t (*writeBulk)(void *context, RdbBulk bulk, int endCmd);
    void (*delete)(void *ctx);
};

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer);


/****************************************************************
 * Create RESP File Writer
 *
 * If provided path is NULL then write stdout
 ****************************************************************/
_LIBRDB_API RdbxRespFileWriter *RDBX_createRespFileWriter(RdbParser *p,
                                                          RdbxToResp *rdbToResp,
                                                          const char* filepath);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
