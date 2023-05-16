#include <sys/time.h>
#include "librdb-api.h"
#ifndef LIBRDB_API_EXT_H
#define LIBRDB_API_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************
* Error codes
****************************************************************/

typedef enum {
    RDBX_ERR_READER_FILE_GENERAL_ERROR = _RDB_ERR_EXTENSION_FIRST,

    /* rdb2json errors */
    RDBX_ERR_R2J_FAILED_OPEN_FILE,
    RDBX_ERR_R2J_INVALID_STATE,

    /* HandlersFilterKey errors */
    RDBX_ERR_R2J_FAILED_COMPILING_REGEX,

} RdbxRes;

/****************************************************************
 * Create File Reader
 ****************************************************************/
typedef struct RdbxReaderFile RdbxReaderFile;

_LIBRDB_API RdbxReaderFile *RDBX_createReaderFile(RdbParser *parser, const char *filename);
_LIBRDB_API RdbReader *RDBX_createReaderSocket(int fd);

/****************************************************************
 * Create RDB to JSON Handlers
 ****************************************************************/
typedef struct RdbxToJson RdbxToJson;

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
typedef struct RdbxFilterKey RdbxFilterKey;

_LIBRDB_API RdbxFilterKey *RDBX_createHandlersFilterKey(RdbParser *p,
                                                        const char *keyRegex,
                                                        uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
