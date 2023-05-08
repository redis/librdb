#include "librdb-api.h"
#ifndef LIBRDB_API_EXT_H
#define LIBRDB_API_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************
* Enums & Typedefs
****************************************************************/

typedef enum {
    RDBX_CONV_JSON_ENC_PLAIN,
    RDBX_CONV_JSON_ENC_BASE64
} RdbxConvJsonEnc;

typedef enum {
    RDBX_ERR_READER_FILE_GENERAL_ERROR = _RDB_ERR_EXTENSION_FIRST,

    /* rdb2json errors */
    RDBX_ERR_R2J_FAILED_OPEN_FILE,
    RDBX_ERR_R2J_INVALID_STATE,

    /* HandlersFilterKey errors */
    RDBX_ERR_R2J_FAILED_COMPILING_REGEX,

} RdbxRes;

/****************************************************************
 * Create Reader extensions
 ****************************************************************/

_LIBRDB_API RdbReader *RDBX_createReaderFile(RdbParser *parser, const char *filename);
_LIBRDB_API RdbReader *RDBX_createReaderSocket(int fd);

/****************************************************************
 * Create Handlers extensions
 ****************************************************************/

_LIBRDB_API RdbHandlers *RDBX_createHandlersRdb2Json(RdbParser *p,
                                                       RdbxConvJsonEnc encoding,
                                                       const char *filename,
                                                       RdbHandlersLevel lvl);

/****************************************************************
 * Create Filters extensions
 ****************************************************************/

_LIBRDB_API RdbHandlers *RDBX_createHandlersFilterKey(RdbParser *p,
                                                        const char *keyRegex,
                                                        uint32_t flags,
                                                        RdbHandlersLevel level);

#ifdef __cplusplus
}
#endif

#endif //LIBRDB_API_EXT_H
