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
typedef struct RdbxToPrint RdbxToPrint;
typedef struct RdbxRespToRedisLoader RdbxRespToRedisLoader;

/****************************************************************
* Error codes
****************************************************************/

typedef enum {
    RDBX_ERR_READER_FILE_GENERAL_ERROR = _RDB_ERR_EXTENSION_FIRST,
    RDBX_ERR_RESP_FAILED_ALLOC,

    /* rdb2json errors */
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
    RDBX_ERR_RESP2REDIS_CONF_SOCKET,
    RDBX_ERR_RESP2REDIS_INVALID_ADDRESS,
    RDBX_ERR_RESP2REDIS_FAILED_CONNECT,
    RDBX_ERR_RESP2REDIS_FAILED_READ,
    RDBX_ERR_RESP2REDIS_FAILED_WRITE,
    RDBX_ERR_RESP2REDIS_CONN_CLOSE,
    RDBX_ERR_RESP2REDIS_MAX_RETRIES,
    RDBX_ERR_RESP2REDIS_SET_TIMEOUT,
    RDBX_ERR_RESP2REDIS_AUTH_FAILED,

    /* SSL/TLS errors */
    RDBX_ERR_SSL_INIT_FAILED,
    RDBX_ERR_SSL_CTX_CREATE_FAILED,
    RDBX_ERR_SSL_CERT_LOAD_FAILED,
    RDBX_ERR_SSL_KEY_LOAD_FAILED,
    RDBX_ERR_SSL_CA_LOAD_FAILED,
    RDBX_ERR_SSL_HANDSHAKE_FAILED,
    RDBX_ERR_SSL_CONNECTION_FAILED,    
} RdbxRes;

/****************************************************************
 * Create RDB Reader
 *
 * Creation of RDB reader based on filename or file-descriptor
 *
 * Note: File-descriptor must be set to blocking mode.
 *
 * TODO: The parser only supports reading asynchronously (non-blocking)
 *       through RDB_parseBuff() API. It is required to Extend parser for
 *       readers to support non-blocking mode as well.
 ****************************************************************/

_LIBRDB_API RdbxReaderFile *RDBX_createReaderFile(RdbParser *parser, const char *filename);

_LIBRDB_API RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int fdCloseWhenDone);

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

    /* Additional metadata to include in json output */
    int includeDbInfo;       /* Set to include DB and SLOT info in JSON output */
    int includeAuxField;     /* Set to include auxiliary fields in JSON output */
    int includeFunc;         /* Set to include functions in JSON output */
    int includeStreamMeta;   /* Set to include Stream metadata in JSON output */
    int includeStreamIdmp;   /* Set to include Stream IDMP data in JSON output */

    int flatten;             /* Set to create a flattened JSON structure */
} RdbxToJsonConf;

_LIBRDB_API RdbxToJson *RDBX_createHandlersToJson(RdbParser *p,
                                                  const char *filename,
                                                  RdbxToJsonConf *c);

/****************************************************************
 * Create PRINT Handlers
 *
 * auxFmt - Format string for auxiliary values, where:
 *          %f = Auxiliary field name
 *          %v = Auxiliary field value
 * keyFmt - Format string for key details, where:
 *          %d = Database number
 *          %k = Key
 *          %v = Value (If the value is a string, it will be printed as escaped string)
 *          %t = Type
 *          %e = Expiry
 *          %r = LRU
 *          %f = LFU
 *          %i = Items
 *
 ****************************************************************/
_LIBRDB_API RdbxToPrint *RDBX_createHandlersToPrint(RdbParser *p,
                                                    const char *auxFmt,
                                                    const char *keyFmt,
                                                    const char *outFilename);

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

_LIBRDB_API RdbxFilter *RDBX_createHandlersFilterExpired(RdbParser *p,
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

    /* funcLibReplaceIfExist - If function-library with the same name is already
     * exist in the target redis, then replace it rather than return failure.
     * (Implemented in RESP by adding `REPLACE` flag to the `FUNCTION LOAD`
     * command) */
    int funcLibReplaceIfExist;

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

    /* Single DB mode. i.e., avoid using the SELECT command. In turn all keys and
     * data in the RDB will be stored in the default DB (index 0).
     *
     * This approach can be helpful when dealing with scenarios such as data
     * partitioned into multiple DBs where you need to merge them into a single DB.
     * Be cautious of potential key conflicts in such case. */
     int singleDb;

    /* Option to load Lua scripts from RDB auxiliary fields. If aux-field is "lua" 
     * then its aux-value is being SCRIPT LOAD (Compatible with Redis Ent. RDB 
     * files that can store scripts in the auxiliary section). */
     int scriptsInAux;

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

/* As streaming RESP protocol, when starting a new command, provide details
 * about the command. Otherwise, pass NULL. This information will be used to log
 * and report the command in case of a failure from Redis server. */
typedef struct RdbxRespWriterStartCmd {
    /* Redis Command name (Ex: "SET", "RESTORE"). Owned by the caller. It is
     * constant static string and Valid for ref behind the duration of the call. */
    const char *cmd;

    /* If key available as part of command. Else empty string.
     * Owned by the caller. */
    const char *key;

    /* On restore command, size of serialized data. Otherwise, set to 0. */
    size_t restoreSize;

} RdbxRespWriterStartCmd;

typedef struct RdbxRespWriter {
    void *ctx;
    void (*destroy)(void *ctx);

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

/****************************************************************
 * SSL/TLS Configuration for Redis connections
 ****************************************************************/

/**
 * SSL/TLS Configuration structure
 *
 * Used to configure SSL/TLS connections to Redis instances.
 * All fields are optional and can be NULL/0 for default behavior.
 */
typedef struct RdbxSSLConfig {
    /* Path to CA certificate file or bundle for server verification.
     * If NULL, system default CA certificates will be used. */
    const char *cacert_filename;

    /* Path to directory containing CA certificates.
     * Alternative to cacert_filename for systems using CA directories. */
    const char *capath;

    /* Path to client certificate file (for mutual TLS authentication).
     * Required only if Redis server requires client certificates. */
    const char *cert_filename;

    /* Path to client private key file (for mutual TLS authentication).
     * Required if cert_filename is provided. */
    const char *private_key_filename;

    /* Server Name Indication (SNI) - hostname for TLS handshake.
     * If NULL, the hostname parameter from RDBX_createRespToRedisTcp will be used.
     * Set this if connecting via IP but need specific hostname for certificate validation. */
    const char *server_name;

    /* List of preferred ciphers (TLSv1.2 and below) in order of preference.
     * Format: colon-separated list (e.g., "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
     * If NULL, OpenSSL default cipher list will be used.
     * See ciphers(1ssl) manpage for syntax details. */
    const char *ciphers;

    /* List of preferred ciphersuites (TLSv1.3) in order of preference.
     * Format: colon-separated list (e.g., "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")
     * If NULL, OpenSSL default ciphersuites will be used.
     * Only available when compiled with TLSv1.3 support.
     * See ciphers(1ssl) manpage for TLSv1.3 ciphersuite syntax. */
    const char *ciphersuites;

/* SSL verification modes for client connections */
#define RDBX_SSL_VERIFY_NONE    0x00  /* Don't verify server certificate (insecure) */
#define RDBX_SSL_VERIFY_PEER    0x01  /* Verify server certificate (recommended) */
    int verify_mode;
} RdbxSSLConfig;

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                             RdbxToResp *rdbToResp,
                                                             RdbxRedisAuth *auth, /*opt*/
                                                             const char *hostname,
                                                             int port,
                                                             RdbxSSLConfig *sslConfig /*opt*/);

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
