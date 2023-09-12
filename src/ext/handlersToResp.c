#include <string.h>
#include <assert.h>
#include <sys/uio.h>
#include "common.h"
#include "utils.h"

#include "../../deps/redis/crc64.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/endianconv.h"

#define _RDB_TYPE_STRING 0
#define _REDISMODULE_AUX_BEFORE_RDB (1<<0)
#define VER_VAL(major,minor) (((unsigned int)(major)<<8) | (unsigned int)(minor))

typedef struct RedisToRdbVersion {
    unsigned int redis;
    unsigned char rdb;
} RedisToRdbVersion;

const RedisToRdbVersion redisToRdbVersion[] = {
        {VER_VAL(7,2), 11},
        {VER_VAL(7,0), 10},
        {VER_VAL(5,0), 9}, //6 and 6.2 had v9 too
        {VER_VAL(4,0), 8},
        {VER_VAL(3,2), 7},
        {VER_VAL(2,6), 6}, //2.8 had v6 too
        {VER_VAL(2,4), 5},
};

typedef enum DelKeyBeforeWrite {
    DEL_KEY_BEFORE_NONE,
    DEL_KEY_BEFORE_BY_DEL_CMD,
    DEL_KEY_BEFORE_BY_RESTORE_REPLACE, /* RESTORE supported */
} DelKeyBeforeWrite;

#define IOV_CONST(iov, str)       iov_plain(iov, str, sizeof(str)-1)
#define IOV_STRING(iov, str, len) iov_plain(iov, str, len)
#define IOV_VALUE(iov, val, ar)   iov_value(iov, val, ar, sizeof(ar))
#define IOV_LEN_AND_VALUE(iov, val, ar1, ar2) \
   do {\
        int l = IOV_VALUE((iov)+1, val, ar2); \
        IOV_VALUE( (iov), l, ar1); \
   } while (0);

struct RdbxToResp {

    RdbxToRespConf conf;

    /* Init to 3. Attempted to be released three times on termination */
    int refcount;

    RdbParser *parser;
    RdbxRespWriter respWriter;
    int respWriterConfigured;

    unsigned int targetVerValue;  /* major << 8 | minor */

    struct {
        RdbBulkCopy key;
        size_t keyLen;
        RdbKeyInfo info;
        DelKeyBeforeWrite delBeforeWrite;
    } keyCtx;

    struct {
        int sentFirstFrag;
        size_t rawSize;
        int isModuleAux;
        uint64_t crc;
        struct {
            char cmdPrefix[100];
            int cmdlen;
        } moduleAux;
    } rawCtx;

    int srcRdbVer;
};

static void deleteRdbToRespCtx(RdbParser *p, void *context) {
    RdbxToResp *ctx = (RdbxToResp *) context;

    if (!ctx) return;

    /* ignore the first release attempt */
    if (--ctx->refcount) return;

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    /* delete respWriter */
    if (ctx->respWriter.delete)
        ctx->respWriter.delete(ctx->respWriter.ctx);

    RDB_free(p, ctx);
}

static inline void iov_plain(struct iovec *iov, const char *s, size_t l) {
    iov->iov_base = (void *) s;
    iov->iov_len = l;
}

static int iov_value(struct iovec *iov, long long count, char *buf, int bufsize) {
    int len = 0;
    len = ll2string(buf, bufsize, count);

    int lenWithNewLine = len;
    buf[lenWithNewLine++] = '\r';
    buf[lenWithNewLine++] = '\n';

    iov_plain(iov, buf, lenWithNewLine);
    return len;
}

static int rdbVerFromRedisVer(RdbxToResp *ctx) {
    const char *ver = ctx->conf.dstRedisVersion;
    if (!ver) return 0;

    int mjr=0, mnr, pch, pos1 = 0, pos2 = 0;
    int scanned = sscanf(ver, "%d.%d%n.%d%n", &mjr, &mnr, &pos1, &pch, &pos2);
    if ((scanned == 3 && pos2 == (int) strlen(ver)) ||
        (scanned == 2 && pos1 == (int) strlen(ver))) {

        ctx->targetVerValue = VER_VAL(mjr, mnr);
        unsigned int i;
        for (i = 0; i < sizeof(redisToRdbVersion) / sizeof(redisToRdbVersion[0]); i++)
            if (ctx->targetVerValue >= redisToRdbVersion[i].redis) return redisToRdbVersion[i].rdb;
    }
    return 0;
}

static void resolveSupportRestore(RdbParser *p, RdbxToResp *ctx, int srcRdbVer) {
    int dstRdbVer;

    ctx->srcRdbVer = srcRdbVer;

    ctx->keyCtx.delBeforeWrite = (ctx->conf.delKeyBeforeWrite) ? DEL_KEY_BEFORE_BY_DEL_CMD : DEL_KEY_BEFORE_NONE;

    if (ctx->conf.supportRestore) {
        /* if not configured destination RDB version, then resolve it from
         * configured destination Redis version */
        dstRdbVer = rdbVerFromRedisVer(ctx);

        if (dstRdbVer < srcRdbVer) {
            RDB_log(p, RDB_LOG_WRN,
                    "Cannot support RESTORE. source RDB version (=%d) is higher than destination (=%d)",
                    srcRdbVer, dstRdbVer);
            ctx->conf.supportRestore = 0;
        } else {
            if (ctx->conf.delKeyBeforeWrite) {
                RDB_log(p, RDB_LOG_DBG, "Optimizing 'del-key-before-write' into single command of RESTORE-REPLACE.");
                ctx->keyCtx.delBeforeWrite = DEL_KEY_BEFORE_BY_RESTORE_REPLACE;
            }
        }
    }

    RdbHandlersLevel lvl = (ctx->conf.supportRestore) ? RDB_LEVEL_RAW : RDB_LEVEL_DATA;
    for (int i = 0; i < RDB_DATA_TYPE_MAX; ++i) {
        RDB_handleByLevel(p, (RdbDataType) i, lvl, 0);
    }

    /* librdb cannot parse a module object */
    RDB_handleByLevel(p, RDB_DATA_TYPE_MODULE, RDB_LEVEL_RAW, 0);
}

static inline RdbRes writevWrap(RdbxToResp *ctx, struct iovec *iov, int cnt, int startCmd, int endCmd) {
    RdbxRespWriter *writer = &ctx->respWriter;
    if (unlikely(writer->writev(writer->ctx, iov, cnt, startCmd, endCmd))) {
        RdbRes errCode = RDB_getErrorCode(ctx->parser);
        assert(errCode != RDB_OK);
        return RDB_getErrorCode(ctx->parser);
    }

    return RDB_OK;
}

/*** Handling common ***/

static RdbRes toRespNewDb(RdbParser *p, void *userData, int dbid) {
    UNUSED(p);

    struct iovec iov[10];
    char dbidStr[10], cntStr[10];

    RdbxToResp *ctx = userData;

    int cnt = ll2string(dbidStr, sizeof(dbidStr), dbid);

    IOV_CONST(&iov[0], "*2\r\n$6\r\nSELECT\r\n$");
    IOV_VALUE(&iov[1], cnt, cntStr);
    IOV_STRING(&iov[2], dbidStr, cnt);
    IOV_CONST(&iov[3], "\r\n");
    return writevWrap(ctx, iov, 4, 1, 1);
}

static RdbRes toRespStartRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    resolveSupportRestore(p, ctx, rdbVersion);

    return RDB_OK;
}

static RdbRes toRespNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(info);
    RdbxToResp *ctx = userData;

    /* handling new key */
    ctx->keyCtx.info = *info;
    ctx->keyCtx.keyLen = RDB_bulkLen(p, key);
    if ((ctx->keyCtx.key = RDB_bulkClone(p, key)) == NULL)
        return RDB_ERR_FAIL_ALLOC;

    /* apply del-key-before-write if configured, unless it is 'SET' command where
     * the key is overridden if it already exists, without encountering any problems. */
    if ((ctx->keyCtx.delBeforeWrite == DEL_KEY_BEFORE_BY_DEL_CMD) && (info->opcode != _RDB_TYPE_STRING)) {
        struct iovec iov[4];
        char keyLenStr[32];
        IOV_CONST(&iov[0], "*2\r\n$3\r\nDEL\r\n$");
        IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n");
        return writevWrap(ctx, iov, 4, 1, 1);
    }
    return RDB_OK;
}

static RdbRes toRespEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* key is in db. Set its expiration time */
    if (ctx->keyCtx.info.expiretime != -1) {
        struct iovec iov[6];
        char keyLenStr[32], expireLenStr[32], expireStr[32];
        /* PEXPIREAT */
        IOV_CONST(&iov[0], "*3\r\n$9\r\nPEXPIREAT\r\n$");

        /* KEY-LEN and KEY */
        IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n$");
        IOV_LEN_AND_VALUE(iov+4, ctx->keyCtx.info.expiretime, expireLenStr, expireStr);

        return writevWrap(ctx, iov, 6, 1, 1);
    }

    if (ctx->keyCtx.key != NULL)
        RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toRespString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToResp *ctx = userData;

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, string);

    /*** fillup iovec ***/

    struct iovec iov[7];
    /* write SET */
    IOV_CONST(&iov[0], "*3\r\n$3\r\nSET\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write string */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], string, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespList(RdbParser *p, void *userData, RdbBulk item) {
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, item);

    struct iovec iov[7];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$5\r\nRPUSH\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write item */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], item, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[32], fieldLenStr[32], valueLenStr[32];
    int fieldLen = RDB_bulkLen(p, field);
    int valueLen = RDB_bulkLen(p, value);

    struct iovec iov[10];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*4\r\n$4\r\nHSET\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write field */
    IOV_VALUE(&iov[4], fieldLen, fieldLenStr);
    IOV_STRING(&iov[5], field, fieldLen);
    IOV_CONST(&iov[6], "\r\n$");
    /* write value */
    IOV_VALUE(&iov[7], valueLen, valueLenStr);
    IOV_STRING(&iov[8], value, valueLen);
    IOV_CONST(&iov[9], "\r\n");
    return writevWrap(ctx, iov, sizeof(iov)/sizeof(iov[0]), 1, 1);
}

static RdbRes toRespSet(RdbParser *p, void *userData, RdbBulk member) {
    RdbxToResp *ctx = userData;
    char keyLenStr[32], valLenStr[32];

    int valLen = RDB_bulkLen(p, member);

    struct iovec iov[7];
    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$4\r\nSADD\r\n$");
    /* write key */
    IOV_VALUE(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    IOV_CONST(&iov[3], "\r\n$");
    /* write member */
    IOV_VALUE(&iov[4], valLen, valLenStr);
    IOV_STRING(&iov[5], member, valLen);
    IOV_CONST(&iov[6], "\r\n");
    return writevWrap(ctx, iov, 7, 1, 1);
}

static RdbRes toRespEndRdb(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    RdbxRespWriter *writer = &ctx->respWriter;
    if (likely(writer->flush(writer->ctx) == 0))
        return RDB_OK;

    if (RDB_getErrorCode(p) != RDB_OK)
        return RDB_getErrorCode(p);

    /* writer didn't take care to report an error */
    RDB_log(p, RDB_LOG_WRN, "Writer returned error indication but didn't RDB_reportError()");
    RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_WRITE, "RESP writer returned error on flush()");
    return (RdbRes) RDBX_ERR_RESP_WRITE;
}

static RdbRes toRespFunction(RdbParser *p, void *userData, RdbBulk func) {
    char funcLenStr[32];

    int funcLen = RDB_bulkLen(p, func);

    struct iovec iov[4];
    IOV_CONST(&iov[0], "*4\r\n$8\r\nFUNCTION\r\n$4\r\nLOAD\r\n$7\r\nREPLACE\r\n$");
    /* write member */
    IOV_VALUE(&iov[1], funcLen, funcLenStr);
    IOV_STRING(&iov[2], func, funcLen);
    IOV_CONST(&iov[3], "\r\n");
    return writevWrap( (RdbxToResp *) userData, iov, 4, 1, 1);

}

/*** Handling raw ***/
/* Callback on start of serializing module aux data (alternative to toRespRawBegin).
 * Following this call, one or more calls will be made to toRespRawFrag() to
 * stream fragments of the serialized data. And at the end toRespRawFragEnd()
 * will be called */
static RdbRes toRespRawBeginModuleAux(RdbParser *p, void *userData, RdbBulk name, int encver, int when, size_t rawSize) {
    char encstr[10];
    UNUSED(p);

    /* reset rawCtx */
    RdbxToResp *ctx = userData;
    ctx->rawCtx.rawSize = rawSize;
    ctx->rawCtx.sentFirstFrag = 0;
    ctx->rawCtx.isModuleAux = 1;
    ctx->rawCtx.crc = 0;

    /* if target doesn't support module-aux, then skip it */
    if (!ctx->conf.supportRestoreModuleAux)
        return RDB_OK;

    /* Build the cmd instead of keeping the values and build it later */
    size_t enclen = snprintf(encstr, sizeof(encstr), "%d", encver);
    const char* whenstr = (when==_REDISMODULE_AUX_BEFORE_RDB) ? "before" :"after";
    ctx->rawCtx.moduleAux.cmdlen = snprintf(ctx->rawCtx.moduleAux.cmdPrefix,
            sizeof(ctx->rawCtx.moduleAux.cmdPrefix),
            "*5\r\n$13\r\nRESTOREMODAUX\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n$",
            strlen(name), name, enclen, encstr, strlen(whenstr), whenstr);
    return RDB_OK;
}

/* Callback on start of serializing value of a key. Following this call, one
 * or more calls will be made to toRespRawFrag() to stream fragments of the
 * serialized data. And at the end toRespRawFragEnd() will be called */
static RdbRes toRespRawBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* reset rawCtx */
    ctx->rawCtx.rawSize = size;
    ctx->rawCtx.sentFirstFrag = 0;
    ctx->rawCtx.isModuleAux = 0;
    ctx->rawCtx.crc = 0;
    return RDB_OK;
}

static inline RdbRes sendFirstRawFrag(RdbxToResp *ctx, RdbBulk frag, size_t fragLen) {
    long long expireTime = 0;
    char expireTimeStr[32], expireTimeLenStr[32], keyLenStr[32], lenStr[32];
    struct iovec iov[10];
    int extra_args = 0, iovs = 0;

    /* this logic must be exactly the same as in toRespRawFragEnd() */
    if (ctx->targetVerValue >= VER_VAL(5,0))
    {
        if (ctx->keyCtx.info.expiretime != -1) {
            expireTime = ctx->keyCtx.info.expiretime;
            extra_args++; /* ABSTTL */
        }

        if ((ctx->keyCtx.info.lfuFreq != -1) || (ctx->keyCtx.info.lruIdle != -1)) {
            extra_args += 2;
        }
    }

    if (ctx->keyCtx.delBeforeWrite == DEL_KEY_BEFORE_BY_RESTORE_REPLACE)
        extra_args++;

    char cmd[64];

    int len = snprintf(cmd, sizeof(cmd), "*%d\r\n$7\r\nRESTORE\r\n$", 4+extra_args);

    IOV_STRING(&iov[iovs++], cmd, len);                             /* RESTORE */
    IOV_VALUE(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);         /* write key len */
    IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);  /* write key */

    if (expireTime) {
        IOV_CONST(&iov[iovs++], "\r\n$");
        IOV_LEN_AND_VALUE(&iov[iovs], expireTime, expireTimeLenStr, expireTimeStr);
        iovs += 2;
        IOV_CONST(&iov[iovs++], "$");
    } else {
        IOV_CONST(&iov[iovs++], "\r\n$1\r\n0\r\n$");
    }
    IOV_VALUE(&iov[iovs++], ctx->rawCtx.rawSize + 10, lenStr); /* write raw len + trailer */
    IOV_STRING(&iov[iovs++], frag, fragLen);                   /* write first frag */
    return writevWrap(ctx, iov, iovs, 1, 0);
}

static inline RdbRes sendFirstRawFragModuleAux(RdbxToResp *ctx, RdbBulk frag, size_t fragLen) {
    struct iovec iov[3];
    char lenStr[32];
    iov[0].iov_base = ctx->rawCtx.moduleAux.cmdPrefix;
    iov[0].iov_len =  ctx->rawCtx.moduleAux.cmdlen;
    IOV_VALUE(&iov[1], ctx->rawCtx.rawSize + 10, lenStr); /* write raw len + trailer */
    IOV_STRING(&iov[2], frag, fragLen);                   /* write first frag */
    return writevWrap(ctx, iov, 3, 1, 0);
}

/* Callback for fragments of a serialized value associated with a new key or module
 * auxiliary data. This callback is invoked after toRespRawBegin() or
 * toRespRawBeginModuleAux(), and it may be called multiple times until the
 * serialization is complete. Finally, toRespRawFragEnd() will be called to signal
 * the registered handlers for the completion of the operation. */
static RdbRes toRespRawFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    struct iovec iov[10];
    int iovs = 0;

    /* if processing module-aux but target doesn't support, then skip it */
    if ( (ctx->rawCtx.isModuleAux) && (!ctx->conf.supportRestoreModuleAux))
        return RDB_OK;

    size_t fragLen = RDB_bulkLen(p, frag);
    ctx->rawCtx.crc = crc64(ctx->rawCtx.crc, (unsigned char *) frag , fragLen);

    /* if first frag, handled differently */
    if (likely(!(ctx->rawCtx.sentFirstFrag))) {
        ctx->rawCtx.sentFirstFrag = 1;
        if (ctx->rawCtx.isModuleAux)
            return sendFirstRawFragModuleAux(ctx, frag, fragLen);
        else
            return sendFirstRawFrag(ctx, frag, fragLen);
    }

    IOV_STRING(&iov[iovs++], frag, fragLen);
    return writevWrap(ctx, iov, iovs, 1, 0);
}

/* This call will be followed one or more calls to toRespRawFrag() which indicates
 * for completion of streaming of fragments of serialized value of a new key or
 * module-aux data. */
RdbRes toRespRawFragEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    char cmd[1024]; /* degenerate usage of iov. All copied strings are small */
    RdbxToResp *ctx = userData;
    uint64_t *crc = &(ctx->rawCtx.crc);

    /* if processing module-aux but target doesn't support, then skip it */
    if ( (ctx->rawCtx.isModuleAux) && (!ctx->conf.supportRestoreModuleAux))
        return RDB_OK;

    /* Add RDB version 2 bytes */
    cmd[0] = ctx->srcRdbVer & 0xff;
    cmd[1] = (ctx->srcRdbVer >> 8) & 0xff;

    /* Add CRC64 8 bytes */
    *crc = crc64(*crc, (unsigned char *) cmd, 2);
    memrev64ifbe(crc);
    memcpy(cmd + 2, crc, 8);

    int len = 10;

    /* Add REPLACE if needed */
    if (ctx->keyCtx.delBeforeWrite == DEL_KEY_BEFORE_BY_RESTORE_REPLACE)
        len += snprintf(cmd+len, sizeof(cmd)-len, "\r\n$7\r\nREPLACE\r\n");
    else
        len += snprintf(cmd+len, sizeof(cmd)-len, "\r\n");

    /* This logic must be exactly the same as in toRespRawFrag() */
    if (likely(ctx->targetVerValue >= VER_VAL(5,0))) {

        /* Add ABSTTL */
        if (ctx->keyCtx.info.expiretime != -1) {
            len += snprintf(cmd+len, sizeof(cmd)-len, "$6\r\nABSTTL\r\n");
            ctx->keyCtx.info.expiretime = -1; /* take care reset before reach toRespEndKey() */
        }

        /* Add IDLETIME or FREQ if needed */
        if (ctx->keyCtx.info.lruIdle != -1) {
            char buf[128];
            int l = snprintf(buf, sizeof(buf), "%lld", ctx->keyCtx.info.lruIdle);
            len += snprintf(cmd+len, sizeof(cmd)-len, "$8\r\nIDLETIME\r\n$%d\r\n%s\r\n", l, buf);
        } else if (ctx->keyCtx.info.lfuFreq != -1) {
            char buf[128];
            int l = snprintf(buf, sizeof(buf), "%d", ctx->keyCtx.info.lfuFreq);
            len += snprintf(cmd+len, sizeof(cmd)-len, "$4\r\nFREQ\r\n$%d\r\n%s\r\n", l, buf);
        }
    }

    struct iovec iov = {cmd, len};
    return writevWrap(ctx, &iov, 1, 0, 1);
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConf *conf) {
    RdbxToResp *ctx;

    /* Verify table up-to-date and aligned */
    assert(redisToRdbVersion[0].rdb == MAX_RDB_VER_SUPPORT);

    if ((ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset(ctx, 0, sizeof(RdbxToResp));
    if (conf) ctx->conf = *conf;
    ctx->parser = p;
    ctx->refcount = 2;

    RdbHandlersDataCallbacks dataCb;
    memset(&dataCb, 0, sizeof(RdbHandlersDataCallbacks));
    dataCb.handleStartRdb = toRespStartRdb;
    dataCb.handleNewDb = toRespNewDb;
    dataCb.handleNewKey = toRespNewKey;
    dataCb.handleEndKey = toRespEndKey;
    dataCb.handleStringValue = toRespString;
    dataCb.handleListItem = toRespList;
    dataCb.handleHashField = toRespHash;
    dataCb.handleSetMember = toRespSet;
    dataCb.handleEndRdb = toRespEndRdb;
    dataCb.handleFunction = toRespFunction;
    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToRespCtx);

    RdbHandlersRawCallbacks rawCb;
    memset(&rawCb, 0, sizeof(RdbHandlersRawCallbacks));
    rawCb.handleStartRdb = NULL; /* already registered to this common callback */
    rawCb.handleNewKey = toRespNewKey;
    rawCb.handleEndKey = toRespEndKey;
    rawCb.handleFrag = toRespRawFrag;
    rawCb.handleBeginModuleAux = toRespRawBeginModuleAux;
    rawCb.handleBegin = toRespRawBegin;
    rawCb.handleEnd = toRespRawFragEnd;
    RDB_createHandlersRaw(p, &rawCb, ctx, deleteRdbToRespCtx);

    return ctx;
}

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer) {
    assert (rdbToResp->respWriterConfigured == 0);
    rdbToResp->respWriter = *writer;
    rdbToResp->respWriterConfigured = 1;
}
