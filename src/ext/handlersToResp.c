#include <string.h>
#include <assert.h>
#include <sys/uio.h>
#include "common.h"

#include "../../deps/redis/crc64.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/endianconv.h"
#include "../../deps/redis/rax.h"

/* RDB opcode defines */
#define _RDB_TYPE_MODULE_2 7
#define _RDB_TYPE_STRING 0
#define _RDB_TYPE_STREAM_LISTPACKS_2 19
#define _REDISMODULE_AUX_BEFORE_RDB (1<<0)

#define VER_VAL(major,minor) (((unsigned int)(major)<<8) | (unsigned int)(minor))

#define KEY_CMD_ID_DBG  "_RDB_CLI_CMD_ID_"

typedef struct RedisToRdbVersion {
    const char *redisStr;
    unsigned int redis;
    unsigned char rdb;
} RedisToRdbVersion;

const RedisToRdbVersion redisToRdbVersion[] = {
        {"99.99", VER_VAL(99,99), 12}, // TODO: Update released version
        {"7.2", VER_VAL(7,2), 11},
        {"7.0", VER_VAL(7,0), 10},
        {"5.0", VER_VAL(5,0), 9}, //6 and 6.2 had v9 too
        {"4.0", VER_VAL(4,0), 8},
        {"3.2", VER_VAL(3,2), 7},
        {"2.6", VER_VAL(2,6), 6}, //2.8 had v6 too
        {"2.4", VER_VAL(2,4), 5},
};

typedef enum DelKeyBeforeWrite {
    DEL_KEY_BEFORE_NONE,
    DEL_KEY_BEFORE_BY_DEL_CMD,
    DEL_KEY_BEFORE_BY_RESTORE_REPLACE, /* RESTORE supported */
} DelKeyBeforeWrite;

struct RdbxToResp {

    RdbxToRespConf conf;

    struct RdbxToRespDebug {

        size_t cmdNum;

        /* configuration */
#define RFLAG_WRITE_FROM_CMD_ID (1<<0)  /* Flag for writing commands from a specific command-id */
#define RFLAG_ENUM_CMD_ID       (1<<1)  /* Enumerate and trace commands by pushing debug command
                                         * of type "SET _RDB_CLI_CMD_ID_ <CMD-ID>" before each
                                         * RESP command */
        int flags;
        size_t writeFromCmdNum;
    } debug;

    int refcount; /* intrusive refcount - Init to 2. Attempted to be released two times on termination */

    RdbParser *parser;
    RdbxRespWriter respWriter;
    int respWriterConfigured;

    unsigned int targetRedisVerVal;  /* major << 8 | minor */

    struct {
        RdbBulkCopy key;
        size_t keyLen;
        RdbKeyInfo info;
        DelKeyBeforeWrite delBeforeWrite;
    } keyCtx;

    struct {
        int sentFirstFrag;
        size_t restoreSize;
        int isModuleAux;
        uint64_t crc;
        struct {
            char cmdPrefix[128];
            int cmdlen;
        } moduleAux;
    } restoreCtx;

    int srcRdbVer;
    int dstRdbVer;

    struct {
        /* +1 on start of XADD. Another +1 on end of XADD. Reset by toRespStreamMetaData() */
        long long xaddStartEndCounter;

        /* The radix tree representing pending entries for a consumer group is rebuilt
         * each time a new consumer group is visited (The tree is used exclusively
         * to map consumer IDs within this group to their respective  associated
         * delivery times, which are necessary for reconstructing XCLAIM commands). */
        rax *groupPel;

        RdbBulkCopy grpName, consName;
        int grpNameLen, consNameLen;

    } streamCtx;
};

static void deletePendingEntriesList(RdbParser *p, rax **pel) {
    /* Free all entries in the Rax tree */
    raxIterator ri_cons;
    raxStart(&ri_cons,*pel);
    raxSeek(&ri_cons,"^",NULL,0);
    while(raxNext(&ri_cons)) {
        RdbStreamPendingEntry *entry = ri_cons.data;
        RDB_free(p, entry);
    }
    /* Free the entire Rax tree */
    raxFree(*pel);
    *pel = NULL;
}

static void deleteRdbToRespCtx(RdbParser *p, void *context) {
    RdbxToResp *ctx = (RdbxToResp *) context;

    if (!ctx) return;

    /* ignore the first release attempt */
    if (--ctx->refcount) return;

    RDB_bulkCopyFree(p, ctx->streamCtx.grpName);

    if(ctx->streamCtx.groupPel)
        deletePendingEntriesList(p, &ctx->streamCtx.groupPel);

    RDB_bulkCopyFree(p, ctx->keyCtx.key);

    RDB_bulkCopyFree(p, ctx->streamCtx.consName);

    /* delete respWriter */
    if (ctx->respWriter.delete)
        ctx->respWriter.delete(ctx->respWriter.ctx);

    RDB_free(p, ctx);
}

static int setRdbVerFromDestRedisVer(RdbxToResp *ctx) {

    const char *ver = ctx->conf.dstRedisVersion;
    if (!ver) {
        RDB_log(ctx->parser, RDB_LOG_WRN, "Target Redis version is not configured! "
                                          "Set it to Redis version: %s", redisToRdbVersion[0].redisStr);

        ctx->targetRedisVerVal = redisToRdbVersion[0].redis;
        return redisToRdbVersion[0].rdb;
    }

    int mjr = 0, mnr, pch, pos1 = 0, pos2 = 0;
    int scanned = sscanf(ver, "%d.%d%n.%d%n", &mjr, &mnr, &pos1, &pch, &pos2);
    if ((scanned == 3 && pos2 == (int) strlen(ver)) ||
        (scanned == 2 && pos1 == (int) strlen(ver))) {

        ctx->targetRedisVerVal = VER_VAL(mjr, mnr);
        unsigned int i;
        for (i = 0; i < sizeof(redisToRdbVersion) / sizeof(redisToRdbVersion[0]); i++)
            if (ctx->targetRedisVerVal >= redisToRdbVersion[i].redis) {
                return redisToRdbVersion[i].rdb;
            }
    }
    RDB_log(ctx->parser, RDB_LOG_WRN, "Configured Obsolete or invalid target version [%s]. Earliest is [2.4]", ver);
    return 0;
}

/*
 * This function Resolves whether the parser can support RESTORE commands. That is, if
 * requested via configuration to support RESTORE, yet it is required to verify that
 * source version of RDB file is aligned with destination version of the Redis
 * target. If not, then RESTORE configuration won't be honored.
 */
static RdbRes resolveSupportRestore(RdbParser *p, RdbxToResp *ctx) {

    ctx->keyCtx.delBeforeWrite = (ctx->conf.delKeyBeforeWrite) ? DEL_KEY_BEFORE_BY_DEL_CMD : DEL_KEY_BEFORE_NONE;
    if (ctx->conf.supportRestore) {

        if (ctx->dstRdbVer < ctx->srcRdbVer) {
            RDB_log(p, RDB_LOG_WRN,
                    "Cannot support RESTORE. source RDB version (=%d) is higher than destination (=%d)",
                    ctx->srcRdbVer, ctx->dstRdbVer);
            ctx->conf.supportRestore = 0;
        } else {
            if (ctx->conf.delKeyBeforeWrite) {
                RDB_log(p, RDB_LOG_DBG, "Optimizing 'del-key-before-write' into single command of RESTORE-REPLACE.");
                ctx->keyCtx.delBeforeWrite = DEL_KEY_BEFORE_BY_RESTORE_REPLACE;
            }
        }
    }

    /* Now that it is being decided whether to use RESTORE or not, configure accordingly
     * parsing level of the parser */
    RdbHandlersLevel lvl = (ctx->conf.supportRestore) ? RDB_LEVEL_RAW : RDB_LEVEL_DATA;
    for (int i = 0; i < RDB_DATA_TYPE_MAX; ++i) {
        /* No need to check return value of RDB_handleByLevel() since it is
         * guaranteed to succeed */
        RDB_handleByLevel(p, (RdbDataType) i, lvl);
    }

    /* Enforce RESTORE for modules. librdb cannot really parse high-level module object */
    RDB_handleByLevel(p, RDB_DATA_TYPE_MODULE, RDB_LEVEL_RAW);

    /* Avoid RESTORE for functions. Redis doesn't have API to RESTORE functions */
    RDB_handleByLevel(p, RDB_DATA_TYPE_FUNCTION, RDB_LEVEL_DATA);

    return RDB_OK;
}

static inline RdbRes onWriteNewCmdDbg(RdbxToResp *ctx) {
    RdbxRespWriter *writer = &ctx->respWriter;
    size_t currCmdNum = ctx->debug.cmdNum++;

    /* Write only commands starting from given command number */
    if ((ctx->debug.flags & RFLAG_WRITE_FROM_CMD_ID) &&
        (currCmdNum < ctx->debug.writeFromCmdNum))
        return RDB_OK;

    /* enumerate and trace cmd-id by preceding each cmd with "SET _RDB_CLI_CMD_ID_ <CMD-ID>" */
    if (ctx->debug.flags & RFLAG_ENUM_CMD_ID) {
        char keyLenStr[32], cmdIdLenStr[32], cmdIdStr[32];

        RdbxRespWriterStartCmd startCmd;
        startCmd.cmd = "SET";
        startCmd.key = KEY_CMD_ID_DBG;

        struct iovec iov[7];
        /* write SET */
        IOV_CONST(&iov[0], "*3\r\n$3\r\nSET\r\n$");
        /* write key */
        IOV_VALUE(&iov[1], sizeof(KEY_CMD_ID_DBG)-1, keyLenStr);
        IOV_STRING(&iov[2], KEY_CMD_ID_DBG, sizeof(KEY_CMD_ID_DBG)-1);
        /* write cmd-id */
        IOV_CONST(&iov[3], "\r\n$");
        IOV_LEN_AND_VAL(&iov[4], currCmdNum, cmdIdLenStr, cmdIdStr);
        if (unlikely(writer->writev(writer->ctx, iov, 6, &startCmd, 1))) {
            RdbRes errCode = RDB_getErrorCode(ctx->parser);

            /* If failed to write RESP writer but no error reported, then write some general error */
            if (errCode == RDB_OK)
                RDB_reportError(ctx->parser, RDB_ERR_GENERAL, "Failed to writev() RESP");

            return RDB_getErrorCode(ctx->parser);
        }
    }
    return RDB_OK;
}

static inline RdbRes writevWrap(RdbxToResp *ctx, struct iovec *iov, int cnt,
                                RdbxRespWriterStartCmd *startCmd, int endCmd) {
    RdbRes res;
    RdbxRespWriter *writer = &ctx->respWriter;

    if (unlikely(ctx->debug.flags && startCmd)) {
        if ((res = onWriteNewCmdDbg(ctx)) != RDB_OK)
            return RDB_getErrorCode(ctx->parser);
    }

    if (unlikely(writer->writev(writer->ctx, iov, cnt, startCmd, endCmd))) {
        res = RDB_getErrorCode(ctx->parser);

        /* If failed to write RESP writer but no error reported, then write some general error */
        if (res == RDB_OK)
            RDB_reportError(ctx->parser, RDB_ERR_GENERAL, "Failed to writev() RESP");

        return RDB_getErrorCode(ctx->parser);
    }

    return RDB_OK;
}

static inline RdbRes sendFirstRestoreFrag(RdbxToResp *ctx, RdbBulk frag, size_t fragLen) {
    long long expireTime = 0;
    char expireTimeStr[32], expireTimeLenStr[32], keyLenStr[32], lenStr[32];
    struct iovec iov[10];
    int extra_args = 0, iovs = 0;

    /* this logic must be exactly the same as in toRespRestoreFragEnd() */
    if (ctx->targetRedisVerVal >= VER_VAL(5, 0))
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

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "RESTORE";
    startCmd.key = ctx->keyCtx.key;

    /* writev RESTORE */
    char cmd[64];

    int len = snprintf(cmd, sizeof(cmd), "*%d\r\n$7\r\nRESTORE", 4+extra_args);

    IOV_STRING(&iov[iovs++], cmd, len);                             /* RESTORE */
    IOV_LENGTH(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);         /* write key len */
    IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);  /* write key */

    if (expireTime) {
        IOV_LEN_AND_VAL(&iov[iovs], expireTime, expireTimeLenStr, expireTimeStr);
        iovs += 2;
        IOV_CONST(&iov[iovs++], "$");
    } else {
        IOV_CONST(&iov[iovs++], "\r\n$1\r\n0\r\n$");
    }

    IOV_VALUE(&iov[iovs++], ctx->restoreCtx.restoreSize + 10, lenStr); /* write restore len + trailer */
    IOV_STRING(&iov[iovs++], frag, fragLen);                           /* write first frag */
    return writevWrap(ctx, iov, iovs, &startCmd, 0);
}

static inline RdbRes sendFirstRestoreFragModuleAux(RdbxToResp *ctx, RdbBulk frag, size_t fragLen) {
    struct iovec iov[3];
    char lenStr[32];

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "RESTOREMODAUX";
    startCmd.key = "";

    /* writev RESTOREMODAUX */
    iov[0].iov_base = ctx->restoreCtx.moduleAux.cmdPrefix;
    iov[0].iov_len =  ctx->restoreCtx.moduleAux.cmdlen;
    IOV_LENGTH(&iov[1], ctx->restoreCtx.restoreSize + 10, lenStr); /* write restore len + trailer */
    IOV_STRING(&iov[2], frag, fragLen);                   /* write first frag */
    return writevWrap(ctx, iov, 3, &startCmd, 0);
}

/*** Handling common ***/

static RdbRes toRespNewDb(RdbParser *p, void *userData, int dbid) {
    UNUSED(p);

    struct iovec iov[10];
    char dbidStr[10], cntStr[10];

    RdbxToResp *ctx = userData;

    /* If configured singleDb then skip writing SELECT */
    if (ctx->conf.singleDb)
        return RDB_OK;

    int cnt = ll2string(dbidStr, sizeof(dbidStr), dbid);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "SELECT";
    startCmd.key = "";

    IOV_CONST(&iov[0], "*2\r\n$6\r\nSELECT");
    IOV_LENGTH(&iov[1], cnt, cntStr);
    IOV_STRING(&iov[2], dbidStr, cnt);
    IOV_CONST(&iov[3], "\r\n");
    return writevWrap(ctx, iov, 4, &startCmd, 1);
}

static RdbRes toRespStartRdb(RdbParser *p, void *userData, int rdbVersion) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* If not configured respWriter then output it to STDOUT */
    assert (ctx->respWriterConfigured == 1);

    ctx->srcRdbVer = rdbVersion;
    ctx->dstRdbVer = setRdbVerFromDestRedisVer(ctx);

    return resolveSupportRestore(p, ctx);
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

        RdbxRespWriterStartCmd startCmd;
        startCmd.cmd = "DEL";
        startCmd.key = ctx->keyCtx.key;

        IOV_CONST(&iov[0], "*2\r\n$3\r\nDEL");
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n");
        return writevWrap(ctx, iov, 4, &startCmd, 1);
    }
    return RDB_OK;
}

static RdbRes toRespEndKey(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    RdbRes res = RDB_OK;

    /* key is in db. Set its expiration time */
    if (ctx->keyCtx.info.expiretime != -1) {
        struct iovec iov[6];
        RdbxRespWriterStartCmd startCmd;
        startCmd.cmd = "PEXPIREAT";
        startCmd.key = ctx->keyCtx.key;

        char keyLenStr[32], expireLenStr[32], expireStr[32];
        /* PEXPIREAT */
        IOV_CONST(&iov[0], "*3\r\n$9\r\nPEXPIREAT");

        /* KEY-LEN and KEY */
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_LEN_AND_VAL(iov+3, ctx->keyCtx.info.expiretime, expireLenStr, expireStr);
        res = writevWrap(ctx, iov, 5, &startCmd, 1);
    }

    RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;

    return res;
}

/*** Handling data ***/

static RdbRes toRespString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToResp *ctx = userData;

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, string);

    /*** fillup iovec ***/

    struct iovec iov[7];

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "SET";
    startCmd.key = ctx->keyCtx.key;

    /* write SET */
    IOV_CONST(&iov[0], "*3\r\n$3\r\nSET");
    /* write key */
    IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    /* write string */
    IOV_LENGTH(&iov[3], valLen, valLenStr);
    IOV_STRING(&iov[4], string, valLen);
    IOV_CONST(&iov[5], "\r\n");
    return writevWrap(ctx, iov, 6, &startCmd, 1);
}

static RdbRes toRespList(RdbParser *p, void *userData, RdbBulk item) {
    RdbxToResp *ctx = userData;
    struct iovec iov[7];

    /*** fillup iovec ***/

    char keyLenStr[32], valLenStr[32];
    int valLen = RDB_bulkLen(p, item);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "RPUSH";
    startCmd.key = ctx->keyCtx.key;

    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$5\r\nRPUSH");
    /* write key */
    IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    /* write item */
    IOV_LENGTH(&iov[3], valLen, valLenStr);
    IOV_STRING(&iov[4], item, valLen);
    IOV_CONST(&iov[5], "\r\n");
    return writevWrap(ctx, iov, 6, &startCmd, 1);
}

static RdbRes toRespHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value) {
    struct iovec iov[10];
    RdbxToResp *ctx = userData;

    /*** fillup iovec ***/

    char keyLenStr[32], fieldLenStr[32], valueLenStr[32];
    int fieldLen = RDB_bulkLen(p, field);
    int valueLen = RDB_bulkLen(p, value);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "HSET";
    startCmd.key = ctx->keyCtx.key;

    /* write RPUSH */
    IOV_CONST(&iov[0], "*4\r\n$4\r\nHSET");
    /* write key */
    IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    /* write field */
    IOV_LENGTH(&iov[3], fieldLen, fieldLenStr);
    IOV_STRING(&iov[4], field, fieldLen);
    /* write value */
    IOV_LENGTH(&iov[5], valueLen, valueLenStr);
    IOV_STRING(&iov[6], value, valueLen);
    IOV_CONST(&iov[7], "\r\n");
    return writevWrap(ctx, iov, 8, &startCmd, 1);
}

static RdbRes toRespSet(RdbParser *p, void *userData, RdbBulk member) {
    struct iovec iov[7];
    RdbxToResp *ctx = userData;
    char keyLenStr[32], valLenStr[32];

    int valLen = RDB_bulkLen(p, member);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "SADD";
    startCmd.key = ctx->keyCtx.key;

    /* write RPUSH */
    IOV_CONST(&iov[0], "*3\r\n$4\r\nSADD");
    /* write key */
    IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    /* write member */
    IOV_LENGTH(&iov[3], valLen, valLenStr);
    IOV_STRING(&iov[4], member, valLen);
    IOV_CONST(&iov[5], "\r\n");
    return writevWrap(ctx, iov, 6, &startCmd, 1);
}

static RdbRes toRespZset(RdbParser *p, void *userData, RdbBulk member, double score) {
    struct iovec iov[10];
    RdbxToResp *ctx = userData;
    char keyLenStr[32], valLenStr[32], scoreLenStr[32];

    int valLen = RDB_bulkLen(p, member);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "ZADD";
    startCmd.key = ctx->keyCtx.key;

    /* write ZADD */
    IOV_CONST(&iov[0], "*4\r\n$4\r\nZADD");
    /* write key */
    IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);

    /* write score */
    char score_str[MAX_D2STRING_CHARS];
    int len = d2string(score_str, sizeof(score_str), score);
    assert(len != 0);
    IOV_LENGTH(&iov[3], len, scoreLenStr);
    IOV_STRING(&iov[4], score_str, strlen(score_str));

    /* write member */
    IOV_LENGTH(&iov[5], valLen, valLenStr);
    IOV_STRING(&iov[6], member, valLen);
    IOV_CONST(&iov[7], "\r\n");
    return writevWrap(ctx, iov, 8, &startCmd, 1);
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

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "FUNCTION";
    startCmd.key = "";

    struct iovec iov[4];
    IOV_CONST(&iov[0], "*4\r\n$8\r\nFUNCTION\r\n$4\r\nLOAD\r\n$7\r\nREPLACE");
    /* write member */
    IOV_LENGTH(&iov[1], funcLen, funcLenStr);
    IOV_STRING(&iov[2], func, funcLen);
    IOV_CONST(&iov[3], "\r\n");
    return writevWrap( (RdbxToResp *) userData, iov, 4, &startCmd, 1);

}

static RdbRes toRespStreamMetaData(RdbParser *p, void *userData, RdbStreamMeta *meta) {

    UNUSED(p);
    char keyLenStr[32], idStr[100], idLenStr[32], maxDelEntryIdLenStr[64], maxDelEntryId[100], entriesLenStr[32], entriesStr[32];
    RdbxToResp *ctx = userData;
    struct iovec iov[15];

    if (ctx->streamCtx.xaddStartEndCounter == 0) {
        /* Use the XGROUP CREATE MKSTREAM + DESTROY trick to generate an empty stream if
         * the key we are serializing is an empty stream, which is possible
         * for the Stream type. (We don't use the MAXLEN 0 trick from aof.c
         * because of Redis Enterprise CRDT compatibility issues - Can't XSETID "back") */

        RdbxRespWriterStartCmd startCmd;
        startCmd.cmd = "XGROUP CREATE";
        startCmd.key = ctx->keyCtx.key;

        IOV_CONST(&iov[0], "*6\r\n$6\r\nXGROUP\r\n$6\r\nCREATE");
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n$7\r\ndummyCG\r\n$1\r\n$\r\n$8\r\nMKSTREAM\r\n");
        IF_NOT_OK_RETURN(writevWrap( (RdbxToResp *) userData, iov, 4, &startCmd, 1));

        /* another startCmd */
        startCmd.cmd = "XGROUP DESTROY";
        startCmd.key = ctx->keyCtx.key;

        IOV_CONST(&iov[0], "*4\r\n$6\r\nXGROUP\r\n$7\r\nDESTROY");
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_CONST(&iov[3], "\r\n$7\r\ndummyCG\r\n");
        IF_NOT_OK_RETURN(writevWrap( (RdbxToResp *) userData, iov, 4, &startCmd, 1));
    }

    /* take care to reset it for next stream-item */
    ctx->streamCtx.xaddStartEndCounter = 0;

    int idLen = snprintf(idStr, sizeof(idStr), "%lu-%lu",meta->lastID.ms,meta->lastID.seq);
    int maxDelEntryIdLen = snprintf(maxDelEntryId, sizeof(maxDelEntryId), "%lu-%lu", meta->maxDelEntryID.ms, meta->maxDelEntryID.seq);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "XSETID";
    startCmd.key = ctx->keyCtx.key;

    if ((ctx->keyCtx.info.opcode >= _RDB_TYPE_STREAM_LISTPACKS_2) && (ctx->targetRedisVerVal >= VER_VAL(7, 0))) {
        IOV_CONST(&iov[0], "*7\r\n$6\r\nXSETID");
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_LENGTH(&iov[3], idLen, idLenStr);
        IOV_STRING(&iov[4], idStr, idLen);
        IOV_CONST(&iov[5], "\r\n$12\r\nENTRIESADDED");
        IOV_LEN_AND_VAL(&iov[6], meta->entriesAdded, entriesLenStr, entriesStr);
        IOV_CONST(&iov[8], "$12\r\nMAXDELETEDID");
        IOV_LENGTH(&iov[9], maxDelEntryIdLen, maxDelEntryIdLenStr);
        IOV_STRING(&iov[10], maxDelEntryId, maxDelEntryIdLen);
        IOV_CONST(&iov[11], "\r\n");
        return writevWrap( (RdbxToResp *) userData, iov, 12, &startCmd, 1);
    } else {
        IOV_CONST(&iov[0], "*3\r\n$6\r\nXSETID");
        IOV_LENGTH(&iov[1], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[2], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        IOV_LENGTH(&iov[3], idLen, idLenStr);
        IOV_STRING(&iov[4], idStr, idLen);
        IOV_CONST(&iov[5], "\r\n");
        return writevWrap( (RdbxToResp *) userData, iov, 6, &startCmd, 1);
    }
}

static RdbRes toRespStreamItem(RdbParser *p, void *userData, RdbStreamID *id, RdbBulk field, RdbBulk val, int64_t itemsLeft) {
    char cmd[64], idStr[100], idLenStr[64], keyLenStr[32], fieldLenStr[32], valLenStr[32];
    int iovs = 0, endCmd = 0;
    RdbxRespWriterStartCmd startCmd, *startCmdRef = NULL;
    struct iovec iov[15];
    RdbxToResp *ctx = userData;

    size_t fieldLen = RDB_bulkLen(p, field);
    size_t valLen = RDB_bulkLen(p, val);

    /* Start of (another) stream item? */
    if ((ctx->streamCtx.xaddStartEndCounter % 2) == 0) {
        startCmd.cmd = "XADD";
        startCmd.key = ctx->keyCtx.key;
        startCmdRef = &startCmd;

        /* writev XADD */
        int cmdLen = snprintf(cmd, sizeof(cmd), "*%lu\r\n$4\r\nXADD", 3 + (itemsLeft + 1) * 2);
        IOV_STRING(&iov[iovs++], cmd, cmdLen);
        IOV_LENGTH(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        int idLen = snprintf(idStr, sizeof(idStr), "%lu-%lu",id->ms,id->seq);
        IOV_LENGTH(&iov[iovs++], idLen, idLenStr);
        IOV_STRING(&iov[iovs++], idStr, idLen);

        ++ctx->streamCtx.xaddStartEndCounter;
    }

    IOV_LENGTH(&iov[iovs++], fieldLen, fieldLenStr);
    IOV_STRING(&iov[iovs++], field, fieldLen);
    IOV_LENGTH(&iov[iovs++], valLen, valLenStr);
    IOV_STRING(&iov[iovs++], val, valLen);

    /* if end of variadic command */
    if (!itemsLeft) {
        IOV_CONST(&iov[iovs++], "\r\n");
        endCmd = 1;
        ++ctx->streamCtx.xaddStartEndCounter;
    }

    return writevWrap( (RdbxToResp *) userData, iov, iovs, startCmdRef, endCmd);
}

/* Emit the XGROUP CREATE in order to create the group. */
static RdbRes toRespStreamNewCGroup(RdbParser *p, void *userData, RdbBulk grpName, RdbStreamGroupMeta *meta) {
    struct iovec iov[16];
    int iovs = 0;
    RdbxToResp *ctx = userData;
    char keyLenStr[32], gNameLenStr[32], idStr[100], idLenStr[32], entriesReadStr[32], entriesReadLenStr[32];

    /* (re)allocate mem to keep group name */
    RDB_bulkCopyFree(p, ctx->streamCtx.grpName);
    ctx->streamCtx.grpNameLen = RDB_bulkLen(p, grpName);
    if(!(ctx->streamCtx.grpName = RDB_bulkClone(p, grpName)))
        return RDB_ERR_FAIL_ALLOC;

    /* (re)allocate rax tree for group pel */
    if(ctx->streamCtx.groupPel)
        deletePendingEntriesList(p, &ctx->streamCtx.groupPel);
    if(!(ctx->streamCtx.groupPel = raxNew()))
        return RDB_ERR_FAIL_ALLOC;

    int idLen = snprintf(idStr, sizeof(idStr), "%lu-%lu",meta->lastId.ms,meta->lastId.seq);

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "XGROUP";
    startCmd.key = ctx->keyCtx.key;

    /* writev XGROUP */
    if ( (meta->entriesRead>=0) && (ctx->targetRedisVerVal >= VER_VAL(7, 0))) {
        /* XGROUP CREATE */
        IOV_CONST(&iov[iovs++], "*7\r\n$6\r\nXGROUP\r\n$6\r\nCREATE");
        /* key */
        IOV_LENGTH(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        /* group name */
        IOV_LENGTH(&iov[iovs++], ctx->streamCtx.grpNameLen, gNameLenStr);
        IOV_STRING(&iov[iovs++], ctx->streamCtx.grpName, ctx->streamCtx.grpNameLen);
        /* last id */
        IOV_LENGTH(&iov[iovs++], idLen, idLenStr);
        IOV_STRING(&iov[iovs++], idStr, idLen);
        /* entries read */
        IOV_CONST(&iov[iovs++], "\r\n$11\r\nENTRIESREAD");
        IOV_LEN_AND_VAL(&iov[iovs], meta->entriesRead, entriesReadLenStr, entriesReadStr);
        iovs += 2;
    } else {
        /* XGROUP CREATE */
        IOV_CONST(&iov[iovs++], "*5\r\n$6\r\nXGROUP\r\n$6\r\nCREATE");
        /* key */
        IOV_LENGTH(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);
        IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);
        /* group name */
        IOV_LENGTH(&iov[iovs++], ctx->streamCtx.grpNameLen, gNameLenStr);
        IOV_STRING(&iov[iovs++], ctx->streamCtx.grpName, ctx->streamCtx.grpNameLen);
        /* last id */
        IOV_LENGTH(&iov[iovs++], idLen, idLenStr);
        IOV_STRING(&iov[iovs++], idStr, idLen);
        IOV_CONST(&iov[iovs++], "\r\n");
    }
    return writevWrap(ctx, iov, iovs, &startCmd, 1);
}

static RdbRes toRespStreamCGroupPendingEntry(RdbParser *p, void *userData, RdbStreamPendingEntry *pendingEntry) {
    RdbxToResp *ctx = userData;
    RdbStreamPendingEntry *pe;

    /* Make a copy pending entry */
    if ((pe = RDB_alloc(p, sizeof(RdbStreamPendingEntry))) == NULL)
        return RDB_ERR_FAIL_ALLOC;

    memcpy(pe, pendingEntry, sizeof(RdbStreamPendingEntry));

    if (!raxTryInsert(ctx->streamCtx.groupPel, (unsigned char *) &(pe->id), sizeof(pe->id), pe, NULL))
        return (RdbRes) RDBX_ERR_STREAM_DUPLICATE_PEL;

    return RDB_OK;
}

static RdbRes toRespStreamNewConsumer(RdbParser *p, void *userData, RdbBulk consName, RdbStreamConsumerMeta *meta) {
    UNUSED(meta);
    RdbxToResp *ctx = userData;

    /* (re)allocate mem to keep consumer name */
    RDB_bulkCopyFree(p, ctx->streamCtx.consName);

    ctx->streamCtx.consNameLen = RDB_bulkLen(p, consName);
    if(!(ctx->streamCtx.consName = RDB_bulkClone(p, consName)))
        return RDB_ERR_FAIL_ALLOC;

    return RDB_OK;
}

/* Callback to handle a pending entry within a consumer */
static RdbRes toRespStreamConsumerPendingEntry(RdbParser *p, void *userData, RdbStreamID *streamId) {
    RdbStreamPendingEntry *pe;
    char cmdTrailer[256], idStr[100], keyLenStr[32], gNameLenStr[32], cNameLenStr[32], sentTime[32], sentCount[32];
    struct iovec iov[16];
    int iovs = 0;
    RdbxToResp *ctx = userData;

    if ((pe = raxFind(ctx->streamCtx.groupPel, (unsigned char *)streamId, sizeof(*streamId))) == raxNotFound) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_STREAM_INTEG_CHECK,
                        "toRespStreamNewConsumer(): Cannot find consumer pending entry in group PEL");
        return (RdbRes) RDBX_ERR_STREAM_INTEG_CHECK;
    }

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "XCLAIM";
    startCmd.key = ctx->keyCtx.key;

    /* writev XCLAIM */
    IOV_CONST(&iov[iovs++], "*12\r\n$6\r\nXCLAIM");
    /* key */
    IOV_LENGTH(&iov[iovs++], ctx->keyCtx.keyLen, keyLenStr);
    IOV_STRING(&iov[iovs++], ctx->keyCtx.key, ctx->keyCtx.keyLen);
    /* group name */
    IOV_LENGTH(&iov[iovs++], ctx->streamCtx.grpNameLen, gNameLenStr);
    IOV_STRING(&iov[iovs++], ctx->streamCtx.grpName, ctx->streamCtx.grpNameLen);

    /* consumer name */
    IOV_LENGTH(&iov[iovs++], ctx->streamCtx.consNameLen, cNameLenStr);
    IOV_STRING(&iov[iovs++], ctx->streamCtx.consName, ctx->streamCtx.consNameLen);
    /* trailer of the command */
    int idLen = snprintf(idStr, sizeof(idStr), "%lu-%lu",streamId->ms, streamId->seq);
    int sentTimeLen = ll2string(sentTime, sizeof(sentTime), pe->deliveryTime);
    int sentCountLen = ll2string(sentCount, sizeof(sentCount), pe->deliveryCount);
    int cmdTrailerLen = snprintf(cmdTrailer, sizeof(cmdTrailer),
                                "\r\n$1\r\n0\r\n$%d\r\n%s\r\n$4\r\nTIME\r\n$%d\r\n%s\r\n$10\r\nRETRYCOUNT\r\n$%d\r\n%s\r\n$6\r\nJUSTID\r\n$5\r\nFORCE\r\n",
                                idLen, idStr, sentTimeLen, sentTime, sentCountLen, sentCount);
    /* max: 2 + 2 + 1 + 3 + 21*2+1 + 2 + 4 + 3 + 21 + 2 + 10 + 3 +21 +2 + 6 + 2 +5 + 2*16 */
    IOV_STRING(&iov[iovs++], cmdTrailer, cmdTrailerLen);
    return writevWrap(ctx, iov, iovs, &startCmd, 1);
}

/*** Handling raw (RESTORE) ***/
/* Callback on start of serializing module aux data (alternative to toRespRestoreBegin).
 * Following this call, one or more calls will be made to toRespRestoreFrag() to
 * stream fragments of the serialized data. And at the end toRespRestoreFragEnd()
 * will be called */
static RdbRes toRespRestoreBeginModuleAux(RdbParser *p, void *userData, RdbBulk name, int encver, int when, size_t rawSize) {
    char encstr[10];
    UNUSED(p);

    /* reset restoreCtx */
    RdbxToResp *ctx = userData;
    ctx->restoreCtx.restoreSize = rawSize;
    ctx->restoreCtx.sentFirstFrag = 0;
    ctx->restoreCtx.isModuleAux = 1;
    ctx->restoreCtx.crc = 0;

    /* if target doesn't support module-aux, then skip it */
    if (!ctx->conf.supportRestoreModuleAux)
        return RDB_OK;

    /* Build the cmd instead of keeping the values and build it later */
    size_t enclen = snprintf(encstr, sizeof(encstr), "%d", encver);
    const char* whenstr = (when==_REDISMODULE_AUX_BEFORE_RDB) ? "before" :"after";
    ctx->restoreCtx.moduleAux.cmdlen = snprintf(ctx->restoreCtx.moduleAux.cmdPrefix,
                                                sizeof(ctx->restoreCtx.moduleAux.cmdPrefix),
                                                "*5\r\n$13\r\nRESTOREMODAUX\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n$%zu\r\n%s",
                                                strlen(name), name, enclen, encstr, strlen(whenstr), whenstr);
    return RDB_OK;
}

/* Callback on start of serializing value of a key. Following this call, one
 * or more calls will be made to toRespRestoreFrag() to stream fragments of the
 * serialized data. And at the end toRespRestoreFragEnd() will be called */
static RdbRes toRespRestoreBegin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    RdbxToResp *ctx = userData;

    /* reset restoreCtx */
    ctx->restoreCtx.restoreSize = size;
    ctx->restoreCtx.sentFirstFrag = 0;
    ctx->restoreCtx.isModuleAux = 0;
    ctx->restoreCtx.crc = 0;
    return RDB_OK;
}

/* Callback for fragments of a serialized value associated with a new key or module
 * auxiliary data. This callback is invoked after toRespRestoreBegin() or
 * toRespRestoreBeginModuleAux(), and it may be called multiple times until the
 * serialization is complete. Finally, toRespRestoreFragEnd() will be called to signal
 * the registered handlers for the completion of the operation. */
static RdbRes toRespRestoreFrag(RdbParser *p, void *userData, RdbBulk frag) {
    UNUSED(p);
    RdbxToResp *ctx = userData;
    struct iovec iov[10];
    int iovs = 0;

    /* if processing module-aux but target doesn't support, then skip it */
    if ((ctx->restoreCtx.isModuleAux) && (!ctx->conf.supportRestoreModuleAux))
        return RDB_OK;

    size_t fragLen = RDB_bulkLen(p, frag);
    ctx->restoreCtx.crc = crc64(ctx->restoreCtx.crc, (unsigned char *) frag , fragLen);

    /* if first frag, handled differently */
    if (likely(!(ctx->restoreCtx.sentFirstFrag))) {
        ctx->restoreCtx.sentFirstFrag = 1;
        if (ctx->restoreCtx.isModuleAux)
            return sendFirstRestoreFragModuleAux(ctx, frag, fragLen);
        else
            return sendFirstRestoreFrag(ctx, frag, fragLen);
    }

    IOV_STRING(&iov[iovs++], frag, fragLen);
    return writevWrap(ctx, iov, iovs, NULL, 0);
}

/* This call will be followed one or more calls to toRespRestoreFrag() which indicates
 * for completion of streaming of fragments of serialized value of a new key or
 * module-aux data. */
static RdbRes toRespRestoreFragEnd(RdbParser *p, void *userData) {
    UNUSED(p);
    char cmd[1024]; /* degenerate usage of iov. All copied strings are small */
    RdbxToResp *ctx = userData;
    uint64_t *crc = &(ctx->restoreCtx.crc);

    /* if processing module-aux but target doesn't support, then skip it */
    if ((ctx->restoreCtx.isModuleAux) && (!ctx->conf.supportRestoreModuleAux))
        return RDB_OK;

    /* Add RDB version 2 bytes. If it is module  */

    if (unlikely(ctx->keyCtx.info.opcode == _RDB_TYPE_MODULE_2)) {
        /* Module object cannot forwarded to destination as a set of Redis commands.
         * (Function resolveSupportRestore() enforced the parser to use RESTORE in case
         * of modules) In order to avoid failure on downgrade when using RESTORE
         * command, we are using the target rdb version for it */
        int rdbVer = (ctx->srcRdbVer > ctx->dstRdbVer) ? ctx->dstRdbVer : ctx->srcRdbVer;
        cmd[0] = rdbVer & 0xff;
        cmd[1] = (rdbVer >> 8) & 0xff;
    } else {
        cmd[0] = ctx->srcRdbVer & 0xff;
        cmd[1] = (ctx->srcRdbVer >> 8) & 0xff;
    }

    /* Add CRC64 8 bytes */
    *crc = crc64(*crc, (unsigned char *) cmd, 2);
    memrev64ifbe(crc);
    memcpy(cmd + 2, crc, 8);

    int len = 10;

    /* if processing module-aux then we are done (no REPLACE, ABSTTL, IDLETIME or FREQ) */
    if (ctx->restoreCtx.isModuleAux) {
        len += snprintf(cmd+len, sizeof(cmd)-len, "\r\n");
        struct iovec iov = {cmd, len};
        return writevWrap(ctx, &iov, 1, NULL, 1);
    }

    /* Add REPLACE if needed */
    if (ctx->keyCtx.delBeforeWrite == DEL_KEY_BEFORE_BY_RESTORE_REPLACE)
        len += snprintf(cmd+len, sizeof(cmd)-len, "\r\n$7\r\nREPLACE\r\n");
    else
        len += snprintf(cmd+len, sizeof(cmd)-len, "\r\n");

    /* This logic must be exactly the same as in toRespRestoreFrag() */
    if (likely(ctx->targetRedisVerVal >= VER_VAL(5, 0))) {

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
    return writevWrap(ctx, &iov, 1, NULL, 1);
}

/*** LIB API functions ***/

_LIBRDB_API RdbxToResp *RDBX_createHandlersToResp(RdbParser *p, RdbxToRespConf *conf) {
    RdbxToResp *ctx;

    crc64_init_thread_safe();

    /* Verify table is aligned with LIBRDB_SUPPORT_MAX_RDB_VER */
    assert(redisToRdbVersion[0].rdb == RDB_getMaxSuppportRdbVersion());

    if ((ctx = RDB_alloc(p, sizeof(RdbxToResp))) == NULL)
        return NULL;

    memset(ctx, 0, sizeof(RdbxToResp));
    if (conf) ctx->conf = *conf;
    ctx->parser = p;
    ctx->refcount = 2;
    ctx->streamCtx.xaddStartEndCounter = 0;
    ctx->streamCtx.grpName = NULL;
    ctx->streamCtx.groupPel = NULL;

    static RdbHandlersDataCallbacks dataCb = {
            toRespStartRdb,
            toRespEndRdb,
            toRespNewDb,
            NULL, /*db-size*/
            NULL, /*slot-info*/
            NULL, /*aux-field*/
            toRespNewKey,
            toRespEndKey,
            toRespString,
            toRespList,
            toRespHash,
            toRespSet,
            toRespZset,
            toRespFunction,
            NULL, /*module*/
            toRespStreamMetaData,
            toRespStreamItem,
            toRespStreamNewCGroup,
            toRespStreamCGroupPendingEntry,
            toRespStreamNewConsumer,
            toRespStreamConsumerPendingEntry
    };
    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToRespCtx);



    static RdbHandlersRawCallbacks rawCb = {
            /* no need to register (twice) common cb. Already registered by dataCb */
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            toRespNewKey,
            toRespEndKey,
            toRespRestoreBeginModuleAux,
            toRespRestoreBegin,
            toRespRestoreFrag,
            toRespRestoreFragEnd,
    };
    RDB_createHandlersRaw(p, &rawCb, ctx, deleteRdbToRespCtx);

    return ctx;
}

_LIBRDB_API void RDBX_attachRespWriter(RdbxToResp *rdbToResp, RdbxRespWriter *writer) {
    assert (rdbToResp->respWriterConfigured == 0);
    rdbToResp->respWriter = *writer;
    rdbToResp->respWriterConfigured = 1;
}

_LIBRDB_API void RDBX_enumerateCmds(RdbxToResp *rdbToResp) {
    rdbToResp->debug.flags |= RFLAG_ENUM_CMD_ID;
}

_LIBRDB_API void RDBX_writeFromCmdNumber(RdbxToResp *rdbToResp, size_t cmdNum) {
    rdbToResp->debug.flags |= RFLAG_WRITE_FROM_CMD_ID;
    rdbToResp->debug.writeFromCmdNum = cmdNum;
}
