#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "common.h"
#include "readerResp.h"

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define PIPELINE_DEPTH_DEF        200   /* Default Number of pending cmds before waiting for response(s) */
#define PIPELINE_DEPTH_MAX        1000  /* limit the max value allowed to configure for pipeline depth */

#define NUM_RECORDED_CMDS         400   /* Number of commands to backlog, in a cyclic array */
#define RECORDED_KEY_MAX_LEN     40    /* Maximum payload size from any command to record into cyclic array */

#define REPLY_BUFF_SIZE           1024  /* reply buffer size */

#define MAX_EINTR_RETRY           3


struct RdbxRespToRedisLoader {

    struct {
        int num;
        int pipelineDepth;
        /* pointers to (static) strings that hold the template of the command sent (no char* allocation required) */
        const char *cmd[NUM_RECORDED_CMDS];
        /* strncpy() of the key sent */
        char key[NUM_RECORDED_CMDS][RECORDED_KEY_MAX_LEN];
    } pendingCmds;

    RespReaderCtx respReader;
    RdbParser *p;
    int fd;
};

static void onReadRepliesError(RdbxRespToRedisLoader *ctx) {
    RespReaderCtx *respReader = &ctx->respReader;
    int currIdx = ctx->respReader.countReplies % NUM_RECORDED_CMDS;

    RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_WRITE,
                    "\nerror from dst '-%s' on key '%s' on command '%s' (RESP Command #%lu)\n",
                    respReader->errorMsg,
                    ctx->pendingCmds.key[currIdx],
                    ctx->pendingCmds.cmd[currIdx],
                    ctx->respReader.countReplies);
}

/* Read 'numToRead' replies from the socket. * Return 0 for success, 1 otherwise. */
static int readReplies(RdbxRespToRedisLoader *ctx, int numToRead) {
    char buff[REPLY_BUFF_SIZE];

    RespReaderCtx *respReader = &ctx->respReader;
    size_t countRepliesBefore = respReader->countReplies;
    size_t repliesExpected = respReader->countReplies + numToRead;

    while (respReader->countReplies < repliesExpected) {
        int bytesReceived = recv(ctx->fd, buff, sizeof(buff), 0);

        if (bytesReceived > 0) {
            /* Data was received, process it */
            if (unlikely(RESP_REPLY_ERR == readRespReplies(respReader, buff, bytesReceived))) {
                onReadRepliesError(ctx);
                return 1;
            }

        } else if (bytesReceived == 0) {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_CONN_CLOSE, "Connection closed by the remote side");
            return 1;
        } else {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_READ, "Failed to recv() from Redis server. (errno=%d)", errno);
            return 1;
        }
    }

    ctx->pendingCmds.num -= (respReader->countReplies - countRepliesBefore);
    return 0;
}

/* For debugging, record the command into the cyclic array before sending it */
static inline void recordCommandSent(RdbxRespToRedisLoader *ctx,RdbxRespWriterStartCmd *cmd) {
    int recordCmdEntry = (ctx->respReader.countReplies + ctx->pendingCmds.num) % NUM_RECORDED_CMDS;

    /* no need to copy the cmd. handlersToResp took care to pass a string that is persistent and constant */
    ctx->pendingCmds.cmd[recordCmdEntry] = cmd->cmd;
    strncpy(ctx->pendingCmds.key[recordCmdEntry], cmd->key, RECORDED_KEY_MAX_LEN-1);
    ctx->pendingCmds.key[recordCmdEntry][RECORDED_KEY_MAX_LEN-1] = '\0';
}

/* Write the vector of data to the socket with writev() sys-call.
 * Return 0 for success, 1 otherwise. */
static int redisLoaderWritev(void *context, struct iovec *iov, int iovCnt,
                             RdbxRespWriterStartCmd *startCmd, int endCmd)
{
    ssize_t writeResult;
    int retries = 0;

    RdbxRespToRedisLoader *ctx = context;

    if (unlikely(ctx->pendingCmds.num == ctx->pendingCmds.pipelineDepth)) {
        if (readReplies(ctx, 1 /* at least one */))
            return 1;
    }

    if (startCmd) recordCommandSent(ctx, startCmd);

    while (1)
    {
        writeResult = writev(ctx->fd, iov, iovCnt);

        /* check for error */
        if (unlikely(writeResult == -1)) {
            if (errno == EINTR) {
                if ((retries++) >= MAX_EINTR_RETRY) {
                    RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_WRITE,
                                    "Failed to write socket. Exceeded EINTR retry limit");
                    return 1;
                }
                continue;
            } else {
                RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_WRITE,
                                "Failed to write socket (errno=%d)", errno);
                return 1;
            }
        }

        /* crunch iov entries that were transmitted entirely */
        while ((iovCnt) && (iov->iov_len <= (size_t) writeResult)) {
            writeResult -= iov->iov_len;
            ++iov;
            --iovCnt;
        }

        /* if managed to send all iov entries */
        if (likely(iovCnt == 0))
            break;

        /* Update pointed iov entry. Only partial of its data sent */
        iov->iov_len -= writeResult;
        iov->iov_base = (char *) iov->iov_base + writeResult;
    }

    ctx->pendingCmds.num += endCmd;
    return 0;
}

/* Flush the pending commands by reading the remaining replies.
 * Return 0 for success, 1 otherwise. */
static int redisLoaderFlush(void *context) {
    RdbxRespToRedisLoader *ctx = context;
    if (ctx->pendingCmds.num)
        return readReplies(ctx, ctx->pendingCmds.num);
    return 0;
}

/* Delete the context and perform cleanup. */
static void redisLoaderDelete(void *context) {
    struct RdbxRespToRedisLoader *ctx = context;

    /* not required to flush on termination */

    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */
    close(ctx->fd);
    RDB_free(ctx->p, ctx);
}

static RdbRes redisAuthCustomized(RdbxRespToRedisLoader *ctx, RdbxRedisAuth *auth) {
    int i, iovs;
    RdbRes res = RDB_OK;

    /* custom auth command - Need to break it into tokens based on spaces and
    * tabs. And then translate it into RESP protocol */

    char prefix[32];

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "<AUTH_CUSTOMIZED_CMD>";
    startCmd.key = "";

    /* allocate iovec (2 for header and trailer. 3 for each argument) */
    struct iovec *iov = (struct iovec *)malloc((auth->cmd.argc * 3 + 2) * sizeof(struct iovec));
    /* allocate temporary buffer to assist converting length to string of all args */
    char (*lenStr)[21] = (char (*)[21])malloc(auth->cmd.argc * 21 * sizeof(char));

    if (iov == NULL || lenStr == NULL) {
        RDB_reportError(ctx->p, RDB_ERR_FAIL_ALLOC,
                        "Failed to allocate for customized AUTH (tokens=%d)", auth->cmd.argc);
        res = RDB_ERR_FAIL_ALLOC; // Return an error code
        goto AuthEnd;
    }

    /* set number of elements in the prefix of the RESP command */
    iov[0].iov_len = snprintf(prefix, sizeof(prefix)-1, "*%d", auth->cmd.argc);
    iov[0].iov_base = prefix;

    for ( i = 0, iovs = 1 ; i < auth->cmd.argc ; ++i)
    {
        size_t tLen = strlen(auth->cmd.argv[i]);
        IOV_CONST(&iov[iovs++], "\r\n$");
        IOV_VALUE(&iov[iovs++], tLen, lenStr[i]);
        IOV_STRING(&iov[iovs++], auth->cmd.argv[i], tLen);
    }
    IOV_CONST(&iov[iovs++], "\r\n");
    redisLoaderWritev(ctx, iov, iovs, &startCmd, 1);

AuthEnd:
    if (iov) free(iov);
    if (lenStr) free(lenStr);
    return res;
}

static RdbRes redisAuth(RdbxRespToRedisLoader *ctx, RdbxRedisAuth *auth) {
    int iovs;
    char userLenStr[21], pwdLenStr[21];

    if ((auth->pwd == NULL) && (auth->cmd.argc == 0))
        return RDB_OK;

    /* if customized auth command */
    if (auth->cmd.argv)
        return redisAuthCustomized(ctx, auth);

    /* AUTH [username] password */

    RdbxRespWriterStartCmd startCmd;
    startCmd.cmd = "AUTH";
    startCmd.key = "";

    struct iovec iov[10];
    if (auth->user) {
        IOV_CONST(&iov[0], "*3\r\n$4\r\nauth\r\n$");
        /* write user */
        IOV_VALUE(&iov[1], strlen(auth->user), userLenStr);
        IOV_STRING(&iov[2], auth->user, strlen(auth->user));
        IOV_CONST(&iov[3], "\r\n$");
        /* write pwd */
        IOV_VALUE(&iov[4], strlen(auth->pwd), pwdLenStr);
        IOV_STRING(&iov[5], auth->pwd, strlen(auth->pwd));
        IOV_CONST(&iov[6], "\r\n");
        iovs = 7;
    } else {
        IOV_CONST(&iov[0], "*2\r\n$4\r\nauth\r\n$");
        /* write pwd */
        IOV_VALUE(&iov[1], strlen(auth->pwd), pwdLenStr);
        IOV_STRING(&iov[2], auth->pwd, strlen(auth->pwd));
        IOV_CONST(&iov[3], "\r\n");
        iovs = 4;
    }

    redisLoaderWritev(ctx, iov, iovs, &startCmd, 1);
    return RDB_OK;
}

/*** LIB API functions ***/

_LIBRDB_API void RDBX_setPipelineDepth(RdbxRespToRedisLoader *r2r, int depth) {
    r2r->pendingCmds.pipelineDepth = (depth <= 0 || depth>PIPELINE_DEPTH_MAX) ? PIPELINE_DEPTH_DEF : depth;
}

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisFd(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            RdbxRedisAuth *auth,
                                                            int fd) {
    RdbxRespToRedisLoader *ctx;
    if ((ctx = RDB_alloc(p, sizeof(RdbxRespToRedisLoader))) == NULL) {
        close(fd);
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_FAILED_ALLOC,
                        "Failed to allocate struct RdbxRespToRedisLoader");
        return NULL;
    }

    /* init RdbxRespToRedisLoader context */
    memset(ctx, 0, sizeof(RdbxRespToRedisLoader));
    ctx->p = p;
    ctx->fd = fd;
    ctx->pendingCmds.num = 0;
    ctx->pendingCmds.pipelineDepth = PIPELINE_DEPTH_DEF;
    readRespInit(&ctx->respReader);

    if (auth && (redisAuth(ctx, auth) != RDB_OK))
        return NULL;

    /* Set 'this' writer to rdbToResp */
    RdbxRespWriter inst = {ctx, redisLoaderDelete, redisLoaderWritev, redisLoaderFlush};
    RDBX_attachRespWriter(rdbToResp, &inst);
    return ctx;
}

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                             RdbxToResp *rdbToResp,
                                                             RdbxRedisAuth *auth,
                                                             const char *hostname,
                                                             int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_CREATE_SOCKET, "Failed to create tcp socket");
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &(server_addr.sin_addr)) <= 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_INVALID_ADDRESS,
                        "Invalid tcp address (hostname=%s, port=%d)", hostname, port);
        close(sockfd);
        return NULL;
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_INVALID_ADDRESS,
                        "Invalid tcp address (hostname=%s, port=%d)", hostname, port);
        close(sockfd);
        return NULL;
    }

    return RDBX_createRespToRedisFd(p, rdbToResp, auth, sockfd);
}
