#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include "extCommon.h"
#include "readerResp.h"

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define PIPELINE_DEPTH_DEF          200   /* Default Number of pending cmds before waiting for response(s) */
#define PIPELINE_DEPTH_MAX          1000  /* limit the max value allowed to configure for pipeline depth */

#define NUM_RECORDED_CMDS           400   /* Number of commands to backlog, in a cyclic array */
#define RECORDED_KEY_MAX_LEN        40    /* Maximum payload size from any command to record into cyclic array */

#define REPLY_BUFF_SIZE             1024  /* reply buffer size */

#define MAX_EINTR_RETRY             5
#define RECV_CMD_TIMEOUT_SEC        10    /* recv() command timeout in seconds */

struct RdbxRespToRedisLoader {

    struct {
        int num;
        int pipelineDepth;
        /* pointers to (static) strings that hold the template of the command sent (no char* allocation required) */
        const char *cmd[NUM_RECORDED_CMDS];
        /* strncpy() of the key sent */
        char key[NUM_RECORDED_CMDS][RECORDED_KEY_MAX_LEN];
        /* if restore cmd, then serialized size. Otherwise, set to 0 */
        size_t restoreSize[NUM_RECORDED_CMDS];
    } pendingCmds;

    RespReaderCtx respReader;
    RdbParser *p;
    int fd;
    int fdOwner; /* Set to 1 if this entity created the socket, and it is the one to release. */
};

/* cb to report RESP error. Returns 1 to propagate. 0 to mask. */
static int onReadRepliesErrorCb(void *context, char *msg) {
    RdbxRespToRedisLoader *ctx = context;

    int currIdx = ctx->respReader.countReplies % NUM_RECORDED_CMDS;

    /*
     * librdb should not fail trying to load empty module
     *
     * If RDB2RESP was configured to "supportRestoreModuleAux" and generates
     * RESTOREMODAUX commands (currently Redis enterprise only), then if RDB was
     * generated by a server with some module, but user didn't make any use of that
     * module, attempting to play it to another server that wasn't loaded with that
     * module, the RDB parser will fail. This is because the module always store
     * something in the AUX field, and the RDB parser will try to load it.
     *
     * In order to overcome this issue, A module that its AUX payload is less than
     * 15 Bytes (including RDB version and checksum) counted as AUX field of an empty
     * Module (not in use), then the parser, when restoring the empty module, it
     * should ignore returned error: "-ERR Module X not found..."
     */
    if ((strcmp(ctx->pendingCmds.cmd[currIdx], "RESTOREMODAUX")==0) &&
        (ctx->pendingCmds.restoreSize[currIdx] < 15) &&
        (strncmp(msg, "ERR Module", 10) == 0) && /* error starts with "-ERR Module" */
        (strstr(msg, "not found")))              /* error includes "not found" */
        return 0; /* mask error */

    char buf[9];
    RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_WRITE,
                    "\nerror from dst '-%s' on key '%s' on command '%s' (RESP Command #%zu)\n",
                    msg,
                    __RDB_key(ctx->p, ctx->pendingCmds.key[currIdx], buf),
                    ctx->pendingCmds.cmd[currIdx],
                    ctx->respReader.countReplies);

    return 1; /* propagate error */
}

/* Read 'numToRead' replies from the socket.
 *
 * numToRead - minimum number of replies to read from the socket before
 *                    returning.
 * sentError -        if set, an error occurred while writing to the server. In
 *                    this case the function will try to read replies from the
 *                    server. Maybe one of the replies will contain an error message
 *                    that explains why write got failed. Whether error message is
 *                    received or not, the function will return to the original issue.
 *
 * Return 0 for success, 1 otherwise. */
static int readReplies(RdbxRespToRedisLoader *ctx, int numToRead, int sentError) {
    int retries = 0;
    char buff[REPLY_BUFF_SIZE];

    RespReaderCtx *respReader = &ctx->respReader;
    size_t countRepliesBefore = respReader->countReplies;
    size_t repliesExpected = respReader->countReplies + numToRead;

    while ((respReader->countReplies < repliesExpected) || (sentError)) {
        int bytesReceived = recv(ctx->fd, buff, sizeof(buff), 0);

        if (bytesReceived > 0) {
            /* Data was received, process it */
            if (unlikely(RESP_REPLY_ERR == readRespReplies(respReader, buff, bytesReceived))) {
                return 1;
            }
            continue;
        }

        /* handle error */

        if (sentError)
            return 0; /* Done lookup for error message. Return to original issue */

        if (bytesReceived == 0) {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_CONN_CLOSE,
                            "Connection closed by the remote side");
            return 1;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                retries++;
                RDB_log(ctx->p, RDB_LOG_INF, 
                        "No reply from redis-server for %d seconds", 
                        retries * RECV_CMD_TIMEOUT_SEC);
                
                /* Parser got external error? Currently Used only for testing */
                if (RDB_getErrorCode(ctx->p) != RDB_OK)
                    return 1;
                
                continue;
            }

            RDB_reportError(ctx->p,
                            (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_READ,
                            "Failed to recv() from Redis server. errno=%d: %s",
                            errno, strerror(errno));
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
    ctx->pendingCmds.restoreSize[recordCmdEntry] = cmd->restoreSize;
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
        if (readReplies(ctx, 1 /* at least one */, 0))
            return 1;
    }

    if (startCmd) recordCommandSent(ctx, startCmd);

    while (1)
    {
        struct msghdr msg = { .msg_iov = iov, .msg_iovlen = iovCnt };
        writeResult = sendmsg(ctx->fd, &msg, MSG_NOSIGNAL /*Ignore SIGPIPE signal*/);

        /* check for error */
        if (unlikely(writeResult == -1)) {
            if (errno == EINTR) {
                if ((retries++) >= MAX_EINTR_RETRY) {
                    RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_WRITE,
                                    "Failed to write socket. Exceeded EINTR retry limit");
                    break;
                }
                continue;
            } else {
                RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_WRITE,
                                "Failed to write socket (errno=%d)", errno);
                break;
            }
        }

        /* crunch iov entries that were transmitted entirely */
        while ((iovCnt) && (iov->iov_len <= (size_t) writeResult)) {
            writeResult -= iov->iov_len;
            ++iov;
            --iovCnt;
        }

        /* if managed to send all iov entries */
        if (likely(iovCnt == 0)) {
            ctx->pendingCmds.num += endCmd;
            return 0;
        }

        /* Update pointed iov entry. Only partial of its data sent */
        iov->iov_len -= writeResult;
        iov->iov_base = (char *) iov->iov_base + writeResult;
    }

    /* Error occurred. Try to receive error msg from dst, which might explain
       why write got failed */
    readReplies(ctx, 0, 1/*sentError*/);
    return 1;
}

/* Flush the pending commands by reading the remaining replies.
 * Return 0 for success, 1 otherwise. */
static int redisLoaderFlush(void *context) {
    RdbxRespToRedisLoader *ctx = context;
    if (ctx->pendingCmds.num)
        return readReplies(ctx, ctx->pendingCmds.num, 0);
    return 0;
}

/* Delete the context and perform cleanup. */
static void redisLoaderDelete(void *context) {
    struct RdbxRespToRedisLoader *ctx = context;

    /* not required to flush on termination */

    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */

    if (ctx->fdOwner) close(ctx->fd);

    RDB_free(ctx->p, ctx);
}

static RdbRes redisAuthCustomized(RdbxRespToRedisLoader *ctx, RdbxRedisAuth *auth) {
    int i, iovs;
    RdbRes res = RDB_OK;

    /* custom auth command - Need to break it into tokens based on spaces and
    * tabs. And then translate it into RESP protocol */

    char prefix[32];

    RdbxRespWriterStartCmd startCmd = {"<AUTH_CUSTOMIZED_CMD>", "", 0};

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

    RdbxRespWriterStartCmd startCmd = {"AUTH", "", 0};

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

/* Create a loader from an existing file descriptor */
_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisFd(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            RdbxRedisAuth *auth,
                                                            int fd) {
    /* Ensure the socket is in blocking mode */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_CONF_BLOCK_SOCKET,
                        "Failed to configure for blocking mode. errno=%d: %s",
                        errno, strerror(errno));
        return NULL;
    }

    /* Set receive timeout (blocking, but with a limit) */
    struct timeval timeout = { .tv_sec = RECV_CMD_TIMEOUT_SEC, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_SET_TIMEOUT,
                        "Failed to configure for blocking mode. errno=%d: %s",
                        errno, strerror(errno));
        return NULL;
    }

    RdbxRespToRedisLoader *ctx = RDB_alloc(p, sizeof(RdbxRespToRedisLoader));
    if (!ctx) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_FAILED_ALLOC, "Failed to allocate struct RdbxRespToRedisLoader");
        return NULL;
    }

    memset(ctx, 0, sizeof(RdbxRespToRedisLoader));
    ctx->p = p;
    ctx->fd = fd;
    ctx->fdOwner = 0;
    ctx->pendingCmds.num = 0;
    ctx->pendingCmds.pipelineDepth = PIPELINE_DEPTH_DEF;
    readRespInit(&ctx->respReader);
    setErrorCb(&ctx->respReader, ctx, onReadRepliesErrorCb);

    if (auth && (redisAuth(ctx, auth) != RDB_OK)) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_AUTH_FAILED, "Redis authentication failed.");
        RDB_free(p, ctx);
        return NULL;
    }

    /* Set writer to rdbToResp */
    RdbxRespWriter inst = {ctx, redisLoaderDelete, redisLoaderWritev, redisLoaderFlush};
    RDBX_attachRespWriter(rdbToResp, &inst);
    return ctx;
}

/* Create a loader and establish a TCP connection */
_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                             RdbxToResp *rdbToResp,
                                                             RdbxRedisAuth *auth,
                                                             const char *hostname,
                                                             int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_CREATE_SOCKET, "Failed to create TCP socket");
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &(server_addr.sin_addr)) <= 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_INVALID_ADDRESS,
                        "Failed to convert IP address. inet_pton(hostname=%s, port=%d) => errno=%d",
                        hostname, port, errno);
        goto createErr;
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_CONNECT,
                        "Failed to connect(hostname=%s, port=%d) => errno=%d",
                        hostname, port, errno);
        goto createErr;
    }

    RdbxRespToRedisLoader *res = RDBX_createRespToRedisFd(p, rdbToResp, auth, sockfd);

    if (!res) goto createErr;

    res->fdOwner = 1;
    return res;

createErr:
    close(sockfd);
    return NULL;
}
