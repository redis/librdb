#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
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
#define RECORDED_DATA_MAX_LEN     40    /* Maximum payload size from any command to record into cyclic array */

#define REPLY_BUFF_SIZE           4096  /* reply buffer size */

#define MAX_EINTR_RETRY          3


struct RdbxRespToRedisLoader {

    struct {
        int num;
        int pipelineDepth;
        char cmdPrefix[NUM_RECORDED_CMDS][RECORDED_DATA_MAX_LEN];
        int cmdAt;
    } pendingCmds;

    RespReaderCtx respReader;
    RdbParser *p;
    int fd;
};

static void onReadRepliesError(RdbxRespToRedisLoader *ctx) {
    RespReaderCtx *respReader = &ctx->respReader;
    int currIdx = ctx->respReader.countReplies % NUM_RECORDED_CMDS;
    char *currCmdRecord = ctx->pendingCmds.cmdPrefix[currIdx];

    /* Print also previous command if available. */
    if (ctx->respReader.countReplies > 1) {
        int prevIdx = (currIdx == 0) ? NUM_RECORDED_CMDS - 1 : currIdx - 1;
        char *prevCmdRecord = ctx->pendingCmds.cmdPrefix[prevIdx];
        RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_WRITE,
            "\nReceived Server error: \"%s\"\nGot failed on command [#%d] (First %d bytes):\n%s\n"
            "\nPreceding command [#%d] was: \n%s\n",
            respReader->errorMsg,
            ctx->respReader.countReplies,
            RECORDED_DATA_MAX_LEN,
            currCmdRecord,
            ctx->respReader.countReplies-1,
            prevCmdRecord);
    } else {
        RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_WRITE,
            "\nReceived Server error:\n\"%s\"\n\nGot failed on command [#%d] (First %d bytes):\n%s\n",
            respReader->errorMsg,
            ctx->respReader.countReplies,
            RECORDED_DATA_MAX_LEN,
            currCmdRecord);
    }
}

/* Read 'numToRead' replies from the socket.
 * Return 0 for success, 1 otherwise. */
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
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2REDIS_FAILED_READ, "Failed to recv() from Redis server. Exit.");
            return 1;
        }
    }

    ctx->pendingCmds.num -= (respReader->countReplies - countRepliesBefore);
    return 0;
}

/* For debugging, record the command into the cyclic array before sending it */
static inline void recordNewCmd(RdbxRespToRedisLoader *ctx, const struct iovec *cmd_iov, int iovcnt) {
    int recordCmdEntry = (ctx->respReader.countReplies + ctx->pendingCmds.num) % NUM_RECORDED_CMDS;
    char *recordCmdPrefixAt = ctx->pendingCmds.cmdPrefix[recordCmdEntry];

    int copiedBytes = 0, bytesToCopy = RECORDED_DATA_MAX_LEN - 1;

    const struct iovec* currentIov = cmd_iov;
    for (int i = 0; i < iovcnt && bytesToCopy; ++i) {
        int slice = (currentIov->iov_len >= ((size_t)bytesToCopy)) ? bytesToCopy : (int) currentIov->iov_len;

        for (int j = 0 ; j < slice ; )
            recordCmdPrefixAt[copiedBytes++] = ((char *)currentIov->iov_base)[j++];

        bytesToCopy -= slice;
        ++currentIov;
    }
    recordCmdPrefixAt[copiedBytes] = '\0';
}

/* Write the vector of data to the socket with writev() sys-call.
 * Return 0 for success, 1 otherwise. */
static int redisLoaderWritev(void *context, struct iovec *iov, int iovCnt, int startCmd, int endCmd) {
    ssize_t writeResult;
    int retries = 0;

    RdbxRespToRedisLoader *ctx = context;

    if (unlikely(ctx->pendingCmds.num == ctx->pendingCmds.pipelineDepth)) {
        if (readReplies(ctx, 1 /* at least one */))
            return 1;
    }

    if (startCmd)
        recordNewCmd(ctx, iov, iovCnt);

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

_LIBRDB_API void RDBX_setPipelineDepth(RdbxRespToRedisLoader *r2r, int depth) {
    r2r->pendingCmds.pipelineDepth = (depth <= 0 || depth>PIPELINE_DEPTH_MAX) ? PIPELINE_DEPTH_DEF : depth;
}

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisFd(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            int fd)
{
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

        /* Set 'this' writer to rdbToResp */
        RdbxRespWriter inst = {ctx, redisLoaderDelete, redisLoaderWritev, redisLoaderFlush};
        RDBX_attachRespWriter(rdbToResp, &inst);
        return ctx;
}

_LIBRDB_API RdbxRespToRedisLoader *RDBX_createRespToRedisTcp(RdbParser *p,
                                                             RdbxToResp *rdbToResp,
                                                             const char *hostname,
                                                             int port) {
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
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

    return RDBX_createRespToRedisFd(p, rdbToResp, sockfd);
}
