#include "common.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "readerResp.h"

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define PIPELINE_DEPTH_DEFAULT    200   /* Default Number of pending cmds before waiting for response(s) */
#define PIPELINE_DEPTH_MAX        1000  /* limit the max value allowed to configure for pipeline depth */

#define NUM_RECORDED_CMDS         400   /* Number of commands to backlog, in a cyclic array */
#define RECORDED_DATA_MAX_LEN     40    /* Maximum payload size from any command to record into cyclic array */

#define REPLY_BUFF_SIZE           4096  /* reply buffer size */


struct RdbxRespToTcpLoader {

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

/* Read 'numToRead' replies from the TCP socket.
 * Return 0 for success, 1 otherwise. */
static int readReplies(RdbxRespToTcpLoader *ctx, int numToRead) {
    char buff[REPLY_BUFF_SIZE];

    RespReaderCtx *respReader = &ctx->respReader;
    size_t countRepliesBefore = respReader->countReplies;
    size_t repliesExpected = respReader->countReplies + numToRead;

    while (respReader->countReplies < repliesExpected) {
        int rd = recv(ctx->fd, buff, sizeof(buff), 0);

        if (rd > 0) {
            /* Data was received, process it */
            if (RESP_REPLY_ERR == readRespReplies(respReader, buff, rd)) {
                RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_READ, respReader->errorMsg);
                return 1;
            }

        } else if (rd == 0) {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_CONN_CLOSE, "Connection closed by the remote side");
            return 1;
        } else {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_READ, "Failed to recv() from Redis server. Exit.");
            return 1;
        }
    }

    ctx->pendingCmds.num -= (respReader->countReplies - countRepliesBefore);
    return 0;
}

/* For debugging, record the command into the cyclic array before sending it */
static inline void recordNewCmd(RdbxRespToTcpLoader *ctx, const struct iovec *cmd_iov, int iovcnt) {
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

/* Write the vector of data to the TCP socket with writev() sys-call.
 * Return 0 for success, 1 otherwise. */
static int tcpLoaderWritev(void *context, const struct iovec *iov, int count, int startCmd, int endCmd) {
    UNUSED(startCmd, endCmd);

    RdbxRespToTcpLoader *ctx = context;

    if (unlikely(ctx->pendingCmds.num == ctx->pendingCmds.pipelineDepth)) {
        if (readReplies(ctx, 1 /* at least one */))
        return 1;
    }

    if (startCmd)
        recordNewCmd(ctx, iov, count);

    if (unlikely(writev(ctx->fd, iov, count) == -1)) {
        RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_WRITE, "Failed to write tcp socket");
        return 1;
    }

    ctx->pendingCmds.num += endCmd;
    return 0;
}

/* Flush the pending commands by reading the remaining replies.
 * Return 0 for success, 1 otherwise. */
static int tcpLoaderFlush(void *context) {
    RdbxRespToTcpLoader *ctx = context;
    if (ctx->pendingCmds.num)
        return readReplies(ctx, ctx->pendingCmds.num);
    return 0;
}

/* Delete the TCP loader context and perform cleanup. */
static void tcpLoaderDelete(void *context) {
    struct RdbxRespToTcpLoader *ctx = context;
    tcpLoaderFlush(ctx);
    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */
    close(ctx->fd);
    RDB_free(ctx->p, ctx);
}

/* Create and initialize the RdbxRespToTcpLoader context.
 * Return a pointer to the created context on success, or NULL on failure. */
_LIBRDB_API RdbxRespToTcpLoader *RDBX_createRespToTcpLoader(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            const char *hostname,
                                                            int port,
                                                            int pipelineDepth) {
    RdbxRespToTcpLoader *ctx;

    if (pipelineDepth <= 0 || pipelineDepth>PIPELINE_DEPTH_MAX)
        pipelineDepth = PIPELINE_DEPTH_DEFAULT;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2TCP_CREATE_SOCKET, "Failed to create tcp socket");
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &(server_addr.sin_addr)) <= 0) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2TCP_INVALID_ADDRESS,
                        "Invalid tcp address (hostname=%s, port=%d)", hostname, port);
        close(sockfd);
        return NULL;
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP2TCP_INVALID_ADDRESS,
                        "Invalid tcp address (hostname=%s, port=%d)", hostname, port);
        close(sockfd);
        return NULL;
    }

    if ((ctx = RDB_alloc(p, sizeof(RdbxRespToTcpLoader))) == NULL) {
        close(sockfd);
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_FAILED_ALLOC, "Failed to allocate struct RdbxRespToTcpLoader");
        return NULL;
    }

    memset(ctx, 0, sizeof(RdbxRespToTcpLoader));
    ctx->p = p;
    ctx->fd = sockfd;
    ctx->pendingCmds.num = 0;
    ctx->pendingCmds.pipelineDepth = pipelineDepth;
    readRespInit(&ctx->respReader);

    /* Attach this writer to rdbToResp */
    RdbxRespWriter inst = {ctx, tcpLoaderDelete, tcpLoaderWritev, tcpLoaderFlush};
    RDBX_attachRespWriter(rdbToResp, &inst);

    return ctx;
}
