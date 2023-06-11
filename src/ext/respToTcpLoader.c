/*
 * Very naive respToTcpLoader block. It plays RESP against live Redis but does not check responses.
 * Sufficient for a start to extend the tests to be able to run against external redis server.
 * This block can be implemented in various ways, such as, async support, writev, buffering, etc.
 */
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

#define NUM_PENDING_CMDS_HIGH_THD 200
#define NUM_PENDING_CMDS_LOW_THD  100

#define NUM_RECORDED_CMDS         400
#define RECORDED_MAX_SIZE         40
#define REPLY_BUFF_SIZE           4096

#define INITIAL_DELAY_USEC        20
#define MAX_RETRIES               6

struct RdbxRespToTcpLoader {

    struct {
        int num;
        int highThreshold;
        int lowThreshold;

        char cmdPrefix[NUM_RECORDED_CMDS][RECORDED_MAX_SIZE];
        int cmdAt;
    } pendingCmds;

    struct {
        size_t nResponses;
        size_t nErrors;
    } protocol;

    size_t sentCmds;

    RdbParser *p;
    int fd;
};

/* return 0 for success. 1 Otherwise. */
static int readReplies(RdbxRespToTcpLoader *ctx, int numToRead) {
    char buff[REPLY_BUFF_SIZE];
    RespReaderCtx respCtx;
    readRespInit(&respCtx);

    int retries = 0;
    int delayUs = INITIAL_DELAY_USEC;

    while ((int)respCtx.countReplies < numToRead) {
        int rd = recv(ctx->fd, buff, sizeof(buff), MSG_DONTWAIT);

        if (rd > 0) {
            /* Data was received, process it */
            if (RESP_REPLY_ERR == readRespReplies(&respCtx, buff, rd)) {
                RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_READ, respCtx.errorMsg);
                return 1;
            }

        } else if (rd == 0) {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_CONN_CLOSE, "Connection closed by the remote side");
            return 1;
        } else {
            /* Error occurred or no data available */
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                /* No data available, retry after delay */
                if (retries >= MAX_RETRIES) {
                    RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_MAX_RETRIES, "Maximum number of retries reached. Exit.");
                    return 1;
                }
                usleep(delayUs);
                delayUs *= 2;  /* Double the delay for each retry */
                retries++;
            } else {
                RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_READ, "Failed to recv() from Redis. Exit.");
                return 1;
            }
        }
    }

    ctx->protocol.nResponses += respCtx.countReplies;
    ctx->pendingCmds.num -= respCtx.countReplies;
    return 0;
}

static inline void recordNewCmd(RdbxRespToTcpLoader *ctx, const struct iovec *iov, int iovcnt) {
    int recordCmdEntry = (ctx->sentCmds + ctx->pendingCmds.num) % NUM_RECORDED_CMDS;
    char *recordCmdPrefixAt = ctx->pendingCmds.cmdPrefix[recordCmdEntry];

    int copiedBytes = 0, bytesToCopy = RECORDED_MAX_SIZE - 1;

    const struct iovec* currentIov = iov;
    for (int i = 0; i < iovcnt && bytesToCopy; ++i) {
        int slice = (currentIov->iov_len >= ((size_t)bytesToCopy)) ? bytesToCopy : (int) currentIov->iov_len;

        for (int j = 0 ; j < slice ; )
            recordCmdPrefixAt[copiedBytes++] = ((char *)currentIov->iov_base)[j++];

        bytesToCopy -= slice;
        ++currentIov;
    }
    recordCmdPrefixAt[copiedBytes] = '\0';
}

/* return 0 for success. 1 Otherwise. */
static int tcpLoaderWritev(void *context, const struct iovec *iov, int count, int startCmd, int endCmd) {
    UNUSED(startCmd, endCmd);

    RdbxRespToTcpLoader *ctx = context;

    /* read replies if crosses high threshold of number pending commands till reach low threshold */
    if (unlikely(ctx->pendingCmds.num == ctx->pendingCmds.highThreshold)) {
        if (readReplies(ctx, ctx->pendingCmds.num - ctx->pendingCmds.lowThreshold))
        return 1;
    }

    if (startCmd)
        recordNewCmd(ctx, iov, count);

    if (unlikely(writev(ctx->fd, iov, count) == -1)) {
        RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_WRITE, "Failed to write tcp socket");
        return 1;
    }

    ctx->pendingCmds.num += endCmd;
    ctx->sentCmds += endCmd;

    return 0;
}

/* return 0 for success. 1 Otherwise. */
static int tcpLoaderFlush(void *context) {
    RdbxRespToTcpLoader *ctx = context;
    if (ctx->pendingCmds.num)
        return readReplies(ctx, ctx->pendingCmds.num);
    return 0;
}

static void tcpLoaderDelete(void *context) {
    struct RdbxRespToTcpLoader *ctx = context;
    tcpLoaderFlush(ctx);
    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */
    close(ctx->fd);
    RDB_free(ctx->p, ctx);
}

_LIBRDB_API RdbxRespToTcpLoader *RDBX_createRespToTcpLoader(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            const char *hostname,
                                                            int port,
                                                            int pipelineDepth) {
    RdbxRespToTcpLoader *ctx;

    if (pipelineDepth <= 0 || pipelineDepth>NUM_PENDING_CMDS_HIGH_THD)
        pipelineDepth = NUM_PENDING_CMDS_HIGH_THD;

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
    ctx->pendingCmds.highThreshold = pipelineDepth;
    ctx->pendingCmds.lowThreshold = (pipelineDepth/2);
    ctx->sentCmds = 0;

    /* Attach this writer to rdbToResp */
    RdbxRespWriter inst = {ctx, tcpLoaderDelete, tcpLoaderWritev, tcpLoaderFlush};
    RDBX_attachRespWriter(rdbToResp, &inst);

    return ctx;
}
