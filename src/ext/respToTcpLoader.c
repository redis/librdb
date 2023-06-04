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

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define NUM_PENDING_CMDS_HIGH_THRESHOLD 200
#define NUM_PENDING_CMDS_LOW_THRESHOLD  100

struct RdbxRespToTcpLoader {

    struct {
        int num;
        int highThreshold;
        int lowThreshold;
    } pendingCmds;

    size_t sentCmds;

    RdbParser *p;
    int fd;
};

/* return 0 for success. 1 Otherwise. */
int readReplies(RdbxRespToTcpLoader *ctx, int numToRead) {
    char buffer[2048];
    int numRead = 0;

    while (numRead < numToRead) {
        /* Read a single-line reply into the buffer */
        ssize_t bytesRead = read(ctx->fd, buffer, sizeof(buffer) - 1);

        /* TODO: Check responses for errors. */
        /* TODO: Record pending commands in case of failure */
        if (bytesRead > 0) {
            /* Iterate through the read bytes to find the end of the lines */
            for (int i = 0; i < bytesRead; i++) {
                if (buffer[i] == '\n') {
                    numRead++;
                }
            }
        } else {
            //
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_READ,
                            "Failed to read responses from socket.");
            ctx->pendingCmds.num -= numRead;
            return 1;
        }
    }
    ctx->pendingCmds.num -= numRead;
    return 0;
}

/* return 0 for success. 1 Otherwise. */
int tcpLoaderFlush(void *context) {
    RdbxRespToTcpLoader *ctx = context;
    if (ctx->pendingCmds.num)
        return readReplies(ctx, ctx->pendingCmds.num);
    return 0;
}

/* return 0 for success. 1 Otherwise. */
int tcpLoaderWritev(void *context, const struct iovec *iov, int count, uint64_t bulksBitmask, int endCmd) {
    UNUSED(endCmd);
    UNUSED(bulksBitmask);
    RdbxRespToTcpLoader *ctx = context;
    if (unlikely(writev(ctx->fd, iov, count) == -1)) {
        RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP2TCP_FAILED_WRITE, "Failed to write tcp socket");
        return 1;
    }

    ctx->pendingCmds.num += endCmd;
    ctx->sentCmds += endCmd;

    /* read replies if crosses high threshold of number pending commands till reach low threshold */
    if (unlikely(ctx->pendingCmds.num >= ctx->pendingCmds.highThreshold)) {
        return readReplies(ctx, ctx->pendingCmds.num - ctx->pendingCmds.lowThreshold);
    }
    return 0;
}

void tcpLoaderDelete(void *context) {
    struct RdbxRespToTcpLoader *ctx = context;
    tcpLoaderFlush(ctx);
    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */
    close(ctx->fd);
    RDB_free(ctx->p, ctx);
}

_LIBRDB_API RdbxRespToTcpLoader *RDBX_createRespToTcpLoader(RdbParser *p,
                                                            RdbxToResp *rdbToResp,
                                                            const char *hostname,
                                                            int port) {
    RdbxRespToTcpLoader *ctx;

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
    ctx->pendingCmds.highThreshold = NUM_PENDING_CMDS_HIGH_THRESHOLD;
    ctx->pendingCmds.lowThreshold = NUM_PENDING_CMDS_LOW_THRESHOLD;
    ctx->sentCmds = 0;

    /* Attach this writer to rdbToResp */
    RdbxRespWriter inst = {ctx, tcpLoaderDelete, tcpLoaderWritev, tcpLoaderFlush};
    RDBX_attachRespWriter(rdbToResp, &inst);

    return ctx;
}
