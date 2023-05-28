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

struct RdbxRespToTcpLoader {
    RdbParser *p;
    int fd;
};

void tcpLoaderDelete(void *context) {
    struct RdbxRespToTcpLoader *ctx = context;
    shutdown(ctx->fd, SHUT_WR); /* graceful shutdown */
    close(ctx->fd);
    RDB_free(ctx->p, ctx);
}

size_t tcpLoaderWrite(void *context, char *str, int len, int endCmd) {
    UNUSED(endCmd);
    RdbxRespToTcpLoader *ctx = context;
    return write(ctx->fd, str, len);
}

size_t tcpLoaderWriteBulk(void *context, RdbBulk b, int endCmd) {
    UNUSED(endCmd);
    struct RdbxRespToTcpLoader *ctx = context;
    return write(ctx->fd, b, RDB_bulkLen(ctx->p, b));
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

    ctx->p = p;
    ctx->fd = sockfd;

    /* Attach this writer to rdbToResp */
    RdbxRespWriter inst = {ctx, tcpLoaderWrite, tcpLoaderWriteBulk, tcpLoaderDelete};
    RDBX_attachRespWriter(rdbToResp, &inst);

    return ctx;
}
