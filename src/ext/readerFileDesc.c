#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include "common.h"

struct RdbxReaderFileDesc {
    RdbParser *parser;
    int fdCloseWhenDone;
    int fd;
};

static void deleteReaderFileDesc(RdbParser *p, void *rdata) {
    if (!rdata) return;

    RdbxReaderFileDesc *readerData = (RdbxReaderFileDesc *) rdata;
    if (readerData->fdCloseWhenDone)
        close(readerData->fd);
    RDB_free(p, readerData);
}

/* Attempts to read entire len, otherwise returns error */
static RdbStatus readFileDesc(void *data, void *buf, size_t len) {
    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *)data;
    size_t totalBytesRead = 0;

    while (totalBytesRead < len) {
        ssize_t bytesRead = read(ctx->fd, (char *)buf + totalBytesRead, len - totalBytesRead);

        /* read some data */
        if (likely(bytesRead > 0)) {
            totalBytesRead += bytesRead;
            continue;
        }

        /* didn't read any data. Stop. */
        if (bytesRead == 0) {
            break;
        }

        assert(bytesRead == -1);

        /* If interrupted, retry read */
        if (errno == EINTR)
            continue;

        /* Wrongly configured to nonblocking mode (Not supported at the moment) */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            RDB_reportError(ctx->parser, RDB_ERR_NONBLOCKING_READ_FD,
                            "readFileDesc(): Unexpected EAGAIN|EWOULDBLOCK. The fd must be set to blocking mode");
            return RDB_STATUS_ERROR;
        }

        RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                        "readFileDesc(): Read failed with errno=%d", errno);
        return RDB_STATUS_ERROR;
    }

    if (totalBytesRead < len) {
        RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                        "readFileDesc(): Not all requested bytes were read");
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int fdCloseWhenDone) {

    int flags = fcntl(fd, F_GETFL);

    if (flags==-1) {

        RDB_reportError(p, RDB_ERR_FAILED_GET_FD_FLAGS,
            "RDBX_createReaderFileDesc(): Error getting file descriptor flags");
        return NULL;
    }

    if (flags & O_NONBLOCK) {
        RDB_reportError(p, RDB_ERR_NONBLOCKING_FD,
            "RDBX_createReaderFileDesc(): fd must be set to blocking mode");
        return NULL;
    }

    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) RDB_alloc(p, sizeof(RdbxReaderFileDesc));
    ctx->parser = p;
    ctx->fd = fd;
    ctx->fdCloseWhenDone = fdCloseWhenDone;
    RDB_createReaderRdb(p, readFileDesc, ctx, deleteReaderFileDesc);
    return ctx;
}
