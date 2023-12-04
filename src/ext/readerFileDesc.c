#include <stdio.h>
#include <string.h>
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

        if (bytesRead == -1) {
            if (errno != EINTR) {
                RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                                "readFileDesc(): Read failed with errno=%d", errno);
                return RDB_STATUS_ERROR;
            }

            continue; /* If interrupted, retry the read */
        } else if (bytesRead == 0) {
            break;
        } else {
            totalBytesRead += bytesRead;
        }
    }

    if (totalBytesRead < len) {
        RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                        "readFileDesc(): Not all requested bytes were read");
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int fdCloseWhenDone) {
    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) RDB_alloc(p, sizeof(RdbxReaderFileDesc));
    ctx->parser = p;
    ctx->fd = fd;
    ctx->fdCloseWhenDone = fdCloseWhenDone;
    RDB_createReaderRdb(p, readFileDesc, ctx, deleteReaderFileDesc);
    return ctx;
}
