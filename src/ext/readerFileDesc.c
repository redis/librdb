#define _POSIX_C_SOURCE 1 /* Required in order to use file-descriptors */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "common.h"


struct RdbxReaderFileDesc {
    RdbParser *parser;
    int fdCloseWhenDone;
    int fd;
    FILE *file;
};

static void deleteReaderFileDesc(RdbParser *p, void *rdata) {
    if (!rdata) return;

    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) rdata;
    if (ctx->file)
        fclose(ctx->file);

    if (ctx->fdCloseWhenDone)
        close(ctx->fd);
    RDB_free(p, ctx);
}

/* Attempts to read entire len, otherwise returns error */
static RdbStatus readFileDesc(void *data, void *buf, size_t len) {
    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *)data;
    size_t totalBytesRead = 0;

    while (1) {
        totalBytesRead += fread((char *)buf + totalBytesRead, 1, len - totalBytesRead, ctx->file);

        if (totalBytesRead == len) {
            return RDB_STATUS_OK;
        } else {
            if (feof(ctx->file)) {
                RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                    "readFileDesc(fd=%d): Reached EOF. Not all requested bytes were read", ctx->fd);
                return RDB_STATUS_ERROR;
            } else if (ferror(ctx->file)) {
                /* Wrongly configured to nonblocking mode (Not supported at the moment) */
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    RDB_reportError(ctx->parser, RDB_ERR_NONBLOCKING_READ_FD,
                        "readFileDesc(fd=%d): Unexpected EAGAIN|EWOULDBLOCK. The fd must be set to blocking mode", ctx->fd);
                    return RDB_STATUS_ERROR;
                }

                RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                    "readFileDesc(fd=%d): System errno %d : %s", ctx->fd, errno, strerror(errno));
                return RDB_STATUS_ERROR;
            }
        }
    }
}

RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int fdCloseWhenDone) {

    int flags = fcntl(fd, F_GETFL);

    if (flags==-1) {

        RDB_reportError(p, RDB_ERR_FAILED_GET_FD_FLAGS,
            "RDBX_createReaderFileDesc(fd=%d): Failed to get fcntl(). Error:%s", fd, strerror(errno));
        return NULL;
    }

    if (flags & O_NONBLOCK) {
        RDB_reportError(p, RDB_ERR_NONBLOCKING_FD,
            "RDBX_createReaderFileDesc(fd=%d): fd must be set to blocking mode", fd);
        return NULL;
    }

    FILE *file = fdopen(fd, "r");

    if (file == NULL) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_FILE,
        "RDBX_createReaderFileDesc(fd=%d): failed on fdopen() with errno %d: %s\"",
            fd, errno, strerror(errno));
        return NULL;
    }

    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) RDB_alloc(p, sizeof(RdbxReaderFileDesc));
    ctx->parser = p;
    ctx->fd = fd;
    ctx->file = file;
    ctx->fdCloseWhenDone = fdCloseWhenDone;
    RDB_createReaderRdb(p, readFileDesc, ctx, deleteReaderFileDesc);
    return ctx;
}
