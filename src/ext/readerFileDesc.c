#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

struct RdbxReaderFileDesc {
    int fd;
};

static void deleteReaderFileDesc(RdbParser *p, void *rdata) {
    if (!rdata) return;

    RdbxReaderFileDesc *readerData = (RdbxReaderFileDesc *) rdata;
    close(readerData->fd);
    RDB_free(p, readerData);
}

static RdbStatus readFileDesc(RdbParser *p, void *data, void *buf, size_t len) {
    UNUSED(p);

    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) data;
    ssize_t bytesRead = read(ctx->fd, buf, len);
    if (bytesRead == -1) {
        RDB_reportError(p, RDB_ERR_FAILED_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int closeWhenDone) {
    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) RDB_alloc(p, sizeof(RdbxReaderFileDesc));
    ctx->fd = fd;
    RDB_createReaderRdb(p, readFileDesc, ctx, (closeWhenDone) ? deleteReaderFileDesc : NULL);
    return ctx;
}
