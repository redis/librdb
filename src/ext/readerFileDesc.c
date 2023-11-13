#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

struct RdbxReaderFileDesc {
    RdbParser *parser;
    int fdClloseWhenDone;
    int fd;
};

static void deleteReaderFileDesc(RdbParser *p, void *rdata) {
    if (!rdata) return;

    RdbxReaderFileDesc *readerData = (RdbxReaderFileDesc *) rdata;
    if (readerData->fdClloseWhenDone)
        close(readerData->fd);
    RDB_free(p, readerData);
}

static RdbStatus readFileDesc(void *data, void *buf, size_t len) {

    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) data;
    ssize_t bytesRead = read(ctx->fd, buf, len);
    if (bytesRead == -1) {
        RDB_reportError(ctx->parser, RDB_ERR_FAILED_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbxReaderFileDesc *RDBX_createReaderFileDesc(RdbParser *p, int fd, int fdCloseWhenDone) {
    RdbxReaderFileDesc *ctx = (RdbxReaderFileDesc *) RDB_alloc(p, sizeof(RdbxReaderFileDesc));
    ctx->parser = p;
    ctx->fd = fd;
    ctx->fdClloseWhenDone = fdCloseWhenDone;
    RDB_createReaderRdb(p, readFileDesc, ctx, deleteReaderFileDesc);
    return ctx;
}
