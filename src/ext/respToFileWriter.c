#include <stdio.h>
#include "common.h"
#include <string.h>
#include <errno.h>

struct RdbxRespToFileWriter {
    long cmdCount;
    RdbParser *p;
    FILE *filePtr;   /* either stdout or pointer to open file */
};

/* return 0 for success. 1 Otherwise. */
static int respFileWritev(void *context, struct iovec *iov, int count,
        RdbxRespWriterStartCmd *startCmd, int endCmd)
{
    UNUSED(startCmd);
    struct RdbxRespToFileWriter *ctx = context;
    ctx->cmdCount += endCmd;

    /* not optimized code */
    for (int i = 0 ; i < count ; ++i) {
        if (unlikely(fwrite(iov[i].iov_base, sizeof(char), iov[i].iov_len, ctx->filePtr) != iov[i].iov_len)) {
            RDB_reportError(ctx->p, (RdbRes) RDBX_ERR_RESP_WRITE, "Failed to write RESP to file: (errno=%d)", errno);
            return 1;
        }
    }

    return 0;
}

/* return 0 for success. 1 Otherwise. */
static int respFileFlush(void *context) {
    struct RdbxRespToFileWriter *ctx = context;
    return (EOF == fflush(ctx->filePtr)) ? 1 : 0;
}

static void respFileWriteDelete(void *context) {
    struct RdbxRespToFileWriter *ctx = context;
    if (ctx != NULL) {
        fflush(ctx->filePtr);
        if (ctx->filePtr != stdout) {
            fclose(ctx->filePtr);
        }
        RDB_free(ctx->p, ctx);
    }
}

RdbxRespToFileWriter *RDBX_createRespToFileWriter(RdbParser *p, RdbxToResp *rdbToResp, const char *filePath) {
    RdbxRespToFileWriter *ctx;
    FILE *filePtr;

    if (filePath == NULL) {
        filePtr = stdout;
    } else {
        filePtr = fopen(filePath, "wb");
        if (filePtr == NULL) {
            RDB_reportError(p, RDB_ERR_FAILED_OPEN_FILE, "createRespWriter: Failed to open file: %s. errno:%d",
                            filePath, errno);
            return NULL;
        }
    }

    if ((ctx = RDB_alloc(p, sizeof(RdbxRespToFileWriter))) == NULL) {
        fclose(filePtr);
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_FAILED_ALLOC, "Failed to allocate struct RdbxRespToFileWriter");
        return NULL;
    }

    ctx->cmdCount = 0;
    ctx->filePtr = filePtr;
    ctx->p = p;

    /* Attach this writer to rdbToResp */
    RdbxRespWriter writer = {ctx, respFileWriteDelete, respFileWritev, respFileFlush};
    RDBX_attachRespWriter(rdbToResp, &writer);
    return ctx;
}
