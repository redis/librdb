#include <stdio.h>
#include <stdlib.h>
#include "common.h"

struct RdbxRespFileWriter {
    long cmdCount;
    RdbParser *p;
    FILE* filePtr;   /* either stdout or pointer to open file */
};

size_t respFileWrite(void *context, char *str, int len, int endCmd) {
    struct RdbxRespFileWriter *ctx = (RdbxRespFileWriter *) context;
    ctx->cmdCount += endCmd;
    return fwrite(str, sizeof(char), len, ctx->filePtr);
}

size_t respFileWriteBulk(void *context, RdbBulk b, int endCmd) {
    struct RdbxRespFileWriter *ctx = (RdbxRespFileWriter *) context;
    UNUSED(endCmd);
    return fwrite(b, sizeof(char), RDB_bulkLen(ctx->p, b), ctx->filePtr);
}

void respFileWriteDelete(void *context) {
    struct RdbxRespFileWriter *ctx = (RdbxRespFileWriter *) context;
    if (ctx != NULL) {
        if (ctx->filePtr != stdout) {
            fclose(ctx->filePtr);
        }
        RDB_free(ctx->p, ctx);
    }
}

long RDBX_getRespFileWriterCmdCount(RdbxRespFileWriter *wr) {
    return wr->cmdCount;
}

RdbxRespFileWriter *RDBX_createRespFileWriter(RdbParser *p, RdbxToResp *rdbToResp, const char* filePath) {
    RdbxRespFileWriter *ctx;
    FILE* filePtr;

    if (filePath == NULL) {
        filePtr = stdout;
    } else {
        filePtr = fopen(filePath, "w");
        if (filePtr == NULL) {
            RDB_reportError(p, (RdbRes) RDBX_ERR_FAILED_OPEN_FILE, "createRespWriter: Failed to open file: %s", filePath);
            return NULL;
        }
    }

    if ((ctx = RDB_alloc(p, sizeof(RdbxRespFileWriter))) == NULL) {
        fclose(filePtr);
        RDB_reportError(p, (RdbRes) RDBX_ERR_RESP_FAILED_ALLOC, "Failed to allocate RdbxRespFileWriter");
        return NULL;
    }

    ctx->cmdCount = 0;
    ctx->filePtr = filePtr;
    ctx->p = p;

    /* Attach this writer to rdbToResp */
    RdbxRespWriter writer = {ctx, respFileWrite, respFileWriteBulk, respFileWriteDelete};
    RDB_attachRespWriter(rdbToResp, &writer);
    return ctx;
}

