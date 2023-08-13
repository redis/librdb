#include <stdio.h>
#include <string.h>
#include "common.h"

struct RdbxReaderFile {
    RdbParser *parser;
    char *filename;
    FILE *file;
};

static void deleteReaderFile(RdbParser *p, void *rdata) {
    if (!rdata) return;
    RdbxReaderFile *readerData = (RdbxReaderFile *) rdata;

    RDB_log(p, RDB_LOG_DBG, "RDB Reader: Closing file %s", readerData->filename);

    if (readerData->filename)
        RDB_free(p, readerData->filename);

    if(readerData->file)
        fclose(readerData->file);

    RDB_free(p, readerData);
}

static RdbStatus readFile(void *data, void *buf, size_t len) {
    RdbxReaderFile *readerFile = data;
    size_t newLen = fread(buf, sizeof(char), len, readerFile->file);
    if (ferror( readerFile->file) != 0) {
        RDB_reportError(readerFile->parser, RDB_ERR_FAILED_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    if (newLen != len) {
        RDB_reportError(readerFile->parser, RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbxReaderFile *RDBX_createReaderFile(RdbParser *p, const char *filename) {
    FILE *f;

    if (filename == NULL) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_RDB_FILE,
                        "Filename is not provided", filename);
        return NULL;
    }

    if (!(f = fopen(filename, "rb"))) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_RDB_FILE, "Failed to open RDB file: %s", filename);
        return NULL;
    }

    RDB_log(p, RDB_LOG_INF, "RDBX_createReaderFile: Initialized with file %s", filename);

    RdbxReaderFile *ctx = RDB_alloc(p, sizeof(RdbxReaderFile));
    ctx->parser = p;
    ctx->file = f;
    ctx->filename = RDB_alloc(p, strlen(filename) + 1);
    strcpy(ctx->filename, filename);
    RDB_createReaderRdb(p, readFile, ctx, deleteReaderFile);
    return ctx;
}
