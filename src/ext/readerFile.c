#include <stdio.h>
#include <string.h>
#include <errno.h>
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
    size_t readLen = fread(buf, sizeof(char), len, readerFile->file);

    if (likely(readLen == len))
        return RDB_STATUS_OK;

    if (feof(readerFile->file)) {
        RDB_reportError(readerFile->parser, RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE,
                        "Encountered an unexpected RDB end-of-file. Parsing halted.");
    } else if (ferror(readerFile->file)) {
        RDB_reportError(readerFile->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                        "An error occurred while attempting to read the RDB file (errno=%d).", errno);
    } else { /* readLen < len */
        RDB_reportError(readerFile->parser, RDB_ERR_FAILED_READ_RDB_FILE,
                        "The amount of data read from the RDB file was less than expected. Reached EOF.");
    }
    return RDB_STATUS_ERROR;
}

RdbxReaderFile *RDBX_createReaderFile(RdbParser *p, const char *filename) {
    FILE *f;

    if (filename == NULL) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_RDB_FILE,
                        "Filename is not provided", filename);
        return NULL;
    }

    if (!(f = fopen(filename, "rb"))) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_RDB_FILE,
                        "Failed to open RDB file `%s`: %s\n", filename, strerror(errno));
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
