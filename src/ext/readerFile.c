#include <stdio.h>
#include <string.h>
#include "common.h"

typedef struct RdbReaderFile {
    char *filename;
    FILE *file;
} RdbReaderFile;

static void deleteReaderFile(RdbParser *p, void *rdata) {
    if (!rdata) return;

    RdbReaderFile *readerData = (RdbReaderFile *) rdata;
    if (readerData->filename) RDB_free(p, readerData->filename);
    if(readerData->file) fclose(readerData->file);
    RDB_free(p, readerData);
}

static RdbStatus readFile(RdbParser *p, void *data, void *buf, size_t len) {
    UNUSED(p);

    RdbReaderFile *readerFile = (RdbReaderFile *) data;
    size_t newLen = fread(buf, sizeof(char), len, readerFile->file);
    if (ferror( readerFile->file) != 0) {
        RDB_reportError(p, RDB_ERR_FAILED_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    if (newLen != len) {
        RDB_reportError(p, RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE, NULL);
        return RDB_STATUS_ERROR;
    }

    return RDB_STATUS_OK;
}

RdbReader *RDBX_createReaderFile(RdbParser *p, const char *filename) {
    FILE *f;

    if (!(f = fopen(filename, "rb"))) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_RDB_FILE,
                           "Failed to open RDB file: %s", filename);
        return NULL;
    }

    RDB_log(p, RDB_LOG_INFO, "RDBX_createReaderFile: Initialized with file %s", filename);

    RdbReaderFile *readerFileData = (RdbReaderFile *) RDB_alloc(p, sizeof(RdbReaderFile));
    readerFileData->file = f;
    readerFileData->filename = RDB_alloc(p, strlen(filename)+1);
    strcpy(readerFileData->filename, filename);
    return RDB_createReaderRdb(p, readFile, readerFileData, deleteReaderFile);
}

RdbReader *RDBX_createReaderSocket(int fd) {
    UNUSED(fd);
    return NULL;
}