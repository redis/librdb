#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "test_common.h"

char* sanitizeFile(char* str) {
    int i, j;
    int len = strlen(str);
    char* output = str;

    for (i = 0, j = 0; i < len; i++) {
        if ((str[i] != ' ')&&(str[i] != '\n')) {
            output[j++] = str[i];
        }
    }
    output[j] = '\0';
    return output;
}

void assert_payload_file(const char *filename, char *expPayload, int sanitize) {
    FILE* fp;
    char* str;
    size_t size;

    assert_non_null(fp = fopen(filename, "r"));

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek (fp, 0, SEEK_SET);
    assert_non_null(str = (char*) malloc(size + 1));

    size_t readBytes = fread(str, 1, size, fp);
    assert_int_equal(readBytes, size);

    str[size] = '\0';
    fclose(fp);

    if (sanitize)
        assert_string_equal( sanitizeFile(expPayload) , sanitizeFile(str));
    else
        assert_string_equal(expPayload, str);
    free(str);
}

void readFileToBuff(const char* filename, unsigned char** buffer, size_t* length) {
    long file_size = 0;
    FILE* file = fopen(filename, "rb");
    assert_non_null(file);
    assert_int_equal(fseek(file, 0, SEEK_END), 0);
    file_size = ftell(file);
    assert_int_not_equal(file_size, -1);
    assert_int_equal(fseek(file, 0, SEEK_SET), 0);
    *buffer = (unsigned char*)malloc(file_size);
    assert_int_equal(fread(*buffer, 1, file_size, file), file_size);
    *length = file_size;
    fclose(file);
}

/* Test different use cases to convert given rdb file to json:
 * 1. RDB_parse - parse with RDB reader
 * 2. RDB_parse - set pause-interval to 1 byte
 * 3. RDB_parseBuff - parse buffer. Use buffer of size 1 char
 * 4. RDB_parseBuff - parse a single buffer. set pause-interval to 1 byte
 *
 * All those tests will be wrapped with a loop that will test it each time with a different
 * bulk allocation type (bulkAllocType) this includes allocating from stack, heap, external,
 * or optimized-external allocation mode.
 */
void testRdbToJsonVariousCases(const char *rdbfile,
                      const char *jsonfile,
                      char *expJson,
                      RdbHandlersLevel parseLevel)
{

    for (int type = 0 ; type <= RDB_BULK_ALLOC_MAX ; ++type) {
        unsigned char *buffer;
        size_t bufLen;
        RdbStatus  status;
        RdbMemAlloc memAlloc = {xmalloc, xrealloc, xfree, type, {xmalloc, xclone, xfree}};
        RdbMemAlloc *pMemAlloc = (type != RDB_BULK_ALLOC_MAX) ? &memAlloc : NULL;

        /* read file to buffer for testing RDB_parseBuff() */
        readFileToBuff(rdbfile, &buffer, &bufLen);

        /*** 1. RDB_parse - parse with RDB reader ***/
        remove(jsonfile);
        RdbParser *parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, RDBX_CONV_JSON_ENC_PLAIN, jsonfile, parseLevel));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
        assert_payload_file(jsonfile, expJson, 1);

        /*** 2. RDB_parse - set pause-interval to 1 byte ***/
        int looseCounterAssert = 0;
        long countPauses = 0;
        size_t lastBytes = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, RDBX_CONV_JSON_ENC_PLAIN, jsonfile, parseLevel));
        RDB_setPauseInterval(parser, 1 /*bytes*/);
        while (1) {
            status = RDB_parse(parser);
            if (status == RDB_STATUS_WAIT_MORE_DATA) {
                looseCounterAssert = 1;
                continue;
            }
            if (status == RDB_STATUS_PAUSED) {
                ++countPauses;
                continue;
            }
            assert_int_equal(status, RDB_STATUS_OK);
            break;
        }
        /* If recorded WAIT_MORE_DATA, it will mess a little our countPauses evaluation.
         * When parser reach WAIT_MORE_DATA together with STATUS_PAUSED, then it
         * will prefer to return WAIT_MORE_DATA */
        if (looseCounterAssert)
            assert_true(countPauses > (((long) bufLen) / 2));
        else
            assert_int_equal(countPauses + 1, bufLen);
        RDB_deleteParser(parser);
        assert_payload_file(jsonfile, expJson, 1);

        /*** 3. RDB_parseBuff - parse buffer. Use buffer of size 1 char ***/
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createHandlersToJson(parser, RDBX_CONV_JSON_ENC_PLAIN, jsonfile, parseLevel));
        parseBuffOneCharEachTime(parser, buffer, bufLen, 1);
        RDB_deleteParser(parser);
        assert_payload_file(jsonfile, expJson, 1);

        /*** 4. RDB_parseBuff - parse a single buffer. set pause-interval to 1 byte ***/
        countPauses = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createHandlersToJson(parser, RDBX_CONV_JSON_ENC_PLAIN, jsonfile, parseLevel));
        RDB_setPauseInterval(parser, 1 /*bytes*/);
        while (1) {
            status = RDB_parseBuff(parser, buffer, bufLen, 1);
            assert_true (lastBytes < RDB_getBytesProcessed(parser));
            lastBytes = RDB_getBytesProcessed(parser);
            if (status == RDB_STATUS_PAUSED) {
                ++countPauses;
                continue;
            }
            assert_int_equal(status, RDB_STATUS_OK);
            break;
        }
        assert_int_equal(countPauses + 1, bufLen);
        RDB_deleteParser(parser);
        assert_payload_file(jsonfile, expJson, 1);

        free(buffer);
    }
}

void testRdbToRespVariousCases(const char *rdbfile,
                               const char *respfile,
                               char *expResp,
                               RdbxToRespConf *conf,
                               int expNumCmds)
{
    RdbStatus  status;
    RdbxToResp *rdbToResp;
    RdbxRespFileWriter *writer;
    RdbParser *p = RDB_createParserRdb(NULL);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, conf));
    assert_non_null(writer = RDBX_createRespFileWriter(p, rdbToResp, respfile));
    RDB_setLogLevel(p, RDB_LOG_ERROR);

    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    /* verify number of commands counted */
    UNUSED(expNumCmds);
    //assert_int_equal( RDBX_getRespFileWriterCmdCount(writer), expNumCmds);

    RDB_deleteParser(p);
    assert_payload_file(respfile, expResp, 0);
}

void parseBuffOneCharEachTime(RdbParser *p, unsigned char *buff, size_t size, int isEOF) {
    for (size_t i = 0 ; i < size-1 ; ++i)
        assert_int_equal(RDB_parseBuff(p, buff + i, 1, 0), RDB_STATUS_WAIT_MORE_DATA);

    if (!isEOF)
        assert_int_equal(RDB_parseBuff(p, buff + size - 1, 1, 1), RDB_STATUS_WAIT_MORE_DATA);
    else
        assert_int_equal(RDB_parseBuff(p, buff + size - 1, 1, 0), RDB_STATUS_OK);
}

/*** simulate external malloc ***/

#define MAGIC_VALUE      0xDEADBEE

void *xmalloc(size_t size) {
    void *ptr = malloc(size + sizeof(int));
    assert_non_null(ptr);
    *(int *)ptr = MAGIC_VALUE;
    return (char *)ptr + sizeof(int);
}

void *xclone(void *str, size_t len) {
    void *ptr = xmalloc(len);
    memcpy(ptr, str, len);
    return ptr;
}

void xfree(void *ptr) {
    int *header = (int *)((char *)ptr - sizeof(int));
    assert_int_equal(*header, MAGIC_VALUE);
    free(header);
}

void *xrealloc(void *ptr, size_t size) {
    if (ptr == NULL)
        return xmalloc(size);

    int *header = (int *)((char *)ptr - sizeof(int));
    assert_int_equal(*header, MAGIC_VALUE);

    void *new_ptr = realloc(header, size + sizeof(int));
    assert_non_null(new_ptr);
    *(int *)new_ptr = MAGIC_VALUE;
    return (char *)new_ptr + sizeof(int);
}