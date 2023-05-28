#include <string.h>
#include <stdlib.h>
#include "test_common.h"

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
void testRdbToJsonCommon(const char *rdbfile,
                         const char *jsonfile,
                         const char *expJsonFile,
                         RdbHandlersLevel parseLevel)
{
    RdbxToJsonConf r2jConf = {parseLevel, RDBX_CONV_JSON_ENC_PLAIN, 0, 1};

    for (int type = 0 ; type <= RDB_BULK_ALLOC_MAX ; ++type) {
        unsigned char *buffer;
        size_t bufLen;
        RdbStatus  status;
        RdbMemAlloc memAlloc = {xmalloc, xrealloc, xfree, type, {xmalloc, xclone, xfree}};
        RdbMemAlloc *pMemAlloc = (type != RDB_BULK_ALLOC_MAX) ? &memAlloc : NULL;

        /* read file to buffer for testing RDB_parseBuff() */
        buffer = (unsigned char *) readFile(rdbfile, &bufLen);

        /*** 1. RDB_parse - parse with RDB reader ***/
        remove(jsonfile);
        RdbParser *parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, &r2jConf));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
        assert_json_equal(jsonfile, expJsonFile);

        /*** 2. RDB_parse - set pause-interval to 1 byte ***/
        int looseCounterAssert = 0;
        long countPauses = 0;
        size_t lastBytes = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, &r2jConf));
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
        assert_json_equal(jsonfile, expJsonFile);

        /*** 3. RDB_parseBuff - parse buffer. Use buffer of size 1 char ***/
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, &r2jConf));
        for (size_t i = 0 ; i < bufLen-1 ; ++i)
            assert_int_equal(RDB_parseBuff(parser, buffer + i, 1, 0), RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(RDB_parseBuff(parser, buffer + bufLen - 1, 1, 0), RDB_STATUS_OK);

        RDB_deleteParser(parser);
        assert_json_equal(jsonfile, expJsonFile);

        /*** 4. RDB_parseBuff - parse a single buffer. set pause-interval to 1 byte ***/
        countPauses = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, &r2jConf));
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
        assert_json_equal(jsonfile, expJsonFile);

        free(buffer);
    }
}

static void test_r2j_single_list_data(void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("single_list.rdb"),
                        TMP_FOLDER("single_list.json"),
                        DUMP_FOLDER("single_list_data.json"),
                        RDB_LEVEL_DATA);
}

static void test_r2j_single_list_struct(void **state) {
    UNUSED(state);

    testRdbToJsonCommon(DUMP_FOLDER("single_list.rdb"),
                        TMP_FOLDER("single_list.json"),
                        DUMP_FOLDER("single_list_struct.json"),
                        RDB_LEVEL_STRUCT);
}

static void test_r2j_single_list_raw (void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("single_list.rdb"),
                        TMP_FOLDER("single_list.json"),
                        DUMP_FOLDER("single_list_raw.json"),
                        RDB_LEVEL_RAW);
}

static void test_r2j_multiple_lists_and_strings_data (void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"),
                        TMP_FOLDER("multiple_lists_strings.json"),
                        DUMP_FOLDER("multiple_lists_strings_data.json"),
                        RDB_LEVEL_DATA);
}

static void test_r2j_multiple_lists_and_strings_struct (void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"),
                        TMP_FOLDER("multiple_lists_strings.json"),
                        DUMP_FOLDER("multiple_lists_strings_struct.json"),
                        RDB_LEVEL_STRUCT);
}

static void test_r2j_multiple_lists_and_strings_raw (void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"),
                        TMP_FOLDER("multiple_lists_strings.json"),
                        DUMP_FOLDER("multiple_lists_strings_raw.json"),
                        RDB_LEVEL_RAW);
}

static void test_r2j_single_string_data(void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"),
                        TMP_FOLDER("single_key.json"),
                        DUMP_FOLDER("single_key_data.json"),
                        RDB_LEVEL_DATA);
}

static void test_r2j_single_string_struct(void **state) {
    UNUSED(state);

    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"),
                        TMP_FOLDER("single_key.json"),
                        DUMP_FOLDER("single_key_struct.json"),
                        RDB_LEVEL_STRUCT);
}

static void test_r2j_single_string_raw(void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"),
                        TMP_FOLDER("single_key.json"),
                        DUMP_FOLDER("single_key_raw.json"),
                        RDB_LEVEL_RAW);
}

static void test_r2j_multiple_dbs (void **state) {
    UNUSED(state);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_dbs.rdb"),
                        TMP_FOLDER("multiple_dbs.json"),
                        DUMP_FOLDER("multiple_dbs_data.json"),
                     RDB_LEVEL_DATA);
}

/*************************** group_rdb_to_json *******************************/
int group_rdb_to_json(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_r2j_single_list_data),
        cmocka_unit_test(test_r2j_single_list_struct),
        cmocka_unit_test(test_r2j_single_list_raw),

        cmocka_unit_test(test_r2j_single_string_data),
        cmocka_unit_test(test_r2j_single_string_struct),
        cmocka_unit_test(test_r2j_single_string_raw),

        cmocka_unit_test(test_r2j_multiple_lists_and_strings_data),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_struct),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_raw),
        cmocka_unit_test(test_r2j_multiple_dbs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
