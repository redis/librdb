#include <string.h>
#include <stdlib.h>
#include "test_common.h"



#define DEF_CONF(parseLevel)                   \
    {                                          \
        .level = parseLevel,                   \
        .encoding = RDBX_CONV_JSON_ENC_PLAIN,  \
        .includeAuxField = 1,                  \
        .includeFunc = 0,                      \
        .flatten = 1,                          \
        .includeStreamMeta = 0,                \
    };

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
                         const char *expJsonFile,
                         RdbxToJsonConf *r2jConf)
{
    const char *jsonfile = TMP_FOLDER("tmp.json");

    for (int type = 0 ; type <= RDB_BULK_ALLOC_MAX ; ++type) {
        unsigned char *buffer;
        size_t bufLen;
        RdbStatus  status;
        RdbMemAlloc memAlloc = {xmalloc, xrealloc, xfree, type, {xmalloc, xclone, xfree}};
        RdbMemAlloc *pMemAlloc = (type != RDB_BULK_ALLOC_MAX) ? &memAlloc : NULL;

        /* read file to buffer for testing RDB_parseBuff() */
        buffer = (unsigned char *) readFile(rdbfile, &bufLen, NULL);

        /*** 1. RDB_parse - parse with RDB reader ***/
        remove(jsonfile);
        RdbParser *parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, r2jConf));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
        assert_json_equal(jsonfile, expJsonFile, 0);

        /*** 2. RDB_parse - set pause-interval to 1 byte ***/
        int countPausesAssert = 1;
        long countPauses = 0;
        size_t lastBytes = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, r2jConf));
        RDB_setPauseInterval(parser, 1 /*bytes*/);
        while (1) {
            status = RDB_parse(parser);
            if (status == RDB_STATUS_WAIT_MORE_DATA) {
                countPausesAssert = 0;
                continue;
            }
            if (status == RDB_STATUS_PAUSED) {
                ++countPauses;
                continue;
            }
            assert_int_equal(status, RDB_STATUS_OK);
            break;
        }

        /* If recorded WAIT_MORE_DATA, it will mess our countPauses evaluation. Skip it. */
        if (countPausesAssert)
            assert_int_equal(countPauses + 1, bufLen);

        RDB_deleteParser(parser);
        assert_json_equal(jsonfile, expJsonFile, 0);

        /*** 3. RDB_parseBuff - parse buffer. Use buffer of size 1 char ***/
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, r2jConf));
        for (size_t i = 0 ; i < bufLen-1 ; ++i)
            assert_int_equal(RDB_parseBuff(parser, buffer + i, 1, 0), RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(RDB_parseBuff(parser, buffer + bufLen - 1, 1, 0), RDB_STATUS_OK);

        RDB_deleteParser(parser);
        assert_json_equal(jsonfile, expJsonFile, 0);

        /*** 4. RDB_parseBuff - parse a single buffer. set pause-interval to 1 byte ***/
        countPauses = 0;
        remove(jsonfile);
        parser = RDB_createParserRdb(pMemAlloc);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createHandlersToJson(parser, jsonfile, r2jConf));
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
        assert_json_equal(jsonfile, expJsonFile, 0);

        free(buffer);
    }
}

static void test_r2j_single_ziplist_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("ziplist_v3.rdb"), DUMP_FOLDER("ziplist_data.json"), &r2jConf);
}

static void test_r2j_single_ziplist_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("ziplist_v3.rdb"), DUMP_FOLDER("ziplist_struct.json"), &r2jConf);
}

static void test_r2j_single_ziplist_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("ziplist_v3.rdb"), DUMP_FOLDER("ziplist_raw.json"), &r2jConf);
}

static void test_r2j_plain_list_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("plain_list_v6.rdb"), DUMP_FOLDER("plain_list_v6_data.json"), &r2jConf);
}

static void test_r2j_plain_list_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("plain_list_v6.rdb"), DUMP_FOLDER("plain_list_v6_struct.json"), &r2jConf);
}

static void test_r2j_plain_list_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("plain_list_v6.rdb"), DUMP_FOLDER("plain_list_v6_raw.json"), &r2jConf);
}

static void test_r2j_plain_hash_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("plain_hash_v3.rdb"), DUMP_FOLDER("plain_hash_data.json"), &r2jConf);
}

static void test_r2j_plain_hash_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("plain_hash_v3.rdb"), DUMP_FOLDER("plain_hash_struct.json"), &r2jConf);
}

static void test_r2j_plain_hash_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("plain_hash_v3.rdb"), DUMP_FOLDER("plain_hash_raw.json"), &r2jConf);
}

static void test_r2j_hash_zl_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zl_v6.rdb"), DUMP_FOLDER("hash_zl_v6_data.json"), &r2jConf);
}

static void test_r2j_hash_zl_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zl_v6.rdb"), DUMP_FOLDER("hash_zl_v6_struct.json"), &r2jConf);
}

static void test_r2j_hash_zl_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zl_v6.rdb"), DUMP_FOLDER("hash_zl_v6_raw.json"), &r2jConf);
}

static void test_r2j_hash_lp_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_lp_v11.rdb"), DUMP_FOLDER("hash_lp_v11_data.json"), &r2jConf);
}

static void test_r2j_hash_lp_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("hash_lp_v11.rdb"), DUMP_FOLDER("hash_lp_v11_struct.json"), &r2jConf);
}

static void test_r2j_hash_lp_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("hash_lp_v11.rdb"), DUMP_FOLDER("hash_lp_v11_raw.json"), &r2jConf);
}

static void test_r2j_hash_zm_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zm_v2.rdb"), DUMP_FOLDER("hash_zm_v2_data.json"), &r2jConf);
}

static void test_r2j_hash_zm_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zm_v2.rdb"), DUMP_FOLDER("hash_zm_v2_struct.json"), &r2jConf);
}

static void test_r2j_hash_zm_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("hash_zm_v2.rdb"), DUMP_FOLDER("hash_zm_v2_raw.json"), &r2jConf);
}

static void test_r2j_plain_set_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("plain_set_v6.rdb"), DUMP_FOLDER("plain_set_v6_data.json"), &r2jConf);
}

static void test_r2j_plain_set_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("plain_set_v6.rdb"), DUMP_FOLDER("plain_set_v6_struct.json"), &r2jConf);
}

static void test_r2j_plain_set_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("plain_set_v6.rdb"), DUMP_FOLDER("plain_set_v6_raw.json"), &r2jConf);
}

static void test_r2j_set_is_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("set_is_v11.rdb"), DUMP_FOLDER("set_is_v11_data.json"), &r2jConf);
}

static void test_r2j_set_is_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("set_is_v11.rdb"), DUMP_FOLDER("set_is_v11_struct.json"), &r2jConf);
}

static void test_r2j_set_is_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("set_is_v11.rdb"), DUMP_FOLDER("set_is_v11_raw.json"), &r2jConf);
}

static void test_r2j_set_lp_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("set_lp_v11.rdb"), DUMP_FOLDER("set_lp_v11_data.json"), &r2jConf);
}

static void test_r2j_set_lp_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("set_lp_v11.rdb"), DUMP_FOLDER("set_lp_v11_struct.json"), &r2jConf);
}

static void test_r2j_set_lp_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("set_lp_v11.rdb"), DUMP_FOLDER("set_lp_v11_raw.json"), &r2jConf);
}

static void test_r2j_plain_zset_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_v6.rdb"), DUMP_FOLDER("plain_zset_v6_data.json"), &r2jConf);
}

static void test_r2j_plain_zset_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_v6.rdb"), DUMP_FOLDER("plain_zset_v6_struct.json"), &r2jConf);
}

static void test_r2j_plain_zset_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_v6.rdb"), DUMP_FOLDER("plain_zset_v6_raw.json"), &r2jConf);
}

static void test_r2j_plain_zset_2_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_2_v11.rdb"), DUMP_FOLDER("plain_zset_2_v11_data.json"), &r2jConf);
}

static void test_r2j_plain_zset_2_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_2_v11.rdb"), DUMP_FOLDER("plain_zset_2_v11_struct.json"), &r2jConf);
}

static void test_r2j_plain_zset_2_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("plain_zset_2_v11.rdb"), DUMP_FOLDER("plain_zset_2_v11_raw.json"), &r2jConf);
}

static void test_r2j_zset_lp_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("zset_lp_v11.rdb"), DUMP_FOLDER("zset_lp_v11_data.json"), &r2jConf);
}

static void test_r2j_zset_lp_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("zset_lp_v11.rdb"), DUMP_FOLDER("zset_lp_v11_struct.json"), &r2jConf);
}

static void test_r2j_zset_lp_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("zset_lp_v11.rdb"), DUMP_FOLDER("zset_lp_v11_raw.json"), &r2jConf);
}

static void test_r2j_zset_zl_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("zset_zl_v6.rdb"), DUMP_FOLDER("zset_zl_v6_data.json"), &r2jConf);
}

static void test_r2j_zset_zl_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("zset_zl_v6.rdb"), DUMP_FOLDER("zset_zl_v6_struct.json"), &r2jConf);
}

static void test_r2j_zset_zl_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("zset_zl_v6.rdb"), DUMP_FOLDER("zset_zl_v6_raw.json"), &r2jConf);
}

static void test_r2j_quicklist_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist.rdb"), DUMP_FOLDER("quicklist_data.json"), &r2jConf);
}

static void test_r2j_quicklist_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist.rdb"), DUMP_FOLDER("quicklist_struct.json"), &r2jConf);
}

static void test_r2j_quicklist_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist.rdb"), DUMP_FOLDER("quicklist_raw.json"), &r2jConf);
}

static void test_r2j_single_list_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist2_v11.rdb"), DUMP_FOLDER("single_list_data.json"), &r2jConf);
}

static void test_r2j_single_list_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist2_v11.rdb"), DUMP_FOLDER("single_list_struct.json"), &r2jConf);
}

static void test_r2j_single_list_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("quicklist2_v11.rdb"), DUMP_FOLDER("single_list_raw.json"), &r2jConf);
}

static void test_r2j_multiple_lists_and_strings_data (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"), DUMP_FOLDER("multiple_lists_strings_data.json"), &r2jConf);
}

static void test_r2j_multiple_lists_and_strings_struct (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"), DUMP_FOLDER("multiple_lists_strings_struct.json"), &r2jConf);
}

static void test_r2j_multiple_lists_and_strings_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_lists_strings.rdb"), DUMP_FOLDER("multiple_lists_strings_raw.json"), &r2jConf);
}

static void test_r2j_single_string_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"), DUMP_FOLDER("single_key_data.json"), &r2jConf);
}

static void test_r2j_single_string_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"), DUMP_FOLDER("single_key_struct.json"), &r2jConf);
}

static void test_r2j_single_string_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("single_key.rdb"), DUMP_FOLDER("single_key_raw.json"), &r2jConf);
}

static void test_r2j_multiple_dbs (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("multiple_dbs.rdb"), DUMP_FOLDER("multiple_dbs_data.json"), &r2jConf);
}

static void test_r2j_function (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeFunc = 1;
    testRdbToJsonCommon(DUMP_FOLDER("function.rdb"), DUMP_FOLDER("function.json"), &r2jConf);
}

static void test_r2j_module_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = {
        .level = RDB_LEVEL_RAW,
        .encoding = RDBX_CONV_JSON_ENC_PLAIN,
        .includeAuxField = 0,
        .includeFunc = 0,
        .flatten = 1,
    };
    testRdbToJsonCommon(DUMP_FOLDER("module.rdb"), DUMP_FOLDER("module_raw.json"), &r2jConf);
}

static void test_r2j_module_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = {
        .level = RDB_LEVEL_DATA,
        .encoding = RDBX_CONV_JSON_ENC_PLAIN,
        .includeAuxField = 0,
        .includeFunc = 0,
        .flatten = 1,
    };
    testRdbToJsonCommon(DUMP_FOLDER("module.rdb"), DUMP_FOLDER("module_data.json"), &r2jConf);
}

static void test_r2j_module_aux_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("module_aux.rdb"), DUMP_FOLDER("module_aux_data.json"), &r2jConf);
}

static void test_r2j_string_int_encoded(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("string_int_encoded.rdb"), DUMP_FOLDER("string_int_encoded.json"), &r2jConf);
}

static void test_r2j_stream_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.flatten = 1;
    testRdbToJsonCommon(DUMP_FOLDER("stream_v11.rdb"), DUMP_FOLDER("stream_data.json"), &r2jConf);
    r2jConf.includeStreamMeta = 1;
    testRdbToJsonCommon(DUMP_FOLDER("stream_v11.rdb"), DUMP_FOLDER("stream_data_with_meta.json"), &r2jConf);
}

/*************************** group_rdb_to_json *******************************/
int group_rdb_to_json(void) {
    const struct CMUnitTest tests[] = {
        /* string */
        cmocka_unit_test(test_r2j_single_string_data),
        cmocka_unit_test(test_r2j_single_string_struct),
        cmocka_unit_test(test_r2j_single_string_raw),

        /* list */
        cmocka_unit_test(test_r2j_single_list_data),
        cmocka_unit_test(test_r2j_single_list_struct),
        cmocka_unit_test(test_r2j_single_list_raw),

        cmocka_unit_test(test_r2j_quicklist_data),
        cmocka_unit_test(test_r2j_quicklist_struct),
        cmocka_unit_test(test_r2j_quicklist_raw),

        cmocka_unit_test(test_r2j_single_ziplist_data),
        cmocka_unit_test(test_r2j_single_ziplist_struct),
        cmocka_unit_test(test_r2j_single_ziplist_raw),

        cmocka_unit_test(test_r2j_plain_list_data),
        cmocka_unit_test(test_r2j_plain_list_raw),

        /* hash */
        cmocka_unit_test(test_r2j_plain_hash_data),
        cmocka_unit_test(test_r2j_plain_hash_struct),
        cmocka_unit_test(test_r2j_plain_hash_raw),

        cmocka_unit_test(test_r2j_hash_zl_data),
        cmocka_unit_test(test_r2j_hash_zl_struct),
        cmocka_unit_test(test_r2j_hash_zl_raw),

        cmocka_unit_test(test_r2j_hash_lp_data),
        cmocka_unit_test(test_r2j_hash_lp_struct),
        cmocka_unit_test(test_r2j_hash_lp_raw),

        cmocka_unit_test(test_r2j_hash_zm_data),
        cmocka_unit_test(test_r2j_hash_zm_struct),
        cmocka_unit_test(test_r2j_hash_zm_raw),

        /* set */
        cmocka_unit_test(test_r2j_plain_set_data),
        cmocka_unit_test(test_r2j_plain_set_struct),
        cmocka_unit_test(test_r2j_plain_set_raw),
        cmocka_unit_test(test_r2j_set_is_data),
        cmocka_unit_test(test_r2j_set_is_struct),
        cmocka_unit_test(test_r2j_set_is_raw),
        cmocka_unit_test(test_r2j_set_lp_data),
        cmocka_unit_test(test_r2j_set_lp_struct),
        cmocka_unit_test(test_r2j_set_lp_raw),

        /* zset */
        cmocka_unit_test(test_r2j_plain_zset_data),
        cmocka_unit_test(test_r2j_plain_zset_struct),
        cmocka_unit_test(test_r2j_plain_zset_raw),
        cmocka_unit_test(test_r2j_plain_zset_2_data),
        cmocka_unit_test(test_r2j_plain_zset_2_struct),
        cmocka_unit_test(test_r2j_plain_zset_2_raw),
        cmocka_unit_test(test_r2j_zset_lp_data),
        cmocka_unit_test(test_r2j_zset_lp_struct),
        cmocka_unit_test(test_r2j_zset_lp_raw),
        cmocka_unit_test(test_r2j_zset_zl_data),
        cmocka_unit_test(test_r2j_zset_zl_struct),
        cmocka_unit_test(test_r2j_zset_zl_raw),

        /* function */
        cmocka_unit_test(test_r2j_function),

        /* module */
        cmocka_unit_test(test_r2j_module_data),
        cmocka_unit_test(test_r2j_module_raw),
        cmocka_unit_test(test_r2j_module_aux_data),

        /* stream */
         cmocka_unit_test(test_r2j_stream_data),

        /* misc */
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_data),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_struct),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_raw),
        cmocka_unit_test(test_r2j_multiple_dbs),
        cmocka_unit_test(test_r2j_string_int_encoded),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
