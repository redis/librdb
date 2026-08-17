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

static void test_r2j_hash_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_v3.rdb"), DUMP_FOLDER("hash_data.json"), &r2jConf);
}

static void test_r2j_hash_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    testRdbToJsonCommon(DUMP_FOLDER("hash_v3.rdb"), DUMP_FOLDER("hash_struct.json"), &r2jConf);
}

static void test_r2j_hash_raw (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    testRdbToJsonCommon(DUMP_FOLDER("hash_v3.rdb"), DUMP_FOLDER("hash_raw.json"), &r2jConf);
}

/* hash with expiry on fields */
static void test_r2j_hash_ex_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_with_expire_v12.rdb"), DUMP_FOLDER("hash_ex_v12_data.json"), &r2jConf);
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

/* lp with expiry on fields */
static void test_r2j_hash_lp_ex_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    testRdbToJsonCommon(DUMP_FOLDER("hash_lp_with_hexpire_v12.rdb"), DUMP_FOLDER("hash_lp_ex_v12_data.json"), &r2jConf);
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

/* Dump 'string_utf8_v12.rdb' holds keys whose names describe their payload,
 * covering all UTF-8 lengths, their first/last code points, JSON specials,
 * control chars and invalid byte cases. With PLAIN encoding every non-ASCII
 * byte is escaped as \u00XX (lossless byte dump) - "Müller" -> "MÃ¼ller". */
static void test_r2j_string_utf8_plain_enc(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.encoding = RDBX_CONV_JSON_ENC_PLAIN;
    testRdbToJsonCommon(DUMP_FOLDER("string_utf8_v12.rdb"),
                        DUMP_FOLDER("string_utf8_v12_plain.json"), &r2jConf);
}

/* With UTF8 encoding, valid UTF-8 sequences pass through verbatim while any byte
 * that isn't part of a well-formed sequence falls back to \u00XX escaping. The
 * 'valid_then_bad_mid' and 'mixed_recovery' keys verify decoding resumes safely
 * for the rest of the string after an invalid byte. */
static void test_r2j_string_utf8_utf8_enc(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.encoding = RDBX_CONV_JSON_ENC_UTF8;
    testRdbToJsonCommon(DUMP_FOLDER("string_utf8_v12.rdb"),
                        DUMP_FOLDER("string_utf8_v12_utf8.json"), &r2jConf);
}

static void test_r2j_multiple_dbs (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.flatten = 0;
    testRdbToJsonCommon(DUMP_FOLDER("multiple_dbs.rdb"), DUMP_FOLDER("multiple_dbs_data.json"), &r2jConf);
}

static void test_r2j_function (void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeFunc = 1;
    testRdbToJsonCommon(DUMP_FOLDER("function2.rdb"), DUMP_FOLDER("function2.json"), &r2jConf);
}

static void test_r2j_module_raw(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_RAW);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("module.rdb"), DUMP_FOLDER("module_raw.json"), &r2jConf);
}

static void test_r2j_module_data(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
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

/* Test RDB v13 stream with IDMP support (RDB_TYPE_STREAM_LISTPACKS_4) */
static void test_r2j_stream_v13_idmp(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.includeStreamMeta = 0;
    r2jConf.includeStreamIdmp = 1;
    testRdbToJsonCommon(DUMP_FOLDER("stream_v13_idmp.rdb"), DUMP_FOLDER("stream_v13.json"), &r2jConf);
}

/* Test RDB v14 stream with NACK zone (RDB_TYPE_STREAM_LISTPACKS_5). The fixture
 * has 4 entries; consumer group "mygroup" has 2 owned PEL entries (head + tail)
 * and 2 NACK-zone (unowned) entries in the middle. The JSON output must include
 * a "nacked" array with the NACKed IDs in on-disk order. */
static void test_r2j_stream_v14_xnack(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    r2jConf.includeStreamMeta = 1;
    r2jConf.includeStreamIdmp = 0;
    testRdbToJsonCommon(DUMP_FOLDER("stream_v14_xnack.rdb"), DUMP_FOLDER("stream_v14_xnack.json"), &r2jConf);
}

/* RDB v14 array (RDB_TYPE_ARRAY) JSON emission. Each fixture exercises
 * a different code path of the schema in docs/rdb-v14-support-plan.md §6 T-4:
 *   - basic           : single-type elements, no insert_idx
 *   - mixed_types     : all four AR_RDB_TAG_* payloads (INT/FLOAT/SDS/SMALLSTR)
 *   - with_insert_idx : insert_idx present and mid-range (49)
 *   - insert_idx_boundary : insert_idx == UINT64_MAX - 1 (stringified, no precision loss)
 *   - insert_idx_none : insert_idx_flag == 0 → key omitted from JSON */
static void test_r2j_array_v14_basic(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("array_v14_basic.rdb"), DUMP_FOLDER("array_v14_basic.json"), &r2jConf);
}

static void test_r2j_array_v14_mixed_types(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("array_v14_mixed_types.rdb"), DUMP_FOLDER("array_v14_mixed_types.json"), &r2jConf);
}

static void test_r2j_array_v14_with_insert_idx(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("array_v14_with_insert_idx.rdb"), DUMP_FOLDER("array_v14_with_insert_idx.json"), &r2jConf);
}

static void test_r2j_array_v14_insert_idx_boundary(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("array_v14_insert_idx_boundary.rdb"), DUMP_FOLDER("array_v14_insert_idx_boundary.json"), &r2jConf);
}

static void test_r2j_array_v14_insert_idx_none(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("array_v14_insert_idx_none.rdb"), DUMP_FOLDER("array_v14_insert_idx_none.json"), &r2jConf);
}

/* v15 RDB with only plain-typed keys (no hash templates): must parse clean
 * once the version gate accepts v15 (RDB v15 support, part 1). */
static void test_r2j_multiple_types_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("multiple_types_v15.rdb"), DUMP_FOLDER("multiple_types_v15.json"), &r2jConf);
}

/* Parse a (hand-crafted, checksum-disabled) v15 template fixture and assert the
 * resulting status/error code. expErr == RDB_OK means the parse must succeed. */
static void testTemplateCorrupt(const char *rdbfilename, RdbRes expErr) {
    char rdbfile[1024];
    snprintf(rdbfile, sizeof(rdbfile), "./test/dumps/%s", rdbfilename);
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERR);
    RDB_IgnoreChecksum(p);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    RdbxToJsonConf conf = DEF_CONF(RDB_LEVEL_DATA);
    conf.includeAuxField = 0;
    assert_non_null(RDBX_createHandlersToJson(p, TMP_FOLDER("tmpl_corrupt.json"), &conf));

    RdbStatus status;
    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);

    if (expErr == RDB_OK) {
        assert_int_equal(status, RDB_STATUS_OK);
    } else {
        assert_int_equal(status, RDB_STATUS_ERROR);
        assert_int_equal(RDB_getErrorCode(p), expErr);
    }
    RDB_deleteParser(p);
}

static void test_r2j_hash_template_arrayref_min_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_arrayref_min_v15.rdb", RDB_OK);
}
static void test_r2j_hash_template_corrupt_zero_fields_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_zero_fields_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}
static void test_r2j_hash_template_corrupt_unsorted_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_unsorted_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}
static void test_r2j_hash_template_corrupt_unknown_id_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_unknown_id_v15.rdb", RDB_ERR_HASH_TMPL_UNKNOWN_ID);
}
static void test_r2j_hash_template_corrupt_dup_id_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_dup_id_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}
/* self-contained (types 29/31) corruption: unknown fields_fmt, unsorted inline
 * fields (partial template freed on error), and a values listpack whose entry
 * count doesn't match the field count. */
static void test_r2j_hash_template_self_corrupt_badfmt_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_self_corrupt_badfmt_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}
static void test_r2j_hash_template_self_corrupt_unsorted_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_self_corrupt_unsorted_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}
static void test_r2j_hash_template_self_corrupt_lpcount_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_self_corrupt_lpcount_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}

/* A sparse (2^62) template id is rejected: the registry is indexed by the id, so
 * an id past RDB_HASH_TMPL_MAX_ID is refused rather than allowed to size an
 * allocation. Redis, which keys templates by id in a dict, does load this
 * fixture (checked with redis-check-rdb) - a deliberate divergence. */
static void test_r2j_hash_template_corrupt_huge_id_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_huge_id_v15.rdb", RDB_ERR_HASH_TMPL_INVLD);
}

/* An oversized field count is untrusted: stream the fields (and hit EOF here)
 * instead of sizing an allocation from the declared count. */
static void test_r2j_hash_template_corrupt_huge_field_count_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_corrupt_huge_field_count_v15.rdb",
                        RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE);
}
static void test_r2j_hash_template_self_corrupt_huge_field_count_v15(void **state) {
    UNUSED(state);
    testTemplateCorrupt("hash_template_self_corrupt_huge_field_count_v15.rdb",
                        RDB_ERR_FAILED_PARTIAL_READ_RDB_FILE);
}

/* v15 hash templates: REF-encoded hashes resolve field names from the
 * top-level template section and must render as ordinary hashes. */
static void test_r2j_hash_template_lp_ref_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_v15.rdb"), DUMP_FOLDER("hash_template_v15.json"), &r2jConf);
}

static void test_r2j_hash_template_array_ref_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_array_v15.rdb"), DUMP_FOLDER("hash_template_array_v15.json"), &r2jConf);
}

/* Template hash value edge cases: integer-encoded, empty-string, and
 * LZF-compressed values all decode correctly through the template path. */
static void test_r2j_hash_template_values_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_values_v15.rdb"), DUMP_FOLDER("hash_template_values_v15.json"), &r2jConf);
}

/* Same payload at STRUCT level resolves through handleHashPlain to the same
 * field/value pairs. */
static void test_r2j_hash_template_lp_ref_v15_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_v15.rdb"), DUMP_FOLDER("hash_template_v15.json"), &r2jConf);
}

/* v15 self-contained hash templates (types 29/31): the field names are
 * inlined in the payload (no template section), covering both field formats
 * (FIELDS_LP / FIELDS_RAW) and both value encodings (listpack / array). Redis
 * writes these only via DUMP, but its loader - and librdb - accept them from an
 * RDB file too. All render as ordinary hashes. */
static void test_r2j_hash_template_self_array_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_self_array_v15.rdb"),
                        DUMP_FOLDER("hash_template_self_3keys_v15.json"), &r2jConf);
}
static void test_r2j_hash_template_self_arraylp_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_self_arraylp_v15.rdb"),
                        DUMP_FOLDER("hash_template_self_2keys_v15.json"), &r2jConf);
}
static void test_r2j_hash_template_self_lp_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_self_lp_v15.rdb"),
                        DUMP_FOLDER("hash_template_self_3keys_v15.json"), &r2jConf);
}
static void test_r2j_hash_template_self_lpraw_v15(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_self_lpraw_v15.rdb"),
                        DUMP_FOLDER("hash_template_self_2keys_v15.json"), &r2jConf);
}
/* Same self-contained payload at STRUCT level resolves via handleHashPlain. */
static void test_r2j_hash_template_self_lp_v15_struct(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_STRUCT);
    r2jConf.includeAuxField = 0;
    testRdbToJsonCommon(DUMP_FOLDER("hash_template_self_lp_v15.rdb"),
                        DUMP_FOLDER("hash_template_self_3keys_v15.json"), &r2jConf);
}

static void test_r2j_cluster_slot_info(void **state) {
    UNUSED(state);
    RdbxToJsonConf r2jConf = DEF_CONF(RDB_LEVEL_DATA);
    r2jConf.includeDbInfo = 1;
    testRdbToJsonCommon(DUMP_FOLDER("cluster_slot_info.rdb"), DUMP_FOLDER("cluster_slot_info.json"), &r2jConf);
}

/*************************** group_rdb_to_json *******************************/
int group_rdb_to_json(void) {
    const struct CMUnitTest tests[] = {
        /* string */
        cmocka_unit_test(test_r2j_single_string_data),
        cmocka_unit_test(test_r2j_single_string_struct),
        cmocka_unit_test(test_r2j_single_string_raw),
        cmocka_unit_test(test_r2j_string_utf8_plain_enc),
        cmocka_unit_test(test_r2j_string_utf8_utf8_enc),

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
        cmocka_unit_test(test_r2j_hash_data),
        cmocka_unit_test(test_r2j_hash_struct),
        cmocka_unit_test(test_r2j_hash_raw),

        cmocka_unit_test(test_r2j_hash_ex_data),

        cmocka_unit_test(test_r2j_hash_zl_data),
        cmocka_unit_test(test_r2j_hash_zl_struct),
        cmocka_unit_test(test_r2j_hash_zl_raw),

        cmocka_unit_test(test_r2j_hash_lp_data),
        cmocka_unit_test(test_r2j_hash_lp_struct),
        cmocka_unit_test(test_r2j_hash_lp_raw),

        cmocka_unit_test(test_r2j_hash_lp_ex_data),

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
        cmocka_unit_test(test_r2j_stream_v13_idmp),
        cmocka_unit_test(test_r2j_stream_v14_xnack),

        /* array (RDB_TYPE_ARRAY, v14+) */
        cmocka_unit_test(test_r2j_array_v14_basic),
        cmocka_unit_test(test_r2j_array_v14_mixed_types),
        cmocka_unit_test(test_r2j_array_v14_with_insert_idx),
        cmocka_unit_test(test_r2j_array_v14_insert_idx_boundary),
        cmocka_unit_test(test_r2j_array_v14_insert_idx_none),

        /* v15 */
        cmocka_unit_test(test_r2j_multiple_types_v15),
        cmocka_unit_test(test_r2j_hash_template_lp_ref_v15),
        cmocka_unit_test(test_r2j_hash_template_array_ref_v15),
        cmocka_unit_test(test_r2j_hash_template_values_v15),
        cmocka_unit_test(test_r2j_hash_template_lp_ref_v15_struct),
        cmocka_unit_test(test_r2j_hash_template_self_array_v15),
        cmocka_unit_test(test_r2j_hash_template_self_arraylp_v15),
        cmocka_unit_test(test_r2j_hash_template_self_lp_v15),
        cmocka_unit_test(test_r2j_hash_template_self_lpraw_v15),
        cmocka_unit_test(test_r2j_hash_template_self_lp_v15_struct),
        cmocka_unit_test(test_r2j_hash_template_arrayref_min_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_zero_fields_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_unsorted_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_unknown_id_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_dup_id_v15),
        cmocka_unit_test(test_r2j_hash_template_self_corrupt_badfmt_v15),
        cmocka_unit_test(test_r2j_hash_template_self_corrupt_unsorted_v15),
        cmocka_unit_test(test_r2j_hash_template_self_corrupt_lpcount_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_huge_id_v15),
        cmocka_unit_test(test_r2j_hash_template_corrupt_huge_field_count_v15),
        cmocka_unit_test(test_r2j_hash_template_self_corrupt_huge_field_count_v15),

        /* misc */
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_data),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_struct),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_raw),
        cmocka_unit_test(test_r2j_multiple_dbs),
        cmocka_unit_test(test_r2j_string_int_encoded),
        cmocka_unit_test(test_r2j_cluster_slot_info),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
