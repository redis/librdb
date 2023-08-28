#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "test_common.h"

static int setupTest(void **state) {
    UNUSED(state);
    runSystemCmd("%s/redis-cli -p %d flushall > /dev/null", redisInstallFolder, redisPort);
    runSystemCmd("%s/redis-cli -p %d save > /dev/null", redisInstallFolder, redisPort);
    return 0;
}

/*
 * Testing RESP against live server:
 * 1. Run RDB to Json (out1.json)
 * 2. Run RDB against Redis and save DUMP-RDB
 * 3. From DUMP-RDB generate Json (out2.json)
 * 4. assert_json_equal(out1.json , out2.json)
 *
 * The test will run twice against:
 * A. old Redis target (no RESTORE)
 * B. new Redis target (RESTORE)
 * Note: This test cannot tell if actually run RESTORE command in the background.
 *       test_rdb_to_resp.c verifies that RESTORE command is used only when it should.
 */
static void test_rdb_to_redis_common(const char *rdbfile, int pipelineDepth, int ignoreListOrder) {
    RdbParser *parser;
    RdbStatus status;

    /* test one time without RESTORE, Playing against old version.
     * and one time with RESTORE, Playing against new version. */
    for (int isRestore = 0 ; isRestore <= 1 ; ++isRestore) {

        /* old-target (not RESTORE) VS. new-target (RESTORE) */
        const char *dstRedisVersion = (isRestore == 0) ? "0.0.1" : "45.67.89";

        runSystemCmd("%s/redis-cli -p %d flushall > /dev/null", redisInstallFolder, redisPort);

        RdbxToRespConf rdb2respConf = {
                .supportRestore = 1,
                .dstRedisVersion = dstRedisVersion,
        };
        RdbxToJsonConf rdb2jsonConf = {RDB_LEVEL_DATA, RDBX_CONV_JSON_ENC_PLAIN, 1, 1};

        /* RDB to JSON */
        parser = RDB_createParserRdb(NULL);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(RDBX_createHandlersToJson(parser,
                                                  TMP_FOLDER("out1.json"),
                                                  &rdb2jsonConf));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);

        /* RDB to TCP */
        RdbxToResp *rdbToResp;
        parser = RDB_createParserRdb(NULL);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, rdbfile));
        assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser, &rdb2respConf));

        RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(parser,
                                                               rdbToResp,
                                                               "127.0.0.1",
                                                               redisPort);
        assert_non_null(r2r);
        RDBX_setPipelineDepth(r2r, pipelineDepth);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);

        /* DUMP-RDB from Redis */
        runSystemCmd("%s/redis-cli -p %d save > /dev/null", redisInstallFolder, redisPort);

        /* DUMP-RDB to JSON */
        parser = RDB_createParserRdb(NULL);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, TMP_FOLDER("dump.rdb")));
        assert_non_null(RDBX_createHandlersToJson(parser,
                                                  TMP_FOLDER("out2.json"),
                                                  &rdb2jsonConf));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);

        /* Json (from DUMP-RDB) vs. expected Json */
        assert_json_equal(TMP_FOLDER("out1.json"), TMP_FOLDER("out2.json"), ignoreListOrder);
    }
}

static void test_rdb_to_redis_single_string(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("single_key.rdb"), 0, 0);
}

static void test_rdb_to_redis_single_list(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("quicklist2_v11.rdb"), 0, 0);
}

static void test_rdb_to_redis_multiple_lists_strings(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("multiple_lists_strings.rdb"), 0, 0);
}

static void test_rdb_to_redis_multiple_lists_strings_pipeline_depth_1(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("multiple_lists_strings.rdb"), 1, 0);
}

static void test_rdb_to_redis_plain_list(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_list_v6.rdb"), 1, 0);
}

static void test_rdb_to_redis_quicklist(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("quicklist.rdb"), 1, 0);
}

static void test_rdb_to_redis_single_ziplist(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("ziplist_v3.rdb"), 1, 0);
}

static void test_rdb_to_redis_plain_hash(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_hash_v3.rdb"), 1, 0);
}

static void test_rdb_to_redis_hash_zl(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_zl_v6.rdb"), 1, 0);
}

static void test_rdb_to_redis_hash_lp(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_lp_v11.rdb"), 1, 0);
}

static void test_rdb_to_redis_hash_zm(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_zm_v2.rdb"), 1, 0);
}

static void test_rdb_to_redis_plain_set(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_set_v6.rdb"), 1, 1);
}

static void test_rdb_to_redis_set_is(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_is_v11.rdb"), 1, 1);
}

static void test_rdb_to_redis_set_lp(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_lp_v11.rdb"), 1, 1);
}

/* iff 'delKeyBeforeWrite' is not set, then the parser will return an error on
 * loading 100_lists.rdb ("mylist1 mylist2 ... mylist100") on key 'mylist62'
 * Because key `mylist62` created earlier with a string value.  */
static void test_rdb_to_redis_del_before_write(void **state) {
    UNUSED(state);
    RdbParser *parser;
    RdbStatus status;
    for (int delKeyBeforeWrite = 0 ; delKeyBeforeWrite <= 1 ; ++delKeyBeforeWrite) {
        RdbxToRespConf rdb2respConf = {
                .delKeyBeforeWrite = delKeyBeforeWrite,
                .supportRestore = 1,
                .dstRedisVersion = "45.67.89"
        };

        runSystemCmd("%s/redis-cli -p %d set mylist62 1 > /dev/null", redisInstallFolder, redisPort);
        /* RDB to TCP */
        RdbxToResp *rdbToResp;
        parser = RDB_createParserRdb(NULL);
        RDB_setLogLevel(parser, RDB_LOG_ERR);
        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("100_lists.rdb")));
        assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser, &rdb2respConf));

        assert_non_null(RDBX_createRespToRedisTcp(parser,
                                                  rdbToResp,
                                                  "127.0.0.1",
                                                  redisPort));

        RDB_setLogLevel(parser, RDB_LOG_ERR);

        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);

        if (status == RDB_STATUS_OK)
            assert_int_equal(delKeyBeforeWrite, 1);
        else {
            assert_int_equal(delKeyBeforeWrite, 0);
            /* verify returned error code. Verify error message. */
            RdbRes err = RDB_getErrorCode(parser);
            assert_int_equal(err, RDBX_ERR_RESP_WRITE);
            assert_non_null(strstr(RDB_getErrorMessage(parser), "mylist62"));
        }

        RDB_deleteParser(parser);
    }
}

/*************************** group_rdb_to_redis *******************************/
int group_rdb_to_redis() {

    if (!redisInstallFolder) {
        printf("[  SKIPPED ] (Redis installation folder is not configured)\n");
        return 0;
    }

    const struct CMUnitTest tests[] = {
            /* string */
            cmocka_unit_test_setup(test_rdb_to_redis_single_string, setupTest),
            /* list */
            cmocka_unit_test_setup(test_rdb_to_redis_single_list, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_plain_list, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_quicklist, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_single_ziplist, setupTest),
            /* hash */
            cmocka_unit_test_setup(test_rdb_to_redis_plain_hash, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_zl, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_lp, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_zm, setupTest),
            /* set */
            cmocka_unit_test_setup(test_rdb_to_redis_plain_set, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_set_is, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_set_lp, setupTest),

            /* misc */
            cmocka_unit_test_setup(test_rdb_to_redis_multiple_lists_strings, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_multiple_lists_strings_pipeline_depth_1, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_del_before_write, setupTest),

    };

    setupRedisServer();
    int res = cmocka_run_group_tests(tests, NULL, NULL);
    teardownRedisServer();

    return res;
}