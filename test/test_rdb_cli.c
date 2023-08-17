#include <string.h>
#include <stdlib.h>
#include "test_common.h"

static int setupTest(void **state) {
    UNUSED(state);
    runSystemCmd("%s/redis-cli -p %d flushall > /dev/null", redisInstallFolder, redisPort);
    runSystemCmd("%s/redis-cli -p %d save > /dev/null", redisInstallFolder, redisPort);
    return 0;
}

/*
 * Testing CLI RESP against live server:
 * 1. Run RDB to Json (out1.json)
 * 2. Run RDB with rdb-cli against Redis and save DUMP-RDB
 * 3. From DUMP-RDB generate Json (out2.json)
 * 4. assert_json_equal(out1.json, out2.json)
 */
static void test_rdb_cli_resp_common(const char *rdbfile) {
    RdbParser *parser;
    RdbStatus status;

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    RdbxToJsonConf rdb2jsonConf = {RDB_LEVEL_DATA, RDBX_CONV_JSON_ENC_PLAIN, 1, 1};

    /* RDB to JSON */
    parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(RDBX_createHandlersToJson(parser, TMP_FOLDER("out1.json"), &rdb2jsonConf));
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);

    /* rdb-cli RDB to RESP and stream toward Redis Server */
    runSystemCmd("./bin/rdb-cli %s redis -h %s -p %d", rdbfile, "127.0.0.1", redisPort);

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
    assert_json_equal(TMP_FOLDER("out1.json"), TMP_FOLDER("out2.json"), 0);
}

static void test_rdb_cli_json(void **state) {
    UNUSED(state);
    runSystemCmd("./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb json -f -w -o ./test/tmp/out.json  > /dev/null ");
    assert_json_equal(DUMP_FOLDER("multiple_lists_strings_data.json"), "./test/tmp/out.json", 0);
}

static void test_rdb_cli_resp_to_redis(void **state) {
    UNUSED(state);
    test_rdb_cli_resp_common(DUMP_FOLDER("multiple_lists_strings.rdb"));
}

/*************************** group_test_rdb_cli *******************************/
int group_test_rdb_cli(void) {

    if (!redisInstallFolder) {
        printf("[  SKIPPED ] (Redis installation folder is not configured)\n");
        return 0;
    }

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_rdb_cli_json),
            cmocka_unit_test_setup(test_rdb_cli_resp_to_redis, setupTest),
    };

    setupRedisServer();
    int res = cmocka_run_group_tests(tests, NULL, NULL);
    teardownRedisServer();
    return res;
}
