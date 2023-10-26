#include <string.h>
#include <stdlib.h>
#include "test_common.h"

static int setupTest(void **state) {
    UNUSED(state);
    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);
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
    RdbxToJsonConf rdb2jsonConf = {
            .level = RDB_LEVEL_DATA,
            .encoding = RDBX_CONV_JSON_ENC_PLAIN,
            .includeAuxField = 0,
            .includeFunc = 0,
            .includeStreamMeta = 0,
            .flatten = 1,
    };

    /* RDB to JSON */
    parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(RDBX_createHandlersToJson(parser, TMP_FOLDER("out1.json"), &rdb2jsonConf));
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);

    /* rdb-cli RDB to RESP and stream toward Redis Server */
    runSystemCmd("./bin/rdb-cli %s redis -h %s -p %d", rdbfile, "127.0.0.1", getRedisPort());

    /* DUMP-RDB from Redis */
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);

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
    runSystemCmd("./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb json -f -o ./test/tmp/out.json  > /dev/null ");
    assert_json_equal(DUMP_FOLDER("multiple_lists_strings_no_aux.json"), "./test/tmp/out.json", 0);
}

static void test_rdb_cli_resp_to_redis(void **state) {
    UNUSED(state);
    test_rdb_cli_resp_common(DUMP_FOLDER("multiple_lists_strings.rdb"));
}

static void test_rdb_cli_filter_db(void **state) {
    UNUSED(state);
    /* -d/--dbnum 0 (found x but not y or z) */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb -d 0 json -f | grep x > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb --dbnum 0 json -f | grep y && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb --dbnum 0 json -f | grep z && exit 1 || exit 0 > /dev/null ");
    /* -D/--no-dbnum 0 (found y and z but not x) */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb -D 0 json -f | grep x && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb --no-dbnum 0 json -f | grep y > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_dbs.rdb --no-dbnum 0 json -f | grep z > /dev/null ");
}

static void test_rdb_cli_filter_key(void **state) {
    UNUSED(state);
    /* -k/--key (found string2 but not mylist1 or lzf_compressed) */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -k string2 json -f | grep string2 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -k string2 json -f | grep mylist1 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -k string2 json -f | grep lzf_compressed && exit 1 || exit 0 > /dev/null ");
    /* -K/--no-key (found mylist1 or lzf_compressed but not string2) */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -K string2 json -f | grep string2 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -K string2 json -f | grep mylist1 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -K string2 json -f | grep lzf_compressed > /dev/null ");
}

static void test_rdb_cli_filter_invalid_input(void **state) {
    UNUSED(state);
    /* invalid regex */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/single_key.rdb -k \"[*x\" json | grep \"Unmatched \\[\" > /dev/null");
}

static void test_rdb_cli_filter_type(void **state) {
    UNUSED(state);
    /* -t/--type */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --type str json -f | grep string2 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --type str json -f | grep lzf_compressed > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --type str json -f | grep string1 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str json -f | grep mylist1 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str json -f | grep mylist2 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str json -f | grep mylist3 && exit 1 || exit 0 > /dev/null ");
    /* -T/--no-type */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --no-type str json -f | grep mylist1 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --no-type str json -f | grep mylist2 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --no-type str json -f | grep mylist3 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -T str json -f | grep string2 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -T str json -f | grep lzf_compressed && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -T str json -f | grep string1 && exit 1 || exit 0 > /dev/null ");
}

static void test_rdb_cli_filter_mix(void **state) {
    UNUSED(state);
    /* Combine 'type' and 'key' filters */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --type str --key string json -f | grep string2 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb --type str --key string json -f | grep string1 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str -k string json -f | grep lzf_compressed && exit 1 || exit 0 > /dev/null");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str -k string json -f | grep list1 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str -k string json -f | grep list2 && exit 1 || exit 0 > /dev/null ");
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/multiple_lists_strings.rdb -t str -k string json -f | grep list3 && exit 1 || exit 0 > /dev/null ");
}

static void test_rdb_cli_input_fd_reader(void **state) {
    UNUSED(state);
    runSystemCmd(" cat ./test/dumps/single_key.rdb | ./bin/rdb-cli - json | grep xxx > /dev/null ");
}

static void test_rdb_cli_redis_auth(void **state) {
    UNUSED(state);
    /* check password authentication */
    setupRedisServer("--requirepass abc");

    /* auth custom command */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/single_key.rdb redis -a 2 auth abc -p %d  > /dev/null ", getRedisPort());

    /* auth pwd */
    sendRedisCmd("FLUSHALL", REDIS_REPLY_ERROR, NULL); /* expected to fail */
    sendRedisCmd("AUTH abc", REDIS_REPLY_STATUS, NULL); /* now expected to succeed */
    runSystemCmd(" ./bin/rdb-cli ./test/dumps/single_key.rdb redis --password abc -p %d  > /dev/null ", getRedisPort());

    /* auth user */
    int major;
    getTargetRedisVersion(&major, NULL);
    /* ACL available since 6.0 */
    if (major>=6) {
        sendRedisCmd("ACL SETUSER newuser on >newpwd  +@all ~*",
                     REDIS_REPLY_STATUS, NULL);
        sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
        runSystemCmd(
                " ./bin/rdb-cli ./test/dumps/single_key.rdb redis -P newpwd -u newuser -p %d  > /dev/null ",
                getRedisPort());
    }

    teardownRedisServer();
}

/*************************** group_test_rdb_cli *******************************/
int group_test_rdb_cli(void) {

    if (!isSetRedisServer()) {
        printf("[  SKIPPED ] (Redis installation folder is not configured)\n");
        return 0;
    }

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_rdb_cli_json),
            cmocka_unit_test_setup(test_rdb_cli_resp_to_redis, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_db, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_key, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_invalid_input, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_type, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_mix, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_input_fd_reader, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_redis_auth, setupTest),
    };

    int res = cmocka_run_group_tests(tests, NULL, NULL);
    return res;
}
