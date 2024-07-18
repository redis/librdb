/* This file tests rdb-cli. Additionally, it also tests the 'print' formatter,
 * which does not have its own separate test file. */

#include <string.h>
#include <unistd.h>
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
            .includeDbInfo = 0,
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
    runSystemCmd("$RDB_CLI_CMD %s redis -h %s -p %d", rdbfile, "127.0.0.1", getRedisPort());

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
    runSystemCmd("$RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb json -f -o ./test/tmp/out.json  > /dev/null ");
    assert_json_equal(DUMP_FOLDER("multiple_lists_strings_no_aux.json"), "./test/tmp/out.json", 0);
}

static void test_rdb_cli_resp_to_redis(void **state) {
    UNUSED(state);
    test_rdb_cli_resp_common(DUMP_FOLDER("multiple_lists_strings.rdb"));
}

static void test_rdb_cli_filter_db(void **state) {
    UNUSED(state);

    /* -d/--dbnum 0 (found x but not y or z) */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_dbs.rdb -d 0 print -k \"%%k\" | sort"),
        "x\n");

    /* -D/--no-dbnum 0 (found y and z but not x) */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_dbs.rdb --no-dbnum 0 print -k \"%%k\" | sort"),
        "y\nz\n");
}

static void test_rdb_cli_filter_key(void **state) {
    UNUSED(state);
    /* -k/--key (found string2 but not mylist1 or lzf_compressed) */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb -k string2 print -k \"%%k\" | sort"),
        "string2\n");

    /* -K/--no-key (found mylist1 or lzf_compressed but not string2) */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb -K string2 print -k \"%%k\" | sort"),
        "lzf_compressed\nmylist1\nmylist2\nmylist3\nstring1\n");
}

static void test_rdb_cli_filter_invalid_input(void **state) {
    UNUSED(state);
    /* invalid regex */
    runSystemCmd(" $RDB_CLI_CMD ./test/dumps/single_key.rdb -k \"[*x\" json | grep \"Unmatched \\[\" > /dev/null");
}

static void test_rdb_cli_filter_type(void **state) {
    UNUSED(state);

    /* -t/--type */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb --type str print -k \"%%k\" | sort"),
        "lzf_compressed\nstring1\nstring2\n");

    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb -t str print -k \"%%k\" | sort"),
        "lzf_compressed\nstring1\nstring2\n");

    /* -T/--no-type */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb --no-type str print -k \"%%k\" | sort"),
        "mylist1\nmylist2\nmylist3\n");

    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb -T str print -k \"%%k\" | sort"),
        "mylist1\nmylist2\nmylist3\n");
}

static void test_rdb_cli_filter_expire(void **state) {
    UNUSED(state);
    sendRedisCmd("SET persistKey STAM", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("SET volatileKey XXX", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("HSET persistHash f1 v1", REDIS_REPLY_INTEGER, "1");
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("PEXPIRE volatileKey 10", REDIS_REPLY_INTEGER, "1");
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);
    runSystemCmd("cp %s %s > /dev/null", TMP_FOLDER("dump.rdb"), TMP_FOLDER("with_expires.rdb"));
    usleep(20000); /*20ms*/

    assert_string_equal(
        runSystemCmd("$RDB_CLI_CMD %s print -k \"%%k\" | sort", TMP_FOLDER("with_expires.rdb")),
        "persistHash\npersistKey\nvolatileKey\n");

    assert_string_equal(
        runSystemCmd("$RDB_CLI_CMD %s -e print -k \"%%k\" | sort", TMP_FOLDER("with_expires.rdb")),
        "volatileKey\n");

    assert_string_equal(
        runSystemCmd("$RDB_CLI_CMD %s -E print | sort", TMP_FOLDER("with_expires.rdb")),
        "0,persistHash,{...},hash,-1,1\n0,persistKey,STAM,string,-1,0\n");
}

static void test_rdb_cli_filter_mix(void **state) {
    UNUSED(state);

    /* Combine 'type' and 'key' filters */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb --type str --key string print -k \"%%k\" | sort"),
        "string1\nstring2\n");

    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_lists_strings.rdb -t str -k string print -k \"%%k\" | sort"),
        "string1\nstring2\n");
}

static void test_rdb_cli_input_fd_reader(void **state) {
    UNUSED(state);
    assert_string_equal(
        runSystemCmd(" cat ./test/dumps/single_key.rdb | $RDB_CLI_CMD - print -k \"%%k\" | sort"),
        "xxx\n");
}

static void test_rdb_cli_redis_auth(void **state) {
    UNUSED(state);
    /* check password authentication */
    setupRedisServer("--requirepass abc");

    /* auth custom command */
    runSystemCmd(" $RDB_CLI_CMD ./test/dumps/single_key.rdb redis -a 2 auth abc -p %d  > /dev/null ", getRedisPort());

    /* auth pwd */
    sendRedisCmd("FLUSHALL", REDIS_REPLY_ERROR, NULL); /* expected to fail */
    sendRedisCmd("AUTH abc", REDIS_REPLY_STATUS, NULL); /* now expected to succeed */
    runSystemCmd(" $RDB_CLI_CMD ./test/dumps/single_key.rdb redis --password abc -p %d  > /dev/null ", getRedisPort());

    /* auth user */
    int major;
    getTargetRedisVersion(&major, NULL);
    /* ACL available since 6.0 */
    if (major>=6) {
        sendRedisCmd("ACL SETUSER newuser on >newpwd  +@all ~*",
                     REDIS_REPLY_STATUS, NULL);
        sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
        runSystemCmd(
                " $RDB_CLI_CMD ./test/dumps/single_key.rdb redis -P newpwd -u newuser -p %d  > /dev/null ",
                getRedisPort());
    }

    teardownRedisServer();
}

static void test_rdb_cli_print(void **state) {
    UNUSED(state);
    sendRedisCmd("SET ABC STAM", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("HSET myhash f1 v1", REDIS_REPLY_INTEGER, "1");
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);

    /* Check default ouput of print */
    assert_string_equal(
        runSystemCmd("$RDB_CLI_CMD %s print | sort", TMP_FOLDER("dump.rdb")),
        "0,ABC,STAM,string,-1,0\n0,myhash,{...},hash,-1,1\n");

    /* Check customized output */
    assert_string_equal(
        runSystemCmd("$RDB_CLI_CMD %s print -k \"%%k\" | sort", TMP_FOLDER("dump.rdb")),
        "ABC\nmyhash\n");

    /* Check customized aux-val output */
    assert_string_equal(
        runSystemCmd(" $RDB_CLI_CMD ./test/dumps/multiple_dbs.rdb print -k \"\" -a \"%%f=%%v\""),
        "redis-ver=255.255.255\nredis-bits=64\nctime=1683103535\nused-mem=967040\naof-base=0\n");
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
            cmocka_unit_test_setup(test_rdb_cli_filter_expire, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_filter_mix, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_input_fd_reader, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_redis_auth, setupTest),
            cmocka_unit_test_setup(test_rdb_cli_print, setupTest),
    };

    int res = cmocka_run_group_tests(tests, NULL, NULL);
    return res;
}
