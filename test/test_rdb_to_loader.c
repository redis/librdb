#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "test_common.h"

const char *redisServerFolder;
pid_t redis_pid = 0;
void cleanupRedisServer() {
    if (redis_pid)
        kill(redis_pid, SIGTERM);
}

void setupGroup() {
    int status;
    pid_t pid = fork();
    assert_int_not_equal (pid, -1);

    redisPort = findFreePort(6500, 6600);

    if (pid == 0) { /* child */
        char redisPortStr[10];
        char fullpath[256];

        printf ("Redis port: %d\n", redisPort);

        snprintf(fullpath, 255, "%s/%s", redisServerFolder, "redis-server");
        snprintf(redisPortStr, sizeof(redisPortStr), "%d", redisPort);
        execl(fullpath, fullpath, "--port", redisPortStr , "--dir", "./test/tmp/", "--logfile", "./redis.log", (char*)NULL);

        /* If execl returns, an error occurred! */
        perror("execl");
        exit(1);
    } else { /* parent */
        UNUSED(status);

        /* wait to server to become available */
        runSystemCmdRetry(5, "%s/redis-cli -p %d ping | grep -i pong > /dev/null", redisServerFolder, redisPort);

        redis_pid = pid;

        /* Close any subprocess in case of exit due to error flow */
        atexit(cleanupRedisServer);
    }
}

void teardownGroup() {
    runSystemCmd("%s/redis-cli -p %d shutdown > /dev/null", redisServerFolder, redisPort);
    wait(NULL);
    printf("Teardown complete.\n");
}

static int setupTest(void **state) {
    UNUSED(state);
    runSystemCmd("%s/redis-cli -p %d flushall > /dev/null", redisServerFolder, redisPort);
    runSystemCmd("%s/redis-cli -p %d save > /dev/null", redisServerFolder, redisPort);
    return 0;
}

/* Testing RESP TCP against live server:
 * 1. Run RDB to Json (out1.json)
 * 2. Run RDB against Redis and save DUMP-RDB
 * 3. From DUMP-RDB generate Json (out2.json)
 * 4. assert_json_equal(out1.json , out2.json)
 */
static void test_rdb_to_loader_common(const char *rdbfile) {
    RdbParser *parser;
    RdbStatus status;

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    RdbxToRespConf rdb2respConf = {1, {10, NULL}};
    RdbxToJsonConf rdb2jsonConf = {RDB_LEVEL_DATA, RDBX_CONV_JSON_ENC_PLAIN, 1, 1};

    /* RDB to JSON */
    parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
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
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser, &rdb2respConf));
    assert_non_null(RDBX_createRespToTcpLoader(parser, rdbToResp, "127.0.0.1", redisPort));
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);

    /* DUMP-RDB from Redis */
    runSystemCmd("%s/redis-cli -p %d save > /dev/null", redisServerFolder, redisPort);

    /* DUMP-RDB to JSON */
    parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
    assert_non_null(RDBX_createReaderFile(parser, TMP_FOLDER("dump.rdb")));
    assert_non_null(RDBX_createHandlersToJson(parser,
                                              TMP_FOLDER("out2.json"),
                                              &rdb2jsonConf));
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);

    /* Json (from DUMP-RDB) vs. expected Json */
    assert_json_equal(TMP_FOLDER("out1.json"), TMP_FOLDER("out2.json"));
}

static void test_rdb_to_loader_single_string(void **state) {
    UNUSED(state);
    test_rdb_to_loader_common(DUMP_FOLDER("single_key.rdb"));
}

static void test_rdb_to_loader_single_list(void **state) {
    UNUSED(state);
    test_rdb_to_loader_common(DUMP_FOLDER("single_list.rdb"));
}

static void test_rdb_to_loader_multiple_lists_strings(void **state) {
    UNUSED(state);
    test_rdb_to_loader_common(DUMP_FOLDER("multiple_lists_strings.rdb"));
}

/*************************** group_rdb_to_loader *******************************/
int group_rdb_to_loader(const char *folder) {
    redisServerFolder = folder;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup(test_rdb_to_loader_single_list, setupTest),
            cmocka_unit_test_setup(test_rdb_to_loader_single_string, setupTest),
            cmocka_unit_test_setup(test_rdb_to_loader_multiple_lists_strings, setupTest),
    };

    setupGroup();
    int res = cmocka_run_group_tests(tests, NULL, NULL);
    teardownGroup();

    return res;
}