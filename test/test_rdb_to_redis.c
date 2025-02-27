#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <assert.h>
#include "test_common.h"

int serverMajorVer, serverMinorVer;

void dummyLogger(RdbLogLevel l, const char *msg) { UNUSED(l, msg); }

static int setupTest(void **state) {
    UNUSED(state);
    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);

    /* FUNCTION FLUSH if redis version is 7.0 or higher */
    if (serverMajorVer >= 7) sendRedisCmd("FUNCTION FLUSH", REDIS_REPLY_STATUS, NULL);
    return 0;
}

void rdb_to_tcp(const char *rdbfile, int pipelineDepth, int isRestore, char *respFileName) {
    RdbxRespToRedisLoader *r2r;
    RdbxToResp *rdbToResp1, *rdbToResp2;
    RdbStatus status;

    RdbxToRespConf rdb2respConf = {
        .supportRestore = isRestore,
        .dstRedisVersion = getTargetRedisVersion(NULL, NULL),
        .supportRestoreModuleAux = isSupportRestoreModuleAux()
    };

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(rdbToResp1 = RDBX_createHandlersToResp(parser, &rdb2respConf));
    assert_non_null(r2r = RDBX_createRespToRedisTcp(parser, rdbToResp1, NULL, "127.0.0.1", getRedisPort()));
    if (respFileName) {
        assert_non_null(rdbToResp2 = RDBX_createHandlersToResp(parser, &rdb2respConf));
        assert_non_null(RDBX_createRespToFileWriter(parser, rdbToResp2, respFileName));
    }
    RDBX_setPipelineDepth(r2r, pipelineDepth);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);
}

static void rdb_to_json(const char *rdbfile, const char *outfile) {
    RdbStatus status;
    RdbxToJsonConf rdb2jsonConf = {
            .level = RDB_LEVEL_DATA,
            .encoding = RDBX_CONV_JSON_ENC_PLAIN,
            .includeAuxField = 0,
            .includeFunc = 1,
            .flatten = 1,
            .includeStreamMeta = 0, /* too messy nested to compare json */
    };

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(RDBX_createHandlersToJson(parser, outfile, &rdb2jsonConf));
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);
    RDB_deleteParser(parser);
}

/* Is saving RDB, and librdb reload generates same digest
 *
 * isDigest - if set, compare DB digest before and after reload
 * isRestore - if set, use RESTORE command after reload. Otherwise, plain commands
 */
static void rdb_save_librdb_reload_eq(int isRestore, char *serverRdbFile) {
    char *res;
    const char *rdbfile = TMP_FOLDER("reload.rdb");
    char expectedSha[100];

    /* Calculate DB isDigest */
    res = sendRedisCmd("DEBUG DIGEST", REDIS_REPLY_STATUS, NULL);
    memcpy(expectedSha, res, strlen(res) + 1);

    /* Keep aside rdb file */
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);
    runSystemCmd("rm %s || true", rdbfile);
    runSystemCmd("cp %s %s > /dev/null", serverRdbFile, rdbfile);

    /* Flush Redis */
    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);

    /* Reload the RDB file */
    rdb_to_tcp(rdbfile, 1, isRestore, NULL);

    sendRedisCmd("DEBUG DIGEST", REDIS_REPLY_STATUS, expectedSha);
}

/*
 * Testing RESP against live server:
 * 1. Convert RDB to Json (out1.json)
 * 2. Upload RDB against Redis and save DUMP-RDB
 * 3. From DUMP-RDB generate Json (out2.json)
 * 4. assert_json_equal(out1.json , out2.json)
 *
 * The test will run twice against:
 * A. old Redis target (no RESTORE)
 * B. new Redis target (RESTORE)
 *
 * Note: This test cannot tell if the parser really run RESTORE command in
 * the background. test_rdb_to_resp.c verifies that RESTORE command is used
 * only when it should.
 */
static void test_rdb_to_redis_common(const char *rdbfile, int ignoreListOrder, char *expRespCmd, const char *expJsonFile) {

    /* test one time without RESTORE, Playing against old version.
     * and one time with RESTORE, Playing against new version. */
    for (int isRestore = 0 ; isRestore <= 1 ; ++isRestore) {
        sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);

        /* FUNCTION FLUSH */
        if (serverMajorVer >= 7)
            sendRedisCmd("FUNCTION FLUSH", REDIS_REPLY_STATUS, NULL);

        /* 1. Convert RDB to Json (out1.json) */
        rdb_to_json(rdbfile, TMP_FOLDER("out1.json"));

        /* 2. Upload RDB against Redis and save DUMP-RDB */
        rdb_to_tcp(rdbfile, 1, isRestore, TMP_FOLDER("cmd.resp"));
        sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);

        if (expRespCmd && !isRestore) {
            /* Verify corresponding RESP commands includes `expRespCmd` */
             assert_file_payload(TMP_FOLDER("cmd.resp"),
                                 expRespCmd,
                                 strlen(expRespCmd),
                                 M_SUBSTR, 1);
        }

        /* 3. From DUMP-RDB generate Json (out2.json) */
        rdb_to_json(TMP_FOLDER("dump.rdb"), TMP_FOLDER("out2.json"));

        /* 4. Verify that dumped RDB and converted to json is as expected  */
        if (expJsonFile)
            assert_json_equal(expJsonFile, TMP_FOLDER("out2.json"), 0);
        else
            assert_json_equal(TMP_FOLDER("out1.json"), TMP_FOLDER("out2.json"), ignoreListOrder);
    }
}

static void test_rdb_to_redis_single_string(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("single_key.rdb"), 0, "SET", NULL);
}

static void test_rdb_to_redis_single_list(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("quicklist2_v11.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_multiple_lists_strings(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("multiple_lists_strings.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_multiple_lists_strings_pipeline_depth_1(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("multiple_lists_strings.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_plain_list(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_list_v6.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_quicklist(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("quicklist.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_single_ziplist(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("ziplist_v3.rdb"), 0, "$5\r\nRPUSH", NULL);
}

static void test_rdb_to_redis_hash(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_v3.rdb"), 0, "$4\r\nHSET", NULL);
}

static void test_rdb_to_redis_hash_with_expire(void **state) {
    UNUSED(state);
    const char* configs[] = {
        "CONFIG SET HASH-MAX-LISTPACK-ENTRIES 0",   /*HT*/
        "CONFIG SET HASH-MAX-LISTPACK-ENTRIES 512", /*listpack*/
    };

    /* hash-field-expiration available since 7.4 */
    if ((serverMajorVer<7) || ((serverMajorVer==7) && (serverMinorVer<4)))
        skip();

    setupRedisServer("--enable-debug-command yes --dbfilename expire.rdb");
    for (int i = 0; i < 2; i++) {
        sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
        sendRedisCmd(configs[i], REDIS_REPLY_STATUS, NULL);
        sendRedisCmd("HSET myhash f4 v1 f5 v2 f6 v3", REDIS_REPLY_INTEGER, "3");
        sendRedisCmd("HPEXPIREAT myhash 70368744177663 FIELDS 2 f4 f5",
                     REDIS_REPLY_ARRAY, "1 1");  /*time=0x3fffffffffff*/
        rdb_save_librdb_reload_eq(0 /*restore*/, TMP_FOLDER("expire.rdb"));
        rdb_save_librdb_reload_eq(1 /*restore*/, TMP_FOLDER("expire.rdb"));
        sendRedisCmd("HPEXPIRETIME myhash FIELDS 3 f4 f5 f6", REDIS_REPLY_ARRAY,
                     "70368744177663 70368744177663 -1"); /* verify expected output */
    }
    teardownRedisServer();
}

static void test_rdb_to_redis_hash_zl(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_zl_v6.rdb"), 0, "$4\r\nHSET", NULL);
}

static void test_rdb_to_redis_hash_lp(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_lp_v11.rdb"), 0, "$4\r\nHSET", NULL);
}

static void test_rdb_to_redis_hash_zm(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("hash_zm_v2.rdb"), 0, "$4\r\nHSET", NULL);
}

static void test_rdb_to_redis_plain_set(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_set_v6.rdb"), 1, "$4\r\nSADD", NULL);
}

static void test_rdb_to_redis_set_is(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_is_v11.rdb"), 1, "$4\r\nSADD", NULL);
}

static void test_rdb_to_redis_set_lp(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_lp_v11.rdb"), 1, "$4\r\nSADD", NULL);
}

static void test_rdb_to_redis_plain_zset(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_zset_v6.rdb"), 1, "$4\r\nZADD", NULL);
}

static void test_rdb_to_redis_plain_zset_2(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("plain_zset_2_v11.rdb"), 1, "$4\r\nZADD", NULL);
}

static void test_rdb_to_redis_zset_lp(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("zset_lp_v11.rdb"), 1, "$4\r\nZADD", NULL);
}

static void test_rdb_to_redis_zset_zl(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("zset_zl_v6.rdb"), 1, "$4\r\nZADD", NULL);
}

static void test_rdb_to_redis_multiple_dbs(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("multiple_dbs.rdb"), 1, NULL, NULL);
}

static void test_rdb_to_redis_set_expired(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_expired_v11.rdb"), 1, "$9\r\nPEXPIREAT",
                             DUMP_FOLDER("set_expired.json"));
}

static void test_rdb_to_redis_set_not_expired(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("set_not_expired_v11.rdb"), 1,"$9\r\nPEXPIREAT",
                             DUMP_FOLDER("set_not_expired.json"));
}

static void test_rdb_to_redis_policy_lfu(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("mem_policy_lfu.rdb"), 1, NULL,
                             DUMP_FOLDER("mem_policy_lfu.json"));
}

static void test_rdb_to_redis_policy_lru(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("mem_policy_lru.rdb"), 1, NULL,
                             DUMP_FOLDER("mem_policy_lru.json"));
}

static void test_rdb_to_redis_function(void **state) {
    UNUSED(state);
    /* function available since 7.0 */
    if (serverMajorVer < 7)
        skip();

    test_rdb_to_redis_common(DUMP_FOLDER("function.rdb"), 1, NULL, NULL);
    sendRedisCmd("FUNCTION LIST", REDIS_REPLY_ARRAY, "myfunc");
}

/* test relied on rdbtest module within redis repo, if available */
static void test_rdb_to_redis_module(void **state) {
    UNUSED(state);

    /* Skip test if testrdb is not loaded */
    if (! strstr( sendRedisCmd("MODULE LIST", REDIS_REPLY_ARRAY, NULL), "testrdb" ) )
        skip();

    /* Apply testrdb SET module command on Redis */
    sendRedisCmd("testrdb.set.key key1 value1", REDIS_REPLY_INTEGER, NULL);
    sendRedisCmd("testrdb.set.key 123456 7890", REDIS_REPLY_INTEGER, NULL);

    /* Save rdb aside */
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);
    runSystemCmd("cp %s %s > /dev/null", TMP_FOLDER("dump.rdb"), TMP_FOLDER("test_rdb_to_redis_module.rdb"));

    /* Flushall Redis database */
    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);

    /* Run the parser against Redis and also let it output RESP to a file */
    rdb_to_tcp(TMP_FOLDER("test_rdb_to_redis_module.rdb"), 1, 1, TMP_FOLDER("rdb_to_tcp.resp"));

    /* Verify resp file contains "RESTOREMODAUX & RESTORE key1" */
    assert_file_payload(TMP_FOLDER("rdb_to_tcp.resp"), STR_AND_SIZE("RESTORE\r\n$4\r\nkey1"), M_SUBSTR, 1);

    /* For Redis enterprise only, verify module-aux data restored (RESTOREMODAUX) as expected */
    if (isSupportRestoreModuleAux())
        assert_file_payload(TMP_FOLDER("rdb_to_tcp.resp"), STR_AND_SIZE("RESTOREMODAUX"), M_SUBSTR, 1);

    /* Verify testrdb GET module command returns expected values from Redis */
    sendRedisCmd("testrdb.get.key key1", REDIS_REPLY_STRING, "value1");
    sendRedisCmd("testrdb.get.key 123456", REDIS_REPLY_STRING, "7890");
}

/*
 * Verify that librdb doesn't fail trying to load empty module
 *
 * In case of RDB was generated by a server with some module, but user didn't make
 * any use of that module. And now we try to load it to another server that was not
 * loaded with that module, the RDB parser will fail because the module always store
 * something in the AUX field, and the RDB parser will try to load it.
 *
 * In order to overcome this issue, A module that its AUX payload is less than
 * 15 Bytes (including RDB version and checksum) counted as AUX field of an empty
 * Module (not in use), then the parser, when restoring the empty module, it
 * should ignore returned error: "-ERR Module X not found..."
 *
 * Redis enterprise only
 */
static void test_rdb_to_redis_module_aux_empty(void **state) {
    UNUSED(state);

    if (!isSupportRestoreModuleAux())
        skip();

    rdb_to_tcp(DUMP_FOLDER("module_aux_empty.rdb"), 1, 1, NULL);
}

static void test_rdb_to_redis_stream(void **state) {
    UNUSED(state);
    test_rdb_to_redis_common(DUMP_FOLDER("stream_v11.rdb"), 1, NULL, NULL);
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
                .funcLibReplaceIfExist=0,
                .supportRestore = 1,
                .dstRedisVersion = getTargetRedisVersion(NULL, NULL),
        };

        /* create key `mylist62` that goanna appear as well in the RDB file */
        sendRedisCmd("set mylist62 1", REDIS_REPLY_STATUS, NULL);

        /* RDB to TCP */
        RdbxToResp *rdbToResp;
        parser = RDB_createParserRdb(NULL);

        /* set dummy logger. Goanna have expected error */
        RDB_setLogger(parser, dummyLogger);

        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("100_lists.rdb")));
        assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser, &rdb2respConf));

        assert_non_null(RDBX_createRespToRedisTcp(parser,
                                                  rdbToResp,
                                                  NULL,
                                                  "127.0.0.1",
                                                  getRedisPort()));

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

/* This test verifies the behavior of the RDB parser when the `hideKeysInLog`
 * option is set. Specifically, it ensures that keys in error messages are
 * replaced with the first 8 hex digits of their SHA256 hash, rather than being
 * logged directly.
 */
static void test_rdb_to_redis_hide_keys_in_log(void **state) {
    UNUSED(state);
    RdbParser *p;
    RdbStatus status;

    RdbxToRespConf rdb2respConf = {
            .delKeyBeforeWrite = 0,
            .funcLibReplaceIfExist=0,
            .supportRestore = 1,
            .dstRedisVersion = getTargetRedisVersion(NULL, NULL),
    };

    /* create key that goanna appear as well in the RDB file */
    sendRedisCmd("set mylist27 1", REDIS_REPLY_STATUS, NULL);

    /* RDB to TCP */
    RdbxToResp *rdbToResp;
    p = RDB_createParserRdb(NULL);

    /* hide keys in log */
    RDB_hideKeysInLog(p);

    RDB_setLogger(p, dummyLogger);
    assert_non_null(RDBX_createReaderFile(p, DUMP_FOLDER("100_lists.rdb")));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, &rdb2respConf));

    assert_non_null(RDBX_createRespToRedisTcp(p,
                                              rdbToResp,
                                              NULL,
                                              "127.0.0.1",
                                              getRedisPort()));

    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    
    /* verify returned error code. Verify error message. */
    assert_int_equal(status, RDB_STATUS_ERROR);
    assert_int_equal(RDB_getErrorCode(p), RDBX_ERR_RESP_WRITE);
    
    /* Expected to print first 8 hex digits of SHA256(key) instead of the key 
     * itself. To eval via bash apply:
     * > echo -n "mylist27" | sha256sum | cut -c 1-8 
     */
    printf("%s\n", RDB_getErrorMessage(p));
    assert_non_null(strstr(RDB_getErrorMessage(p), "0bdab52c")); /* sha256("mylist27") */
    
    /* Verify that the key is not in the log */
    assert_null(strstr(RDB_getErrorMessage(p), "mylist27"));    
    
    RDB_deleteParser(p);
}

/* Load "function.rdb" more than once. If 'funcLibReplaceIfExist' is not set, then
 * expected to fail */
static void test_rdb_to_redis_func_lib_replace_if_exist(void **state) {
    UNUSED(state);
    int funcLibReplaceIfExistArr[] = {0, 0, 1};
    int expectedStatus[] = {RDB_STATUS_OK, RDB_STATUS_ERROR, RDB_STATUS_OK};

    /* function available since 7.0 */
    if (serverMajorVer < 7)
        skip();

    for (int i = 0 ; i < 3 ; i++) {
        RdbStatus status;
        RdbxToRespConf rdb2respConf = {
                .delKeyBeforeWrite = 0,
                .funcLibReplaceIfExist = funcLibReplaceIfExistArr[i],
                .supportRestore = 1,
                .dstRedisVersion = getTargetRedisVersion(NULL, NULL),
        };

        /* RDB to TCP */
        RdbxToResp *rdbToResp;
        RdbParser *parser = RDB_createParserRdb(NULL);
        RDB_setLogger(parser, dummyLogger);
        assert_non_null(
                RDBX_createReaderFile(parser, DUMP_FOLDER("function.rdb")));
        assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser,
                                                              &rdb2respConf));
        assert_non_null(RDBX_createRespToRedisTcp(parser,
                                                  rdbToResp,
                                                  NULL,
                                                  "127.0.0.1",
                                                  getRedisPort()));

        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);


        /* Verify myfunc is loaded (either succeeded or not) */
        sendRedisCmd("FUNCTION LIST", REDIS_REPLY_ARRAY, "myfunc");

        assert_int_equal(expectedStatus[i], status);

        if (status != RDB_STATUS_OK) {
            /* verify returned error code. Verify error message. */
            RdbRes err = RDB_getErrorCode(parser);
            assert_int_equal(err, RDBX_ERR_RESP_WRITE);
            assert_non_null(strstr(RDB_getErrorMessage(parser), "mylib"));
        }
        RDB_deleteParser(parser);
    }
}

/* Create dummy TCP server that doesn't respond to the client and verify that
 * the parser retries after TIMEOUT_SECONDS. Not part of CI since it takes to long */
int countdownRetries;
RdbParser *parser;
void dummyTcpTimeoutLogger(RdbLogLevel l, const char *msg) {
    UNUSED(l);
    if (strstr(msg, "No reply from redis-server for") != NULL)
        if (--countdownRetries == 0)
            RDB_reportError(parser, (RdbRes)12345678, "Inject error to end the test");
}
void test_rdb_tcp_timeout(void **state) {
    UNUSED(state);
    const int RECV_TIMEOUT_SECONDS = 10; /* socket retry timeout */
    int test_retries = 3; /* limit test to finite number of retries */
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    /* expected to retry 3 times before ending the test */
    countdownRetries = test_retries;

    /* Dummy TCP server that only receives messages but does not respond */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(server_fd >= 0);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(0);
    assert_int_equal(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), 0);
    socklen_t addr_len = sizeof(server_addr);
    assert_int_equal(getsockname(server_fd, (struct sockaddr *)&server_addr, &addr_len), 0);
    int assigned_port = ntohs(server_addr.sin_port);
    assert_int_equal(listen(server_fd, 1), 0);
    printf("Dummy TCP server started, waiting for client to connect...\n");

    parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_INF);
    RDB_setLogger(parser, dummyTcpTimeoutLogger);
    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));

    RdbxToRespConf rdb2respConf = {
            .supportRestore = 1,
            .dstRedisVersion = getTargetRedisVersion(NULL, NULL),
            .supportRestoreModuleAux = isSupportRestoreModuleAux()
    };

    RdbxToResp *rdbToResp;
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(parser, &rdb2respConf));
    assert_non_null(RDBX_createRespToRedisTcp(parser, rdbToResp, NULL, "127.0.0.1", assigned_port));

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    assert_true(client_fd >= 0);

    /* Start the timer to measure timeout and run parser */
    time_t start_time = time(NULL);
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);

    /* Verify dummy error code */
    assert_int_equal(RDB_getErrorCode(parser), 12345678);

    /* Measure elapsed time and verify it's within the expected range */
    time_t elapsedTime = time(NULL) - start_time;
    int expectedTime = RECV_TIMEOUT_SECONDS * test_retries;
    printf("Elapsed time: %ld, expected time: %d\n", elapsedTime, expectedTime);
    assert_in_range(elapsedTime, expectedTime - 2, expectedTime + 2);

    RDB_deleteParser(parser);
    close(client_fd);
    close(server_fd);
}

/*************************** group_rdb_to_redis *******************************/
int group_rdb_to_redis(void) {

    if (!isSetRedisServer()) {
        printf("[  SKIPPED ] (Redis installation folder is not configured)\n");
        return 0;
    }

    getTargetRedisVersion(&serverMajorVer, &serverMinorVer);

    const struct CMUnitTest tests[] = {
            /* string */
            cmocka_unit_test_setup(test_rdb_to_redis_single_string, setupTest),
            /* list */
            cmocka_unit_test_setup(test_rdb_to_redis_single_list, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_plain_list, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_quicklist, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_single_ziplist, setupTest),
            /* hash */
            cmocka_unit_test_setup(test_rdb_to_redis_hash, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_with_expire, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_zl, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_lp, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hash_zm, setupTest),
            /* set */
            cmocka_unit_test_setup(test_rdb_to_redis_plain_set, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_set_is, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_set_lp, setupTest),
            /* zset */
            cmocka_unit_test_setup(test_rdb_to_redis_plain_zset, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_plain_zset_2, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_zset_lp, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_zset_zl, setupTest),

            /* module */
            cmocka_unit_test_setup(test_rdb_to_redis_module, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_module_aux_empty, setupTest),

            /* stream */
            cmocka_unit_test_setup(test_rdb_to_redis_stream, setupTest),

            /* expired keys */
            cmocka_unit_test_setup(test_rdb_to_redis_set_expired, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_set_not_expired, setupTest),

            /* mem policy */
            cmocka_unit_test_setup(test_rdb_to_redis_policy_lfu, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_policy_lru, setupTest),

            /* misc */
            cmocka_unit_test_setup(test_rdb_to_redis_multiple_lists_strings, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_multiple_lists_strings_pipeline_depth_1, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_del_before_write, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_hide_keys_in_log, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_multiple_dbs, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_function, setupTest),
            cmocka_unit_test_setup(test_rdb_to_redis_func_lib_replace_if_exist, setupTest),
            //cmocka_unit_test_setup(test_rdb_tcp_timeout, setupTest), /* too long to run */
    };

    int res = cmocka_run_group_tests(tests, NULL, NULL);
    return res;
}
