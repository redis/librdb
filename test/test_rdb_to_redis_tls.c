#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "test_common.h"

#ifdef USE_OPENSSL

static int setupTest(void **state) {
    UNUSED(state);    
    
    /* Flush and save */
    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);
    sendRedisCmd("SAVE", REDIS_REPLY_STATUS, NULL);

    /* FUNCTION FLUSH if redis version is 7.0 or higher */
    static int serverMajorVer = 0;
    static int serverMinorVer = 0;
    if (!serverMajorVer) getTargetRedisVersion(&serverMajorVer, &serverMinorVer);
    if (serverMajorVer >= 7) sendRedisCmd("FUNCTION FLUSH", REDIS_REPLY_STATUS, NULL);
    
    return 0;
}

/* Test basic TLS connection with server verification */
static void test_tls_basic_connection(void **state) {
    UNUSED(state);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);

    /* Create SSL config with CA certificate for server verification */
    RdbxSSLConfig sslConfig = {
        .cacert_filename = "./test/tls/ca.crt",
        .verify_mode = RDBX_SSL_VERIFY_PEER,
        .server_name = "Server-only"  /* SNI - matches certificate CN */
    };

    RdbxToRespConf conf = {0};

    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
    RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, &conf);
    assert_non_null(rdbToResp);

    /* Connect with TLS to the TLS port */
    RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(
        parser, rdbToResp, NULL, "127.0.0.1", getRedisTlsPort(), &sslConfig);
    assert_non_null(r2r);

    /* Parse and send data */
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);

    RDB_deleteParser(parser);

    /* Verify via non-TLS port that data was written */
    sendRedisCmd("GET xxx", REDIS_REPLY_STRING, "111");
}

/* Test TLS connection with mutual authentication (client certificate) */
static void test_tls_mutual_auth(void **state) {
    UNUSED(state);

    /* Restart Redis to require client certificates */

    if (!setupRedisServerTls("--loglevel verbose --tls-auth-clients yes")) {
        skip();
        return;
    }

    sendRedisCmd("FLUSHALL", REDIS_REPLY_STATUS, NULL);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);

    /* Create SSL config with client certificate */
    RdbxSSLConfig sslConfig = {
        .cacert_filename = "./test/tls/ca.crt",
        .cert_filename = "./test/tls/client.crt",
        .private_key_filename = "./test/tls/client.key",
        .verify_mode = RDBX_SSL_VERIFY_PEER,
        .server_name = "Server-only"
    };

    RdbxToRespConf conf = {0};

    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
    RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, &conf);
    assert_non_null(rdbToResp);

    /* Connect with TLS and client cert to the TLS port */
    RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(
        parser, rdbToResp, NULL, "127.0.0.1", getRedisTlsPort(), &sslConfig);
    assert_non_null(r2r);

    /* Parse and send data */
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);

    RDB_deleteParser(parser);

    /* Verify data was written - the RDB file contains key "xxx" with value "111" */
    sendRedisCmd("GET xxx", REDIS_REPLY_STRING, "111");
    teardownRedisServer();
}

/* Test TLS connection with insecure mode (no verification) */
static void test_tls_insecure_mode(void **state) {
    UNUSED(state);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);

    /* Create SSL config without verification */
    RdbxSSLConfig sslConfig = {
        .verify_mode = RDBX_SSL_VERIFY_NONE
    };

    RdbxToRespConf conf = {0};

    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
    RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, &conf);
    assert_non_null(rdbToResp);

    /* Connect with TLS but no verification to the TLS port */
    RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(
        parser, rdbToResp, NULL, "127.0.0.1", getRedisTlsPort(), &sslConfig);
    assert_non_null(r2r);

    /* Parse and send data */
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);

    RDB_deleteParser(parser);

    /* Verify data was written - the RDB file contains key "xxx" with value "111" */
    sendRedisCmd("GET xxx", REDIS_REPLY_STRING, "111");
}

/* Test TLS connection using hostname instead of IP address */
static void test_tls_hostname_resolution(void **state) {
    UNUSED(state);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);

    /* Create SSL config with CA certificate for server verification */
    RdbxSSLConfig sslConfig = {
        .cacert_filename = "./test/tls/ca.crt",
        .verify_mode = RDBX_SSL_VERIFY_PEER,
        .server_name = "Server-only"  /* SNI - matches certificate CN */
    };

    RdbxToRespConf conf = {0};

    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
    RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, &conf);
    assert_non_null(rdbToResp);

    /* Connect with TLS using "localhost" hostname instead of "127.0.0.1" */
    RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(
        parser, rdbToResp, NULL, "localhost", getRedisTlsPort(), &sslConfig);
    assert_non_null(r2r);

    /* Parse and send data */
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);

    RDB_deleteParser(parser);

    /* Verify data was written - the RDB file contains key "xxx" with value "111" */
    sendRedisCmd("GET xxx", REDIS_REPLY_STRING, "111");
}

/* Test TLS connection with custom cipher configuration - uses multiple lists/strings RDB */
static void test_tls_custom_ciphers(void **state) {
    UNUSED(state);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);

    /* Create SSL config with custom cipher list (high security ciphers only) */
    RdbxSSLConfig sslConfig = {
        .cacert_filename = "./test/tls/ca.crt",
        .verify_mode = RDBX_SSL_VERIFY_PEER,
        .server_name = "Server-only",
        .ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
#ifdef TLS1_3_VERSION
        .ciphersuites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
#endif
    };

    RdbxToRespConf conf = {0};

    assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
    RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, &conf);
    assert_non_null(rdbToResp);

    /* Connect with TLS using custom ciphers */
    RdbxRespToRedisLoader *r2r = RDBX_createRespToRedisTcp(
        parser, rdbToResp, NULL, "127.0.0.1", getRedisTlsPort(), &sslConfig);
    assert_non_null(r2r);

    /* Parse and send data */
    RdbStatus status;
    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(status, RDB_STATUS_OK);

    RDB_deleteParser(parser);

    /* Verify data was written - the RDB file contains string "string1" with value "blaa" */
    sendRedisCmd("GET xxx", REDIS_REPLY_STRING, "111");
}

#endif /* USE_OPENSSL */

int group_rdb_to_redis_tls(void) {
#ifdef USE_OPENSSL

    /* Try to setup Redis with TLS - setupRedisServerTls will print warning if it fails */
    if (setupRedisServerTls("--loglevel verbose") == 0) {
        printf("[  SKIPPED ] (Failed to setup Redis with TLS.\n");
        return 1;
    }
    
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_tls_basic_connection, setupTest),
        cmocka_unit_test_setup(test_tls_mutual_auth, setupTest),
        cmocka_unit_test_setup(test_tls_insecure_mode, setupTest),
        cmocka_unit_test_setup(test_tls_hostname_resolution, setupTest),
        cmocka_unit_test_setup(test_tls_custom_ciphers, setupTest),
    };

    printf("\n--- Test Group: group_rdb_to_redis_tls ---\n");
    int res = cmocka_run_group_tests(tests, NULL, NULL);
    
    teardownRedisServer();
    return res;
#else
    printf("\n--- Test Group: group_rdb_to_redis_tls ---\n");
    printf("[  SKIPPED ] (librdb was not compiled with TLS support)\n\n");
    return 0;
#endif
}

