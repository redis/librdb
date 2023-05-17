#include <string.h>
#include "test_common.h"

static void test_r2s_single_string(void **state) {
    UNUSED(state);

    const char *rdbfile = PATH_DUMP_FOLDER("single_key.rdb");
    const char *respfile = PATH_TMP_FOLDER("single_key.resp");

    char expResp[] = "*3\r\n$3\r\nSET\r\n$3\r\nxxx\r\n$3\r\n111\r\n";

    RdbStatus  status;
    RdbxToRespConfig r2rConf;
    RdbxToResp *rdbToResp;
    r2rConf.targetRedisVer = "6.0"; /* todo  */
    RdbParser *p = RDB_createParserRdb(NULL);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, &r2rConf));
    assert_non_null(RDBX_createRespFileWriter(p, rdbToResp, respfile));
    RDB_setLogLevel(p, RDB_LOG_ERROR);

    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    RDB_deleteParser(p);
    assert_payload_file(respfile, expResp, 0);
}

static void test_r2s_single_list(void **state) {
    UNUSED(state);

    const char *rdbfile = PATH_DUMP_FOLDER("single_list.rdb");
    const char *respfile = PATH_TMP_FOLDER("single_list.resp");

    char expResp[] = "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval3\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval1\r\n";

    RdbStatus  status;
    RdbxToResp *rdbToResp;
    RdbxRespFileWriter *writer;
    RdbxToRespConfig config;
    config.targetRedisVer = "6.0"; /* todo  */
    RdbParser *p = RDB_createParserRdb(NULL);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, &config));
    assert_non_null(writer = RDBX_createRespFileWriter(p, rdbToResp, respfile));
    RDB_setLogLevel(p, RDB_LOG_ERROR);

    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    /* verify number of commands counted */
    assert_int_equal( RDBX_getRespFileWriterCmdCount(writer), 3);

    RDB_deleteParser(p);
    assert_payload_file(respfile, expResp, 0);
}

/*************************** group_rdb_to_json *******************************/
int group_rdb_to_resp(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_r2s_single_string),
            cmocka_unit_test(test_r2s_single_list),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
