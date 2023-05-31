#include <string.h>
#include <unistd.h>
#include "test_common.h"

/* todo: support select db, expiry */

static void testRdbToRespCommon(const char *rdbfile,
                                char *expResp,
                                RdbxToRespConf *conf,
                                int expNumCmds)
{
    static int outputs = 0;
    static char respfile[50];
    snprintf(respfile, sizeof(respfile), "./test/tmp/output%d.resp", ++outputs);
    RdbStatus  status;
    RdbxToResp *rdbToResp;
    RdbxRespFileWriter *writer;
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERROR);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, conf));
    assert_non_null(writer = RDBX_createRespFileWriter(p, rdbToResp, respfile));
    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    /* verify number of commands counted */
    UNUSED(expNumCmds);
    RDB_deleteParser(p);
    assert_payload_file(respfile, expResp, NULL);
}

static void test_r2r_single_string(void **state) {
    UNUSED(state);
    unsigned char expRespData[] = "*3\r\n$3\r\nSET\r\n$3\r\nxxx\r\n$3\r\n111\r\n";
    RdbxToRespConf r2rConf;

    memset(&r2rConf, 0, sizeof(r2rConf));
    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 10;
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespData, &r2rConf, 1);

    /* Avoid RESTORE command because corresponding RDB ver. of given Redis ver. < source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 0;
    r2rConf.restore.dstRedisVersion = "7.0";   /* resolved to rdb version 10 */
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespData, &r2rConf, 1);

    /* Configure not to use RESTORE command */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespData, &r2rConf, 1);

    /* Default configuration avoid RESTORE */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespData, NULL, 1);
}

static void test_r2r_single_string_restore(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;
    unsigned char expRespRestore[] = {
            0x2a, 0x34, 0x0d, 0x0a,  // *, 4, \r, \n
            0x24, 0x37, 0x0d, 0x0a,  // $, 7, \r, \n
            0x52, 0x45, 0x53, 0x54,  // R, E, S, T
            0x4f, 0x52, 0x45, 0x0d,  // O, R, E, \r
            0x0a, 0x24, 0x33, 0x0d,  // \n, $, 3, \r
            0x0a, 0x78, 0x78, 0x78,  // \n, x, x, x
            0x0d, 0x0a, 0x24, 0x31,  // \r, \n, $, 1
            0x0d, 0x0a, 0x30, 0x0d,  // \r, \n, 0, \r
            0x0a, 0x24, 0x31, 0x33,  // \n, $, 1, 3
            0x0d, 0x0a, 0x00, 0xc0,  // \r, \n, Null, ...
            0x6f, 0x0b, 0x00, 0xa6,  // ... (non printable)
            0x11, 0x98, 0xb1, 0x42,  // ... (non printable)
            0x3e, 0x16, 0x7d         // ... (non printable)
    };

    /* Use RESTORE command because target RDB ver. == source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 11;
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespRestore, &r2rConf, 1);

    /* Use RESTORE command because corresponding RDB ver. of given Redis ver. == source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 0;
    r2rConf.restore.dstRedisVersion = "7.2";
    testRdbToRespCommon(DUMP_FOLDER("single_key.rdb"), (char *) expRespRestore, &r2rConf, 1);
}

static void test_r2r_single_list(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;

    char expResp[] = "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval3\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval1\r\n";

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 6;
    testRdbToRespCommon(DUMP_FOLDER("single_list.rdb"), expResp, &r2rConf, 1);
}

static void test_r2r_single_list_restore(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;

    unsigned char expRespRestore[] = {
            0x2A, 0x34, 0x0D, 0x0A,  // '*', '4', '\r', '\n'
            0x24, 0x37, 0x0D, 0x0A,  // '$', '7', '\r', '\n'
            0x52, 0x45, 0x53, 0x54,  // 'R', 'E', 'S', 'T'
            0x4F, 0x52, 0x45, 0x0D,  // 'O', 'R', 'E', '\r'
            0x0A, 0x24, 0x36, 0x0D,  // '\n', '$', '6', '\r'
            0x0A, 0x6D, 0x79, 0x6C,  // '\n', 'm', 'y', 'l'
            0x69, 0x73, 0x74, 0x0D,  // 'i', 's', 't', '\r'
            0x0A, 0x24, 0x31, 0x0D,  // '\n', '$', '1', '\r'
            0x0A, 0x30, 0x0D, 0x0A,  // '\n', '0', '\r', '\n'
            0x24, 0x33, 0x39, 0x0D,  // '$', '3', '9', '\r'
            0x0A, 0x12, 0x01, 0x02,  // '\n', '\x12', '\x01', '\x02'
            0x19, 0x19, 0x00, 0x00,  // '\x19', '\x19', '\x00', '\x00'
            0x00, 0x03, 0x00, 0x84,  // '\x00', '\x03', '\x00', '\x84'
            0x76, 0x61, 0x6C, 0x33,  // 'v', 'a', 'l', '3'
            0x05, 0x84, 0x76, 0x61,  // '\x05', '\x84', 'v', 'a'
            0x6C, 0x32, 0x05, 0x84,  // 'l', '2', '\x05', '\x84'
            0x76, 0x61, 0x6C, 0x31,  // 'v', 'a', 'l', '1'
            0x05, 0xFF, 0x0B, 0x00,  // '\x05', '\xFF', '\x0B', '\x00'
            0xB1, 0x54, 0x39, 0xA7,  // '\xB1', 'T', '9', '\xA7'
            0x2D, 0xE4, 0xCA, 0xCA,  // '\x2D', '\xE4', '\xCA', '\xCA'
            0x27, 0x0D, 0x0A };      // '\x27', '\r', '\n'

    /* Use RESTORE command because target RDB ver. == source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 11;
    testRdbToRespCommon(DUMP_FOLDER("single_list.rdb"), (char *) expRespRestore, &r2rConf, 1);
}

static void test_r2r_multiple_lists_and_strings(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;

    char expResp[] = "*3\r\n$3\r\nSET\r\n$7\r\nstring2\r\n$9\r\nHi there!\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist1\r\n$2\r\nv1\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist3\r\n$2\r\nv3\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist3\r\n$2\r\nv2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist3\r\n$2\r\nv1\r\n"
                     "*3\r\n$3\r\nSET\r\n$14\r\nlzf_compressed\r\n$118\r\ncccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\r\n"
                     "*3\r\n$3\r\nSET\r\n$7\r\nstring1\r\n$4\r\nblaa\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist2\r\n$2\r\nv2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$7\r\nmylist2\r\n$2\r\nv1\r\n";

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 6;
    testRdbToRespCommon(DUMP_FOLDER("multiple_lists_strings.rdb"), expResp, &r2rConf, 1);
}
/*************************** group_rdb_to_resp *******************************/
int group_rdb_to_resp(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_r2r_single_string_restore),
            cmocka_unit_test(test_r2r_single_string),
            cmocka_unit_test(test_r2r_single_list_restore),
            cmocka_unit_test(test_r2r_single_list),
            cmocka_unit_test(test_r2r_multiple_lists_and_strings),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
