#include <string.h>
#include <malloc.h>
#include "test_common.h"

/* This group of tests only partially check the RESP protocol output of
 * the parser by comparing the prefix of the output rather than maintaining
 * hardcoded and non-readable payload in the test. It is sufficient because test
 * "test_rdb_to_loader" will parse RESP commands output as well, apply them to
 * a live Redis server, and ensure that the reconstructed database matches the
 * source RDB file.
 *
 * Note that checking the prefix of whether it is starting of RESTORE command
 * is important here because test "test_rdb_to_loader" can get the same result,
 * either by applying RESTORE or plain Redis RESP commands.
 */

/* TODO: support select db, expiry */

void assert_resp_file(const char *filename, char *resp, int isPrefix, int expMatch) {
    char *filedata = readFile(filename, NULL);
    int result = (isPrefix) ? strncmp(filedata, resp, strlen(resp)) : strcmp(filedata, resp);

    if ( ((result != 0) && (expMatch)) || ((result == 0) && (!expMatch)) ) {
        printf("Expected payload %s %s %s match.\n",
               (isPrefix) ? "prefix" : "file",
               filename,
               (expMatch) ? "" : "not to");
        printf("---- %s ----\n", filename);
        printf ("%s", filedata);
        printf("\n---- Expected %s ----\n", (isPrefix) ? "prefix" : "file");
        printf("%s", resp);
        printf("\n------------\n");
        assert_true(0);
    }
    free(filedata);
}

static void testRdbToRespCommon(const char *rdbfilename,
                                RdbxToRespConf *conf,
                                char *expResp,
                                int isPrefix,
                                int expMatch)
{
    static int outputs = 0;
    static char rdbfile[100];
    static char respfile[100];

    /* build file path of input (rdb) file and output (resp) file */
    snprintf(rdbfile, sizeof(rdbfile), "./test/dumps/%s", rdbfilename);
    snprintf(respfile, sizeof(respfile), "./test/tmp/out%d_%s.resp", ++outputs, rdbfilename);
    RdbStatus  status;
    RdbxToResp *rdbToResp;
    RdbxRespFileWriter *writer;
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, conf));
    assert_non_null(writer = RDBX_createRespFileWriter(p, rdbToResp, respfile));
    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    /* verify number of commands counted */
    RDB_deleteParser(p);
    assert_resp_file(respfile, expResp, isPrefix, expMatch);
}

static void runWithAndWithoutRestore(const char *rdbfile) {
    RdbxToRespConf r2rConf;

    unsigned char restorePrefix[] = {
            0x2a, 0x34, 0x0d, 0x0a,  // *, 4, \r, \n
            0x24, 0x37, 0x0d, 0x0a,  // $, 7, \r, \n
            0x52, 0x45, 0x53, 0x54,  // R, E, S, T
            0x4f, 0x52, 0x45, 0x0d,  // O, R, E, \r
            0x0a, 0x24,              // \n, $,
            0x00                     // end of string
    };

    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;

    /* expect not use RESTORE */
    r2rConf.restore.dstRdbVersion = 1;
    testRdbToRespCommon(rdbfile, &r2rConf, (char*)restorePrefix, 1, 0);

    /* expect use RESTORE */
    r2rConf.restore.dstRdbVersion = 100;
    testRdbToRespCommon(rdbfile, &r2rConf, (char*)restorePrefix, 1, 1);
}

static void test_r2r_single_string_exact_match(void **state) {
    UNUSED(state);
    unsigned char expRespData[] = "*3\r\n$3\r\nSET\r\n$3\r\nxxx\r\n$3\r\n111\r\n";
    RdbxToRespConf r2rConf;

    memset(&r2rConf, 0, sizeof(r2rConf));
    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 10;
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespData, 0, 1);

    /* Avoid RESTORE command because corresponding RDB ver. of given Redis ver. < source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 0;
    r2rConf.restore.dstRedisVersion = "7.0";   /* resolved to rdb version 10 */
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespData, 0, 1);

    /* Configure not to use RESTORE command */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespData, 0, 1);

    /* Default configuration avoid RESTORE */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon("single_key.rdb", NULL, (char *) expRespData, 0, 1);
}

static void test_r2r_single_string_exact_match_restore_exact_match(void **state) {
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
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespRestore, 0, 1);

    /* Use RESTORE command because corresponding RDB ver. of given Redis ver. == source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 0;
    r2rConf.restore.dstRedisVersion = "7.2";
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespRestore, 0, 1);
}

static void test_r2r_single_list_exact_match(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;

    char expResp[] = "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval3\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval1\r\n";

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.restore.dstRdbVersion = 6;
    testRdbToRespCommon("quicklist2_v11.rdb", &r2rConf, expResp, 0, 1);
}

static void test_r2r_plain_list(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("plain_list_v6.rdb");
}

static void test_r2r_quicklist(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("quicklist.rdb");
}

static void test_r2r_list_ziplist(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("ziplist_v3.rdb");
}

static void test_r2r_quicklist2_list(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("quicklist2_v11.rdb");
}

static void test_r2r_multiple_lists_and_strings(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("multiple_lists_strings.rdb");
}

static void test_r2r_plain_hash(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("plain_hash_v3.rdb");
}

static void test_r2r_hash_zl(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("hash_zl_v6.rdb");
}

static void test_r2r_hash_lp(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("hash_lp_v11.rdb");
}

static void test_r2r_hash_zm(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("hash_zm_v2.rdb");
}

static void test_r2r_plain_set(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("plain_set_v6.rdb");
}

static void test_r2r_set_is(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("set_is_v11.rdb");
}

static void test_r2r_set_lp(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("set_is_v11.rdb");
}

/*************************** group_rdb_to_resp *******************************/
int group_rdb_to_resp(void) {
    const struct CMUnitTest tests[] = {

            /* selected tests to verify entire payload. It is not really required,
             * since the generated RESP will be tested against live server as well */
            cmocka_unit_test(test_r2r_single_string_exact_match),
            cmocka_unit_test(test_r2r_single_string_exact_match_restore_exact_match),
            cmocka_unit_test(test_r2r_single_list_exact_match),

            /*** verify only prefix of generated RESP ***/

            /* list */
            cmocka_unit_test(test_r2r_plain_list),
            cmocka_unit_test(test_r2r_quicklist),
            cmocka_unit_test(test_r2r_quicklist2_list),
            cmocka_unit_test(test_r2r_list_ziplist),
            /* hash */
            cmocka_unit_test(test_r2r_plain_hash),
            cmocka_unit_test(test_r2r_hash_zl),
            cmocka_unit_test(test_r2r_hash_lp),
            cmocka_unit_test(test_r2r_hash_zm),
            /* set */
            cmocka_unit_test(test_r2r_plain_set),
            cmocka_unit_test(test_r2r_set_is),
            cmocka_unit_test(test_r2r_set_lp),

            /* misc */
            cmocka_unit_test(test_r2r_multiple_lists_and_strings),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
