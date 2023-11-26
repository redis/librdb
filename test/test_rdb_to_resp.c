#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_common.h"

 /* To enhance the clarity of our tests and keep expected outputs concise, a
  * filter is defined to remove the initial SELECT command that precedes all
  * RESP outputs when parsing RDB to RESP */
RdbRes dontPropHandleNewDb(RdbParser *p, void *userData,  int dbnum) {
    UNUSED(p, userData, dbnum);
    return RDB_OK_DONT_PROPAGATE;
}

RdbHandlersDataCallbacks filterSelectCmd = {.handleNewDb = dontPropHandleNewDb};

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

static void testRdbToRespCommon(const char *rdbfilename,
                                RdbxToRespConf *conf,
                                char *expResp,
                                int expRespLen,
                                MatchType matchType,
                                int expMatch)
{
    static int outputs = 0;
    static char rdbfile[1024];
    static char respfile[1024];

    /* build file path of input (rdb) file and output (resp) file */
    snprintf(rdbfile, sizeof(rdbfile), "./test/dumps/%s", rdbfilename);
    snprintf(respfile, sizeof(respfile), "./test/tmp/out%d_%s.resp", ++outputs, rdbfilename);
    RdbStatus  status;
    RdbxToResp *rdbToResp;
    RdbxRespToFileWriter *writer;
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    assert_non_null(rdbToResp = RDBX_createHandlersToResp(p, conf));
    assert_non_null(writer = RDBX_createRespToFileWriter(p, rdbToResp, respfile));
    assert_non_null(RDB_createHandlersData(p, &filterSelectCmd, NULL, NULL));

    while ((status = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    /* verify number of commands counted */
    RDB_deleteParser(p);
    assert_file_payload(respfile, expResp, expRespLen, matchType, expMatch);
}

static void runWithAndWithoutRestore(const char *rdbfile) {
    RdbxToRespConf r2rConf;

    unsigned char restorePrefix[] = {
            0x2a, 0x34, 0x0d, 0x0a,  // *, 4, \r, \n
            0x24, 0x37, 0x0d, 0x0a,  // $, 7, \r, \n
            0x52, 0x45, 0x53, 0x54,  // R, E, S, T
            0x4f, 0x52, 0x45, 0x0d,  // O, R, E, \r
            0x0a, 0x24,              // \n, $,
    };

    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.delKeyBeforeWrite = 0;

    /* expect not use RESTORE */
    r2rConf.dstRedisVersion = "0.1";
    testRdbToRespCommon(rdbfile, &r2rConf, (char*)restorePrefix, sizeof(restorePrefix), M_PREFIX, 0);

    /* expect use RESTORE */
    r2rConf.dstRedisVersion = "45.67.89";
    testRdbToRespCommon(rdbfile, &r2rConf, (char*)restorePrefix, sizeof(restorePrefix), M_PREFIX, 1);
}

static void test_r2r_string_exact_match(void **state) {
    UNUSED(state);
    unsigned char expRespData[] = "*3\r\n$3\r\nSET\r\n$3\r\nxxx\r\n$3\r\n111\r\n";
    RdbxToRespConf r2rConf;

    memset(&r2rConf, 0, sizeof(r2rConf));
    /* Avoid RESTORE command because corresponding RDB ver. of given Redis ver. < source RDB ver. */
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.0";   /* resolved to rdb version 10 */
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespData, sizeof(expRespData), M_ENTIRE, 1);

    /* Configure not to use RESTORE command */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespData, sizeof(expRespData), M_ENTIRE, 1);

    /* Default configuration avoid RESTORE */
    r2rConf.supportRestore = 0;
    testRdbToRespCommon("single_key.rdb", NULL, (char *) expRespData, sizeof(expRespData), M_ENTIRE, 1);
}

static void test_r2r_del_before_write_restore_replace(void **state) {
    UNUSED(state);
    unsigned char expRespRestore[] = {
    0x2a, 0x35, 0x0d, 0x0a, 0x24, 0x37, 0x0d, 0x0a,    0x52, 0x45, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x0d,  // *5..$7..  RESTORE.
    0x0a, 0x24, 0x33, 0x0d, 0x0a, 0x78, 0x78, 0x78,    0x0d, 0x0a, 0x24, 0x31, 0x0d, 0x0a, 0x30, 0x0d,  // .$3..xxx  ..$1..0.
    0x0a, 0x24, 0x31, 0x33, 0x0d, 0x0a, 0x00, 0xc0,    0x6f, 0x0b, 0x00, 0xa6, 0x11, 0x98, 0xb1, 0x42,  // .$13....  o......B
    0x3e, 0x16, 0x7d, 0x0d, 0x0a, 0x24, 0x37, 0x0d,    0x0a, 0x52, 0x45, 0x50, 0x4c, 0x41, 0x43, 0x45,  // >.}..$7.  .REPLACE
    0x0d, 0x0a,                                                                                         // ..
    };

    /* Expected to use RESTORE command because RDB version of file 'single_key.rdb'
     * is equal to target RDB version (inferred from dstRedisVersion) */
    RdbxToRespConf r2rConf = { 0 };
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.2";
    /* If `RESTORE` supported, the flag delKeyBeforeWrite will attach `REPLACE` to the
     * `RESTORE` command (rather than sending preceding DEL command) */
    r2rConf.delKeyBeforeWrite = 1;
    testRdbToRespCommon("single_key.rdb", &r2rConf, (char *) expRespRestore, sizeof(expRespRestore), M_ENTIRE, 1);
}

static void test_r2r_list_exact_match(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;

    char expResp[] = "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval3\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval2\r\n"
                     "*3\r\n$5\r\nRPUSH\r\n$6\r\nmylist\r\n$4\r\nval1\r\n";

    /* Won't use RESTORE command because target RDB ver. < source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.0";
    testRdbToRespCommon("quicklist2_v11.rdb", &r2rConf, expResp, sizeof(expResp), M_ENTIRE, 1);
}

static void test_r2r_policy_lfu(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;
    char expResp[] = "$4\r\nFREQ\r\n$1\r\n5\r\n";

    /* Use RESTORE command because target RDB ver. == source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.2";
    testRdbToRespCommon("mem_policy_lfu.rdb", &r2rConf, expResp, sizeof(expResp)-1, M_SUFFIX, 1);
}

static void test_r2r_policy_lru(void **state) {
    UNUSED(state);
    RdbxToRespConf r2rConf;
    char expResp[] = "$8\r\nIDLETIME\r\n$2\r\n24\r\n";

    /* Use RESTORE command because target RDB ver. == source RDB ver. */
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.2";
    testRdbToRespCommon("mem_policy_lru.rdb", &r2rConf, expResp, sizeof(expResp)-1, M_SUFFIX, 1);
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

static void test_r2r_plain_zset(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("plain_zset_v6.rdb");
}

static void test_r2r_plain_zset_2(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("plain_zset_2_v11.rdb");
}

static void test_r2r_zset_lp(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("zset_lp_v11.rdb");
}

static void test_r2r_zset_zl(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("zset_zl_v6.rdb");
}

static void test_r2r_stream(void **state) {
    UNUSED(state);
    runWithAndWithoutRestore("stream_v11.rdb");
}

static void test_r2r_module(void **state) {
    UNUSED(state);
    unsigned char expRespData[] = {
    0x2a, 0x34, 0x0d, 0x0a, 0x24, 0x37, 0x0d, 0x0a,    0x52, 0x45, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x0d,  // *4..$7..  RESTORE.
    0x0a, 0x24, 0x34, 0x0d, 0x0a, 0x6b, 0x65, 0x79,    0x31, 0x0d, 0x0a, 0x24, 0x31, 0x0d, 0x0a, 0x30,  // .$4..key  1..$1..0
    0x0d, 0x0a, 0x24, 0x32, 0x39, 0x0d, 0x0a, 0x07,    0x81, 0xb5, 0xeb, 0x2d, 0xff, 0xfa, 0xdd, 0x6c,  // ..$29...  ...-...l
    0x01, 0x05, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65,    0x31, 0x00, 0x0b, 0x00, 0x03, 0xb6, 0x8b, 0x8a,  // ...value  1.......
    0x58, 0x44, 0xb9, 0xff, 0x0d, 0x0a,                                                                 // XD....
    };

    RdbxToRespConf r2rConf;

    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.2";   /* resolved to rdb version 11 */
    testRdbToRespCommon("module.rdb", &r2rConf, (char *) expRespData, sizeof(expRespData), M_ENTIRE, 1);
}

static void test_r2r_module_aux(void **state) {
    UNUSED(state);
    unsigned char expRespData[] = {
            0x2a, 0x34, 0x0d, 0x0a, 0x24, 0x37, 0x0d, 0x0a,    0x52, 0x45, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x0d,  //  *4..$7..  RESTORE.
            0x0a, 0x24, 0x31, 0x0d, 0x0a, 0x78, 0x0d, 0x0a,    0x24, 0x31, 0x0d, 0x0a, 0x30, 0x0d, 0x0a, 0x24,  //  .$1..x..  $1..0..$
            0x31, 0x33, 0x0d, 0x0a, 0x00, 0xc0, 0x01, 0x0b,    0x00, 0x4f, 0xa7, 0x5a, 0xc5, 0x2c, 0x9e, 0xf8,  //  13......  .O.Z.,..
            0x75, 0x0d, 0x0a, 0x00, 0x0b, 0x00, 0xa6, 0xe6,    0xfb, 0x24, 0xce, 0x1a, 0x8c, 0x25, 0x0d, 0x0a,  //  u.......  .$...%..
    };

    RdbxToRespConf r2rConf;
    memset(&r2rConf, 0, sizeof(r2rConf));
    r2rConf.supportRestore = 1;
    r2rConf.dstRedisVersion = "7.2";   /* resolved to rdb version 11 */
    testRdbToRespCommon("module_aux.rdb", &r2rConf, (char *) expRespData, sizeof(expRespData), M_ENTIRE, 1);
}

static void test_r2r_stream_with_target_62_and_72(void **state) {
    size_t fileLen;
    UNUSED(state);
    RdbxToRespConf r2rConf1 = { .dstRedisVersion="6.2"};
    char *f1 = readFile(DUMP_FOLDER("stream_v11_target_ver_6.2.resp"), &fileLen, NULL);
    testRdbToRespCommon("stream_v11.rdb", &r2rConf1, f1, fileLen, M_ENTIRE, 1);
    free(f1);

    RdbxToRespConf r2rConf = { .dstRedisVersion="7.2" };
    f1 = readFile(DUMP_FOLDER("stream_v11_target_ver_7.2.resp"), &fileLen, NULL);
    testRdbToRespCommon("stream_v11.rdb", &r2rConf, f1, fileLen, M_ENTIRE, 1);
    free(f1);
}

/*************************** group_rdb_to_resp *******************************/
int group_rdb_to_resp(void) {
    const struct CMUnitTest tests[] = {

            /* selected tests to verify entire payload. It is not really required,
             * since the generated RESP will be tested against live server as well */
            cmocka_unit_test(test_r2r_string_exact_match),
            cmocka_unit_test(test_r2r_list_exact_match),

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
            /* zset */
            cmocka_unit_test(test_r2r_plain_zset),
            cmocka_unit_test(test_r2r_plain_zset_2),
            cmocka_unit_test(test_r2r_zset_lp),
            cmocka_unit_test(test_r2r_zset_zl),
            /* mem policy */
            cmocka_unit_test(test_r2r_policy_lfu),
            cmocka_unit_test(test_r2r_policy_lru),
            /* module*/
            cmocka_unit_test(test_r2r_module),
            cmocka_unit_test(test_r2r_module_aux),
            /* stream */
            cmocka_unit_test(test_r2r_stream),
            cmocka_unit_test(test_r2r_stream_with_target_62_and_72),
            /* misc */
            cmocka_unit_test(test_r2r_multiple_lists_and_strings),
            cmocka_unit_test(test_r2r_del_before_write_restore_replace),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
