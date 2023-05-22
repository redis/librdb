#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "test_common.h"

static void test_createReader_missingFile(void **state) {
    UNUSED(state);

    RdbParser *parser = RDB_createParserRdb(NULL);
    RdbxReaderFile *reader = RDBX_createReaderFile(parser, "./test/dumps/non_exist_file.rdb");

    /* verify didn't get back reader instance */
    assert_null(reader);

    /* verify returned error code */
    RdbRes err = RDB_getErrorCode(parser);
    assert_int_equal(err, RDB_ERR_FAILED_OPEN_RDB_FILE);

    /* verify returned error string */
    assert_string_equal(RDB_getErrorMessage(parser), "Failed to open RDB file: ./test/dumps/non_exist_file.rdb");

    RDB_deleteParser(parser);
}

static void test_createHandlersRdbToJson_and_2_FilterKey(void **state) {
    UNUSED(state);

    const char *rdbfile = PATH_DUMP_FOLDER("multiple_lists_strings.rdb");
    const char *jsonfile = PATH_TMP_FOLDER("multiple_lists_strings.json");

    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677580558",
            "used-mem":"937464",
            "aof-base":"0",
            [{
            "mylist1":["v1"],
            "mylist3":["v3","v2","v1"],
            "mylist2":["v2","v1"]
            }]

    );
    RdbStatus  status;
    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(RDBX_createHandlersToJson(parser,
                                              RDBX_CONV_JSON_ENC_PLAIN,
                                              jsonfile,
                                              RDB_LEVEL_DATA));

    assert_non_null(RDBX_createHandlersFilterKey(parser, ".*i.*", 0));
    assert_non_null(RDBX_createHandlersFilterKey(parser, "mylist.*", 0));


    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    RDB_deleteParser(parser);
    assert_payload_file(jsonfile, expJson, 1);
}

static void test_mixed_levels_registration(void **state) {
    UNUSED(state);

    char expJsonRaw[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677580558",
            "used-mem":"937464",
            "aof-base":"0",
            [{
                "string2":"\x00\tHithere!",
                "lzf_compressed":"\x00\xc3\t@v\x01cc\xe0i\x00\x01cc",
                "string1":"\x00\x04blaa"
            }]
    );

    char expJsonData[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677580558",
            "used-mem":"937464",
            "aof-base":"0",
            [{
                "mylist1":["v1"],
                "mylist3":["v3","v2","v1"],
                "mylist2":["v2","v1"]
            }]
    );

    const char *rdbfile = PATH_DUMP_FOLDER("multiple_lists_strings.rdb");
    const char *jsonfileRaw = PATH_TMP_FOLDER("multiple_lists_strings_raw.json");
    const char *jsonfileData = PATH_TMP_FOLDER("multiple_lists_strings_data.json");

    RdbStatus  status;
    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERROR);
    assert_non_null(RDBX_createReaderFile(parser, rdbfile));
    assert_non_null(RDBX_createHandlersToJson(parser,
                                                RDBX_CONV_JSON_ENC_PLAIN,
                                                jsonfileData,
                                                RDB_LEVEL_DATA));

    assert_non_null(RDBX_createHandlersToJson(parser,
                                                RDBX_CONV_JSON_ENC_PLAIN,
                                                jsonfileRaw,
                                                RDB_LEVEL_RAW));

    /* at what level of the parser each obj type should be handled and callback */
    RDB_handleByLevel(parser, RDB_DATA_TYPE_STRING, RDB_LEVEL_RAW, 0);
    RDB_handleByLevel(parser, RDB_DATA_TYPE_LIST, RDB_LEVEL_DATA, 0);

    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal( status, RDB_STATUS_OK);

    RDB_deleteParser(parser);
    assert_payload_file(jsonfileRaw, expJsonRaw, 1);
    assert_payload_file(jsonfileData, expJsonData, 1);
}

static void printResPicture(int result) {
    if (result)
        printf("    x_x\n"
               "    /|\\\n"
               "    / \\\n"
               "Tests got failed!\n\n");
    else
        printf("    \\o/\n"
               "     |\n"
               "    / \\\n"
               "All tests passed!!!\n\n");

}

#define RUN_TEST_GROUP(grp) \
    if ((runGroupPrefix == NULL) || (strncmp(runGroupPrefix, #grp, strlen(runGroupPrefix)) == 0)) { \
        printf ("\n--- Test Group: %s ---\n", #grp); \
        result |= grp(); \
    }

/*************************** group_main *******************************/
int group_main(void) {
    /* Insert here your test functions */
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_createReader_missingFile),
        cmocka_unit_test(test_createHandlersRdbToJson_and_2_FilterKey),
        cmocka_unit_test(test_mixed_levels_registration),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/*************************** MAIN *******************************/
int main(int argc, char *argv[]) {
    struct timeval st, et;
    char *runGroupPrefix = NULL;
    const char *hostname = NULL;
    int port = 0;
    int result = 0;

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i+1 < argc) {
            port =  atoi(argv[++i]);
        } else if ((strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hostname") == 0) && i+1 < argc) {
            hostname = argv[++i];
        } else if ((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--run-group") == 0) && i+1 < argc) {
            runGroupPrefix = argv[++i];
        } else {
            printf("Invalid argument: %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }

    gettimeofday(&st,NULL);

    if ((port != 0) && (hostname != NULL)) {
        printf("Using External server for the test.");

    } else {

        //setenv("LIBRDB_DEBUG_DATA", "1", 1); /*<< to see parser states printouts*/

        printf("\n*************** START TESTING *******************\n");
        setenv("LIBRDB_SIM_WAIT_MORE_DATA", "0", 1);
        RUN_TEST_GROUP(group_rdb_to_resp);
        RUN_TEST_GROUP(group_main);
        RUN_TEST_GROUP(group_rdb_to_json);
        RUN_TEST_GROUP(group_mem_management);
        RUN_TEST_GROUP(group_bulk_ops);

        RUN_TEST_GROUP(group_pause);

        printf("\n*************** SIMULATING WAIT_MORE_DATA *******************\n");
        setenv("LIBRDB_SIM_WAIT_MORE_DATA", "1", 1);
        RUN_TEST_GROUP(group_main);
        RUN_TEST_GROUP(group_rdb_to_resp);
        RUN_TEST_GROUP(group_rdb_to_json);
        RUN_TEST_GROUP(group_mem_management);
        RUN_TEST_GROUP(group_bulk_ops);
        printf("\n*************** END TESTING *******************\n");

        gettimeofday(&et, NULL);

        int elapsed = (et.tv_sec - st.tv_sec) * 1000 + (et.tv_usec - st.tv_usec) / 1000;
        printf("Total time: %d milliseconds\n", elapsed);
    }

    printResPicture(result);
    return result;
}
