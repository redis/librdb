#include <string.h>
#include "test_common.h"

static void test_r2j_single_list_data(void **state) {
    UNUSED(state);

    char expJson[] = QUOTE(
        "redis-ver":"255.255.255",
        "redis-bits":"64",
        "ctime":"1677071222",
        "used-mem":"982208",
        "repl-stream-db":"0",
        "repl-id":"f42ea6b158e5926941d08bde6b9ecb6ae88dcd45",
        "repl-offset":"162395634",
        "aof-base":"0",
        [
            {"mylist":["val3", "val2", "val1"]}
        ]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_list.rdb"),
                  PATH_TMP_FOLDER("single_list.json"),
                  expJson,
                  RDB_LEVEL_DATA);
}

static void test_r2j_single_list_struct(void **state) {
    UNUSED(state);

    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677071222",
            "used-mem":"982208",
            "repl-stream-db":"0",
            "repl-id":"f42ea6b158e5926941d08bde6b9ecb6ae88dcd45",
            "repl-offset":"162395634",
            "aof-base":"0",
            [
                {"mylist":["\x19\x00\x00\x00\x03\x00\x84val3\x05\x84val2\x05\x84val1\x05\xff"]}
            ]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_list.rdb"),
                  PATH_TMP_FOLDER("single_list.json"),
                  expJson,
                  RDB_LEVEL_STRUCT);
}

static void test_r2j_single_list_raw (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677071222",
            "used-mem":"982208",
            "repl-stream-db":"0",
            "repl-id":"f42ea6b158e5926941d08bde6b9ecb6ae88dcd45",
            "repl-offset":"162395634",
            "aof-base":"0",
            [
                {"mylist":"\x12\x01\x02\x19\x19\x00\x00\x00\x03\x00\x84val3\x05\x84val2\x05\x84val1\x05\xff"}
            ]
    );
    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_list.rdb"),
                  PATH_TMP_FOLDER("single_list.json"),
                  expJson,
                  RDB_LEVEL_RAW);
}

static void test_r2j_multiple_lists_and_strings_data (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
        "redis-ver":"255.255.255",
        "redis-bits":"64",
        "ctime":"1677580558",
        "used-mem":"937464",
        "aof-base":"0",
        [{
            "string2":"Hithere!",
            "mylist1":["v1"],
            "mylist3":["v3","v2","v1"],
            "lzf_compressed":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "string1":"blaa",
            "mylist2":["v2","v1"]
        }]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("multiple_lists_strings.rdb"),
                  PATH_TMP_FOLDER("multiple_lists_strings.json"),
                  expJson,
                  RDB_LEVEL_DATA);
}

static void test_r2j_multiple_lists_and_strings_struct (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
         "redis-ver":"255.255.255",
         "redis-bits":"64",
         "ctime":"1677580558",
         "used-mem":"937464",
         "aof-base":"0",
         [{
            "string2":"Hithere!",
            "mylist1":["\x0b\x00\x00\x00\x01\x00\x82v1\x03\xff"],
            "mylist3":["\x13\x00\x00\x00\x03\x00\x82v3\x03\x82v2\x03\x82v1\x03\xff"],
            "lzf_compressed":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "string1":"blaa",
            "mylist2":["\x0f\x00\x00\x00\x02\x00\x82v2\x03\x82v1\x03\xff"]
        }]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("multiple_lists_strings.rdb"),
                     PATH_TMP_FOLDER("multiple_lists_strings.json"),
                     expJson,
                     RDB_LEVEL_STRUCT);
}

static void test_r2j_multiple_lists_and_strings_raw (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1677580558",
            "used-mem":"937464",
            "aof-base":"0",
            [{
                "string2":"\x00\tHithere!",
                "mylist1":"\x12\x01\x02\x0b\x0b\x00\x00\x00\x01\x00\x82v1\x03\xff",
                "mylist3":"\x12\x01\x02\x13\x13\x00\x00\x00\x03\x00\x82v3\x03\x82v2\x03\x82v1\x03\xff",
                "lzf_compressed":"\x00\xc3\t@v\x01cc\xe0i\x00\x01cc",
                "string1":"\x00\x04blaa",
                "mylist2":"\x12\x01\x02\x0f\x0f\x00\x00\x00\x02\x00\x82v2\x03\x82v1\x03\xff"
            }]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("multiple_lists_strings.rdb"),
                  PATH_TMP_FOLDER("multiple_lists_strings.json"),
                  expJson,
                  RDB_LEVEL_RAW);
}

static void test_r2j_single_string_data(void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1672087814",
            "used-mem":"972952",
            "repl-stream-db":"0",
            "repl-id":"67ebe8f627f436e2630eef8661a697fa33563a8f",
            "repl-offset":"162341903",
            "aof-base":"0",
            [
                {"xxx":"111"}
            ]
    );
    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_key.rdb"),
                  PATH_TMP_FOLDER("single_key.json"),
                  expJson,
                  RDB_LEVEL_DATA);
}

static void test_r2j_single_string_struct (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1672087814",
            "used-mem":"972952",
            "repl-stream-db":"0",
            "repl-id":"67ebe8f627f436e2630eef8661a697fa33563a8f",
            "repl-offset":"162341903",
            "aof-base":"0",
            [
            {"xxx":"111"}
            ]
    );
    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_key.rdb"),
                     PATH_TMP_FOLDER("single_key.json"),
                     expJson,
                     RDB_LEVEL_STRUCT);
}

static void test_r2j_single_string_raw (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1672087814",
            "used-mem":"972952",
            "repl-stream-db":"0",
            "repl-id":"67ebe8f627f436e2630eef8661a697fa33563a8f",
            "repl-offset":"162341903",
            "aof-base":"0",
            [
                {"xxx":"\x00\xc0o"}
            ]
    );
    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("single_key.rdb"),
                  PATH_TMP_FOLDER("single_key.json"),
                  expJson,
                  RDB_LEVEL_RAW);
}

static void test_r2j_multiple_dbs (void **state) {
    UNUSED(state);
    char expJson[] = QUOTE(
            "redis-ver":"255.255.255",
            "redis-bits":"64",
            "ctime":"1683103535",
            "used-mem":"967040",
            "aof-base":"0",
            [
                {"x":"0"},
                {"y":"1"},
                {"z":"2"}
            ]
    );

    testRdbToJsonVariousCases(PATH_DUMP_FOLDER("multiple_dbs.rdb"),
                     PATH_TMP_FOLDER("multiple_dbs.json"),
                     expJson,
                     RDB_LEVEL_DATA);
}

/*************************** group_rdb_to_json *******************************/
int group_rdb_to_json(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_r2j_single_list_data),
        cmocka_unit_test(test_r2j_single_list_struct),
        cmocka_unit_test(test_r2j_single_list_raw),

        cmocka_unit_test(test_r2j_single_string_data),
        cmocka_unit_test(test_r2j_single_string_struct),
        cmocka_unit_test(test_r2j_single_string_raw),

        cmocka_unit_test(test_r2j_multiple_lists_and_strings_data),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_struct),
        cmocka_unit_test(test_r2j_multiple_lists_and_strings_raw),

        cmocka_unit_test(test_r2j_multiple_dbs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
