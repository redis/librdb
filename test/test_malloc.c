#include <string.h>
#include <stdlib.h>
#include "test_common.h"

enum {
    CNT_CLONE_BULK,
    CNT_MALLOC_BULK,
    CNT_FREE_BULK,
    CNT_MALLOC_WRAPPER,
    CNT_REALLOC_WRAPPER,
    CNT_FREE_WRAPPER,
    CNT_MAX
};

int counters[CNT_MAX];

void *myCloneBulk(void *str, size_t len) {++counters[CNT_CLONE_BULK]; return xclone(str, len); }
void *myMallocBulk(size_t size) { ++counters[CNT_MALLOC_BULK]; return xmalloc(size); }
void myFreeBulk(void *ptr) { ++counters[CNT_FREE_BULK]; xfree(ptr); }

void *myMalloc (size_t size) { ++counters[CNT_MALLOC_WRAPPER]; return xmalloc(size); }
void *myRealloc (void *ptr, size_t size) { ++counters[CNT_REALLOC_WRAPPER]; return xrealloc(ptr, size); }
void myFree (void *ptr) { ++counters[CNT_FREE_WRAPPER]; xfree(ptr); }

static void test_extern_alloc(void **state) {
    UNUSED(state);
    RdbStatus  status;

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

    for (int bulkAllocType = 0 ; bulkAllocType < RDB_BULK_ALLOC_MAX ; ++bulkAllocType) {
        memset(counters, 0, sizeof(counters));

        RdbMemAlloc mem = {myMalloc, myRealloc, myFree,
                           bulkAllocType,   /* << change each iteration */
                           { myMallocBulk, myCloneBulk, myFreeBulk }
        };

        RdbParser *parser = RDB_createParserRdb(&mem);
        RDB_setLogLevel(parser, RDB_LOG_ERROR);

        assert_non_null(RDBX_createReaderFile(parser, PATH_DUMP_FOLDER("single_key.rdb")));
        assert_non_null(RDBX_createHandlersToJson(parser,
                                                  RDBX_CONV_JSON_ENC_PLAIN,
                                                  PATH_TMP_FOLDER("single_key.json"),
                                                  RDB_LEVEL_DATA));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
        assert_json_file(PATH_TMP_FOLDER("single_key.json"), expJson);

        switch (bulkAllocType) {
            case RDB_BULK_ALLOC_STACK:
                assert_int_equal(0, counters[CNT_MALLOC_BULK]);
                assert_int_equal(0, counters[CNT_CLONE_BULK]);
                break;
            case RDB_BULK_ALLOC_HEAP:
                assert_int_equal(0, counters[CNT_MALLOC_BULK]);
                assert_int_equal(0, counters[CNT_CLONE_BULK]);
                break;
            case RDB_BULK_ALLOC_EXTERN:
            case RDB_BULK_ALLOC_EXTERN_OPT:
                /* Exactly 8 pairs of auxiliary fields and 1 pair of key-value should be created
                 * by provided "external" Bulk allocator. 18 calls in total */
                assert_int_equal(18, counters[CNT_MALLOC_BULK]);
                /* Exactly 1 key need to be cloned externally by rdb2json */
                assert_int_equal(1, counters[CNT_CLONE_BULK]);
                break;
        }

        assert_int_not_equal(0, counters[CNT_MALLOC_WRAPPER]);
        assert_int_not_equal(0, counters[CNT_FREE_WRAPPER]);
    }
}

/*************************** group_rdb_to_json *******************************/
int group_mem_management(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_extern_alloc),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
