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

    for (int bulkAllocType = 0 ; bulkAllocType < RDB_BULK_ALLOC_MAX ; ++bulkAllocType) {
        memset(counters, 0, sizeof(counters));

        RdbMemAlloc mem = {myMalloc, myRealloc, myFree,
                           bulkAllocType,   /* << change each iteration */
                           { myMallocBulk, myCloneBulk, myFreeBulk }
        };

        RdbParser *parser = RDB_createParserRdb(&mem);
        RDB_setLogLevel(parser, RDB_LOG_ERR);

        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("single_key.rdb")));
        RdbxToJsonConf r2jConf = {RDB_LEVEL_DATA, RDBX_CONV_JSON_ENC_PLAIN, 0, 1};
        assert_non_null(RDBX_createHandlersToJson(parser,
                                                  TMP_FOLDER("single_key.json"),
                                                  &r2jConf));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal(status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
        assert_json_equal(TMP_FOLDER("single_key.json"), DUMP_FOLDER("single_key_data.json"), 0);

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
