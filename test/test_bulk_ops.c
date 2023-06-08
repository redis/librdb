#include <string.h>
#include "test_common.h"

RdbMemAlloc mem = {xmalloc, xrealloc, xfree,
                   RDB_BULK_ALLOC_MAX,   /* << change each iteration */
                   { xmalloc, xclone, xfree }
};

void loggerCb(RdbLogLevel l, const char *msg) {
    UNUSED(l, msg);
    /* mask simulated errors */
}

void reportErrorCb(RdbRes errorID, const char *errorMsg) {
    UNUSED(errorID, errorMsg);
}

void testBulkOps(RdbParser *p, RdbBulk b, int strlenCheck) {

    /*** test clone, and free ***/

    RdbBulkCopy bcopy = RDB_bulkClone(p, b);

    if (RDB_isRefBulk(p, b)) {
        assert_ptr_not_equal(b, bcopy);
        assert_int_not_equal(mem.bulkAllocType, RDB_BULK_ALLOC_EXTERN);
    } else if (mem.bulkAllocType == RDB_BULK_ALLOC_HEAP)
        assert_ptr_equal(b, bcopy); /* heap clone uses refcount */
    else if (mem.bulkAllocType == RDB_BULK_ALLOC_EXTERN)
        assert_ptr_not_equal(b, bcopy); /* xclone imp creates a new copy */

    assert_string_equal(b, bcopy);
    RDB_bulkCopyFree(p, bcopy);

    /* Try clone non exist bulk */
    RdbBulk nonExistBulk = "NON EXIST BULK";
    assert_null(RDB_bulkClone(p, nonExistBulk));
    RdbRes err = RDB_getErrorCode(p);
    assert_int_equal(err, RDB_ERR_INVALID_BULK_CLONE_REQUEST);

    /*** test bulk len ***/

    /* enabled this check only if for sure bulk cannot have the char `\0' */
    if (strlenCheck)
        assert_int_equal(strlen(b), RDB_bulkLen(p, b));
    assert_true(0 != RDB_bulkLen(p, b));
}

RdbRes handle_aux_field(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    UNUSED(userData);
    testBulkOps(p, auxkey, 1);
    testBulkOps(p, auxval, 1);
    return RDB_OK;
}

RdbRes handle_new_key(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    UNUSED(userData, info);
    testBulkOps(p, key, 1);
    return RDB_OK;
}

RdbRes handle_raw_begin(RdbParser *p, void *userData, size_t size) {
    UNUSED(p);
    /* init rawObjSizeLeft with declared size. Verified by handle_raw_end */
    size_t *rawObjSizeLeft = (size_t *)userData;
    *rawObjSizeLeft = size;
    return RDB_OK;
}

RdbRes handle_raw_frag(RdbParser *p, void *userData, RdbBulk frag) {
    size_t *rawObjSizeLeft = (size_t *)userData;

    *rawObjSizeLeft -= RDB_bulkLen(p, frag);
    testBulkOps(p, frag, 0);
    return RDB_OK;
}

RdbRes handle_raw_end(RdbParser *p, void *userData) {
    UNUSED(p);
    size_t *rawObjSizeLeft = (size_t *)userData;

    /* Verify reported size by handle_raw_begin == total received bulks */
    assert_int_equal(*rawObjSizeLeft, 0);
    return RDB_OK;
}

RdbRes handle_string_value(RdbParser *p, void *userData, RdbBulk str) {
    UNUSED(userData);
    testBulkOps(p, str, 0);
    return RDB_OK;
}

RdbRes handle_list_element(RdbParser *p, void *userData, RdbBulk b) {
    UNUSED(userData);
    testBulkOps(p, b, 0);
    return RDB_OK;
}

static void test_raw_handlers_callbacks_bulk_ops (void **state) {
    UNUSED(state);
    RdbStatus  status;
    size_t rawObjSizeLeft;
    void *user_data =&rawObjSizeLeft;

    for (mem.bulkAllocType = 0 ; mem.bulkAllocType < RDB_BULK_ALLOC_MAX ; ++mem.bulkAllocType) {

        RdbHandlersRawCallbacks callbacks = {
                .handleAuxField = handle_aux_field,
                .handleNewKey = handle_new_key,
                .handleBegin = handle_raw_begin,
                .handleFrag = handle_raw_frag,
                .handleEnd = handle_raw_end,
        };

        RdbParser *parser = RDB_createParserRdb(&mem);
        RDB_setLogger(parser, loggerCb);
        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("multiple_lists_strings.rdb")));
        assert_non_null(RDB_createHandlersRaw(parser, &callbacks, user_data, NULL));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal( status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
    }
}

static void test_struct_handlers_callbacks_bulk_ops (void **state) {
    UNUSED(state);
    RdbStatus  status;
    size_t rawObjSizeLeft;
    void *user_data =&rawObjSizeLeft;

    for (mem.bulkAllocType = 0 ; mem.bulkAllocType < RDB_BULK_ALLOC_MAX ; ++mem.bulkAllocType) {

        RdbHandlersStructCallbacks callbacks = {
                .handleAuxField = handle_aux_field,
                .handleNewKey = handle_new_key,
                .handleStringValue = handle_string_value,
                .handlerPlainNode = handle_list_element,
                .handlerQListNode = handle_list_element,

        };

        RdbParser *parser = RDB_createParserRdb(&mem);
        RDB_setLogger(parser, loggerCb);
        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("multiple_lists_strings.rdb")));
        assert_non_null(RDB_createHandlersStruct(parser, &callbacks, user_data, NULL));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal( status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
    }
}

static void test_data_handlers_callbacks_bulk_ops (void **state) {
    UNUSED(state);
    RdbStatus  status;
    size_t rawObjSizeLeft;
    void *user_data =&rawObjSizeLeft;

    for (mem.bulkAllocType = 0 ; mem.bulkAllocType < RDB_BULK_ALLOC_MAX ; ++mem.bulkAllocType) {

        RdbHandlersDataCallbacks callbacks = {
                .handleAuxField = handle_aux_field,
                .handleNewKey = handle_new_key,
                .handleStringValue = handle_string_value,
                .handleListElement = handle_list_element,
        };

        RdbParser *parser = RDB_createParserRdb(&mem);
        RDB_setLogger(parser, loggerCb);
        assert_non_null(RDBX_createReaderFile(parser, DUMP_FOLDER("multiple_lists_strings.rdb")));
        assert_non_null(RDB_createHandlersData(parser, &callbacks, user_data, NULL));
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
        assert_int_equal( status, RDB_STATUS_OK);
        RDB_deleteParser(parser);
    }
}

/*************************** group_rdb_to_json *******************************/
int group_bulk_ops(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_raw_handlers_callbacks_bulk_ops),
            cmocka_unit_test(test_struct_handlers_callbacks_bulk_ops),
            cmocka_unit_test(test_data_handlers_callbacks_bulk_ops),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
