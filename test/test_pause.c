#include <string.h>
#include "test_common.h"

int aux_fields_counter;
RdbRes handle_pause_aux_field_pause(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    UNUSED(userData, auxkey, auxval);
    ++aux_fields_counter;
    RDB_pauseParser(p);
    return RDB_OK;
}

static void test_pause_by_handlers_callback(void **state) {
    UNUSED(state);
    RdbStatus  status;
    int pause_counter = 0;
    void *user_data = NULL;
    aux_fields_counter = 0;

    RdbHandlersRawCallbacks cb = { .handleAuxField = handle_pause_aux_field_pause };
    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_ERR);
    assert_non_null(RDBX_createReaderFile(parser, "./test/dumps/quicklist2_v11.rdb"));
    assert_non_null(RDB_createHandlersRaw(parser, &cb, user_data, NULL));

    while ((status = RDB_parse(parser)) != RDB_STATUS_OK) {
        if (status == RDB_STATUS_PAUSED) ++pause_counter;
    }
    assert_int_equal( status, RDB_STATUS_OK);
    assert_int_equal( pause_counter, aux_fields_counter);

    RDB_deleteParser(parser);
}

/*************************** group_rdb_to_json *******************************/
int group_pause(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_pause_by_handlers_callback),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
