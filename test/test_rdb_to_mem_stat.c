#include <string.h>
#include <stdlib.h>
#include "test_common.h"

/* The memory estimate lives in handlersCommon and is surfaced two ways: the print
 * format specifiers (%z bytes, %g largest, %n encoding) via RDBX_createHandlersToPrint,
 * and the built-in statistics report via RDBX_createHandlersToStat. These tests drive
 * each handler to a temp file and assert on its output. */

#define DRIFT_TOLERANCE_PCT 25
/* Drift is asserted only at/above this MEMORY USAGE. Below it, footprint is
 * dominated by allocator/build specifics not recoverable from an RDB and varies
 * ~2x across Redis builds; the feature targets large keys. */
#define DRIFT_MIN_BYTES 128

#define OUT TMP_FOLDER("memstat.out")

/* Run print over rdbfile into OUT, rendering each key with keyFmt. */
static char *runPrint(const char *rdbfile, const char *keyFmt) {
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERR);
    RdbxToPrint *toPrint = RDBX_createHandlersToPrint(p, NULL, keyFmt ? keyFmt : "", OUT);
    assert_non_null(toPrint);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    RdbStatus s;
    while ((s = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(s, RDB_STATUS_OK);
    RDB_deleteParser(p);

    size_t len;
    char *buf = readFile(OUT, &len, NULL);
    assert_non_null(buf);
    return buf;
}

/* Copy the line that starts with "<key>," into `out` (without newline). 1 if found. */
static int lineForKey(const char *buf, const char *key, char *out, size_t outsz) {
    size_t klen = strlen(key);
    const char *p = buf;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
        if (strncmp(p, key, klen) == 0 && p[klen] == ',') {
            size_t n = (linelen < outsz - 1) ? linelen : outsz - 1;
            memcpy(out, p, n); out[n] = '\0';
            return 1;
        }
        p = nl ? nl + 1 : NULL;
    }
    return 0;
}

/*** Static fixture tests: exact encoding / items / largest ***/

static void assertKey(const char *buf, const char *key, const char *expLine) {
    char line[512];
    assert_true(lineForKey(buf, key, line, sizeof(line)));
    assert_string_equal(line, expLine);
}

static void test_memStat_fields_hash_listpack(void **state) {
    UNUSED(state);
    char *buf = runPrint(DUMP_FOLDER("hash_lp_v11.rdb"), "%k,%n,%i,%g");
    assertKey(buf, "hash1", "hash1,listpack,5,8");
    assertKey(buf, "hash2", "hash2,listpack,6,7");
    free(buf);
}

static void test_memStat_fields_set_intset(void **state) {
    UNUSED(state);
    char *buf = runPrint(DUMP_FOLDER("set_is_v11.rdb"), "%k,%n,%i,%g");
    assertKey(buf, "myintest", "myintest,intset,6,10");
    free(buf);
}

static void test_memStat_fields_zset_skiplist(void **state) {
    UNUSED(state);
    char *buf = runPrint(DUMP_FOLDER("plain_zset_2_v11.rdb"), "%k,%n,%i,%g");
    assertKey(buf, "myzset", "myzset,skiplist,24,3");
    free(buf);
}

static void test_memStat_fields_lists(void **state) {
    UNUSED(state);
    char *buf = runPrint(DUMP_FOLDER("multiple_lists_strings.rdb"), "%k,%n,%i,%g");
    assertKey(buf, "mylist1", "mylist1,quicklist,1,2");
    assertKey(buf, "mylist2", "mylist2,quicklist,2,2");
    assertKey(buf, "mylist3", "mylist3,quicklist,3,2");
    free(buf);
}

/*** Statistics report (deterministic, on a fixture) ***/

static char *runStat(const char *rdbfile, long long nowSecs) {
    RdbParser *p = RDB_createParserRdb(NULL);
    RDB_setLogLevel(p, RDB_LOG_ERR);
    RdbxToStat *ts = RDBX_createHandlersToStat(p, 0, nowSecs, OUT);
    assert_non_null(ts);
    assert_non_null(RDBX_createReaderFile(p, rdbfile));
    RdbStatus s;
    while ((s = RDB_parse(p)) == RDB_STATUS_WAIT_MORE_DATA);
    assert_int_equal(s, RDB_STATUS_OK);
    RDB_deleteParser(p);
    size_t len; char *buf = readFile(OUT, &len, NULL);
    assert_non_null(buf);
    return buf;
}

static void test_memStat_stat_default(void **state) {
    UNUSED(state);
    /* multiple_lists_strings: 3 strings (string1, string2, lzf_compressed) + 3 lists */
    char *buf = runStat(DUMP_FOLDER("multiple_lists_strings.rdb"), 0);
    assert_non_null(strstr(buf, "Statistics (Memory is estimated)"));
    assert_non_null(strstr(buf, "string"));          /* by-type rows present */
    assert_non_null(strstr(buf, "list"));
    assert_non_null(strstr(buf, "TOTAL"));
    assert_non_null(strstr(buf, "Top "));
    assert_non_null(strstr(buf, "lzf_compressed"));  /* largest key */
    /* new columns */
    assert_non_null(strstr(buf, "items/key"));
    assert_non_null(strstr(buf, "volatile"));
    assert_non_null(strstr(buf, "expired"));
    assert_non_null(strstr(buf, "avg item"));
    assert_non_null(strstr(buf, "ttl"));
    free(buf);
}

/* set_not_expired_v11.rdb holds one key ("mykey") with a far-future expiry. Pinning
 * the reference time on either side of it exercises the volatile/expired accounting.
 * The Top-N row ends with "<ttl>  <key>", so "expired  mykey" discriminates the two
 * runs (the bare word "expired" also appears as a column header in both). */
static void test_memStat_stat_expiry(void **state) {
    UNUSED(state);
    /* now ~= epoch: the key is volatile but not yet expired */
    char *buf = runStat(DUMP_FOLDER("set_not_expired_v11.rdb"), 1);
    assert_non_null(strstr(buf, "volatile keys hold"));
    assert_non_null(strstr(buf, "mykey"));
    assert_null(strstr(buf, "expired  mykey"));
    free(buf);

    /* now far in the future: the same key is now expired */
    buf = runStat(DUMP_FOLDER("set_not_expired_v11.rdb"), 99999999999LL);
    assert_non_null(strstr(buf, "volatile keys hold"));
    assert_non_null(strstr(buf, "expired  mykey"));
    free(buf);
}

/*** Live-Redis drift test (memBytes vs MEMORY USAGE) ***/

static long long memUsage(const char *key) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "MEMORY USAGE %s", key);
    return atoll(sendRedisCmd(cmd, REDIS_REPLY_INTEGER, NULL));
}

static void fillN(const char *cmd, const char *key, int n) {
    char buf[16384];
    int off = snprintf(buf, sizeof(buf), "%s %s", cmd, key);
    for (int i = 0; i < n; i++) off += snprintf(buf + off, sizeof(buf) - off, " e%d", i);
    sendRedisCmd(buf, -1, NULL);
}
static void fillHash(const char *key, int n) {
    char buf[16384];
    int off = snprintf(buf, sizeof(buf), "HSET %s", key);
    for (int i = 0; i < n; i++) off += snprintf(buf + off, sizeof(buf) - off, " f%d v%d", i, i);
    sendRedisCmd(buf, -1, NULL);
}
static void fillZset(const char *key, int n) {
    char buf[16384];
    int off = snprintf(buf, sizeof(buf), "ZADD %s", key);
    for (int i = 0; i < n; i++) off += snprintf(buf + off, sizeof(buf) - off, " %d m%d", i, i);
    sendRedisCmd(buf, -1, NULL);
}

static void test_memStat_live_drift(void **state) {
    UNUSED(state);
    if (!isSetRedisServer()) { printf("    (skipped: no live Redis server)\n"); return; }

    static const char *keys[16];
    long long expected[16];
    int n = 0;

    sendRedisCmd("FLUSHALL", -1, NULL);
    sendRedisCmd("SET str_raw aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", -1, NULL); keys[n++] = "str_raw";
    fillN("RPUSH", "list_ql", 300);   keys[n++] = "list_ql";
    fillN("SADD", "set_ht", 300);     keys[n++] = "set_ht";
    fillHash("hash_ht", 300);         keys[n++] = "hash_ht";
    fillZset("zset_sl", 300);         keys[n++] = "zset_sl";

    for (int i = 0; i < n; i++) expected[i] = memUsage(keys[i]);
    sendRedisCmd("SAVE", -1, "OK");

    char *buf = runPrint(TMP_FOLDER("dump.rdb"), "%k,%z");
    int failures = 0;
    for (int i = 0; i < n; i++) {
        char line[256], *comma;
        assert_true(lineForKey(buf, keys[i], line, sizeof(line)));
        comma = strchr(line, ',');
        long long est = atoll(comma + 1), act = expected[i];
        long long drift = (act > 0) ? (llabs(est - act) * 100 / act) : 0;
        int asserted = (act >= DRIFT_MIN_BYTES);
        printf("    %-10s est=%-7lld actual=%-7lld drift=%lld%%%s\n",
               keys[i], est, act, drift, asserted ? "" : "  (logged)");
        if (asserted && drift > DRIFT_TOLERANCE_PCT) failures++;
    }
    free(buf);
    assert_int_equal(failures, 0);
}

/*** Group ***/

int group_rdb_to_mem_stat(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_memStat_fields_hash_listpack),
        cmocka_unit_test(test_memStat_fields_set_intset),
        cmocka_unit_test(test_memStat_fields_zset_skiplist),
        cmocka_unit_test(test_memStat_fields_lists),
        cmocka_unit_test(test_memStat_stat_default),
        cmocka_unit_test(test_memStat_stat_expiry),
        cmocka_unit_test(test_memStat_live_drift),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
