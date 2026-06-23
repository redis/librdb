#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "handlersCommon.h"

#define STAT_TOPN_DEFAULT 10

typedef struct TopEntry {
    char        *key;       /* owned copy (RDB_alloc), freed on delete */
    unsigned int keyLen;
    RdbKeyInfo   info;
    unsigned long items;
    uint64_t     memBytes;
    uint64_t     largest;
    int          dbnum;
} TopEntry;

struct RdbxToStat {
    RdbxHandlersBase base;   /* MUST be first (shared callbacks cast userData) */
    struct { uint64_t count, bytes, items, nVolatile, nExpired; } typeAgg[RDB_DATA_TYPE_MAX];
    uint64_t volatileBytes;  /* memory held by keys that carry an expiry */
    uint64_t nowMs;          /* reference time for expiry evaluation (ms) */
    TopEntry *top; int topCap, nTop;
};

/*** Statistics folding ***/

static void topInsert(RdbxToStat *ctx) {
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
    int slot = -1;
    if (ctx->nTop < ctx->topCap) {
        slot = ctx->nTop++;
    } else { /* replace the current minimum if this key is bigger */
        int mn = 0;
        for (int i = 1; i < ctx->topCap; i++)
            if (ctx->top[i].memBytes < ctx->top[mn].memBytes) mn = i;
        if (kc->memBytes <= ctx->top[mn].memBytes) return;
        RDB_free(ctx->base.p, ctx->top[mn].key);
        slot = mn;
    }
    TopEntry *e = &ctx->top[slot];
    e->keyLen = kc->keyLen;
    e->key = RDB_alloc(ctx->base.p, e->keyLen + 1);
    memcpy(e->key, kc->key, e->keyLen);
    e->key[e->keyLen] = '\0';
    e->info = kc->info;
    e->items = kc->items;
    e->memBytes = kc->memBytes;
    e->largest = kc->largest;
    e->dbnum = ctx->base.dbnum;
}

static void foldKey(RdbxToStat *ctx) {
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
    int t = kc->info.dataType;
    if (t >= 0 && t < RDB_DATA_TYPE_MAX) {
        ctx->typeAgg[t].count++;
        ctx->typeAgg[t].bytes += kc->memBytes;
        ctx->typeAgg[t].items += kc->items;
        if (kc->info.expiretime != -1) {
            ctx->typeAgg[t].nVolatile++;
            ctx->volatileBytes += kc->memBytes;
            if ((uint64_t) kc->info.expiretime < ctx->nowMs)
                ctx->typeAgg[t].nExpired++;
        }
    }
    topInsert(ctx);
}

static int topCmpDesc(const void *a, const void *b) {
    uint64_t x = ((const TopEntry*)a)->memBytes, y = ((const TopEntry*)b)->memBytes;
    return (x < y) - (x > y);
}

/* Human-readable byte size. Rotating buffers so several calls in one fprintf
 * (e.g. memory + avg) don't alias. */
static const char *human(uint64_t b) {
    static char ring[4][24]; static int r = 0;
    char *s = ring[r++ & 3];
    const char *u[] = {"B", "K", "M", "G", "T"};
    double v = (double) b; int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; i++; }
    if (i == 0) snprintf(s, 24, "%llu B", (unsigned long long) b);
    else        snprintf(s, 24, "%.1f %s", v, u[i]);
    return s;
}

/* A count, or "-" when zero (e.g. element count for a string row, which has none). */
static const char *countOrDash(uint64_t v) {
    static char ring[4][24]; static int r = 0;
    char *s = ring[r++ & 3];
    if (v == 0) return "-";
    snprintf(s, 24, "%llu", (unsigned long long) v);
    return s;
}

/* Remaining TTL of a key given its absolute expiry (ms) and the reference time:
 * "none" if no expiry, "expired" if already past, else a coarse duration. */
static const char *humanDur(long long expiretimeMs, uint64_t nowMs) {
    static char buf[24];
    if (expiretimeMs == -1) return "none";
    if ((uint64_t) expiretimeMs < nowMs) return "expired";
    long long s = ((uint64_t) expiretimeMs - nowMs) / 1000;
    if (s < 60)        snprintf(buf, sizeof(buf), "%llds", s);
    else if (s < 3600) snprintf(buf, sizeof(buf), "%lldm", s / 60);
    else if (s < 86400)snprintf(buf, sizeof(buf), "%lldh", s / 3600);
    else               snprintf(buf, sizeof(buf), "%lldd", s / 86400);
    return buf;
}

/* Built-in formatted statistics report: a by-type table (sorted by memory, with
 * a TOTAL row) followed by the largest-by-memory keys. */
static void renderPretty(RdbxToStat *ctx) {
    FILE *o = ctx->base.outfile;
    uint64_t totalBytes = 0, totalKeys = 0;
    int order[RDB_DATA_TYPE_MAX], nTypes = 0;

    for (int t = 0; t < RDB_DATA_TYPE_MAX; t++) {
        if (!ctx->typeAgg[t].count) continue;
        order[nTypes++] = t;
        totalKeys  += ctx->typeAgg[t].count;
        totalBytes += ctx->typeAgg[t].bytes;
    }
    /* sort type rows by memory desc (simple selection; <=9 rows) */
    for (int i = 0; i < nTypes; i++)
        for (int j = i + 1; j < nTypes; j++)
            if (ctx->typeAgg[order[j]].bytes > ctx->typeAgg[order[i]].bytes) {
                int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
            }

    uint64_t totalItems = 0, totalVol = 0, totalExp = 0;
    for (int i = 0; i < nTypes; i++) {
        int t = order[i];
        totalItems += ctx->typeAgg[t].items;
        totalVol   += ctx->typeAgg[t].nVolatile;
        totalExp   += ctx->typeAgg[t].nExpired;
    }

    fprintf(o, "Memory statistics (estimated):\n");
    fprintf(o, "  %-8s %12s %14s %10s %10s %9s %12s %10s %7s\n",
            "type", "keys", "items", "items/key", "volatile", "expired", "memory", "avg", "mem%");
    for (int i = 0; i < nTypes; i++) {
        int t = order[i];
        uint64_t c = ctx->typeAgg[t].count, b = ctx->typeAgg[t].bytes, it = ctx->typeAgg[t].items;
        double pct = totalBytes ? (b * 100.0 / totalBytes) : 0;
        fprintf(o, "  %-8s %12llu %14s %10s %10llu %9llu %12s %10s %6.1f%%\n",
                rdbxTypeName(t), (unsigned long long) c, countOrDash(it),
                countOrDash(c ? it / c : 0),
                (unsigned long long) ctx->typeAgg[t].nVolatile,
                (unsigned long long) ctx->typeAgg[t].nExpired,
                human(b), human(c ? b / c : 0), pct);
    }
    fprintf(o, "  %-8s %12llu %14llu %10s %10llu %9llu %12s\n", "TOTAL",
            (unsigned long long) totalKeys, (unsigned long long) totalItems, "",
            (unsigned long long) totalVol, (unsigned long long) totalExp, human(totalBytes));
    if (ctx->volatileBytes) {
        double pct = totalBytes ? (ctx->volatileBytes * 100.0 / totalBytes) : 0;
        fprintf(o, "  volatile keys hold %s (%.1f%% of memory)\n", human(ctx->volatileBytes), pct);
    }

    if (ctx->nTop > 0) {
        qsort(ctx->top, ctx->nTop, sizeof(TopEntry), topCmpDesc);
        fprintf(o, "\nTop %d keys by memory:\n", ctx->nTop);
        fprintf(o, "  %12s %-8s %5s %12s %10s %8s  %s\n",
                "memory", "type", "db", "items", "avg item", "ttl", "key");
        for (int i = 0; i < ctx->nTop; i++) {
            TopEntry *e = &ctx->top[i];
            fprintf(o, "  %12s %-8s %5d %12llu %10s %8s  %s\n", human(e->memBytes),
                    rdbxTypeName(e->info.dataType), e->dbnum,
                    (unsigned long long) e->items,
                    e->items ? human(e->memBytes / e->items) : "-",
                    humanDur(e->info.expiretime, ctx->nowMs), e->key);
        }
    }
}

/*** Handling ***/

static RdbRes toStatNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(p);
    ((RdbxToStat *) userData)->base.dbnum = db;
    return RDB_OK;
}

static RdbRes toStatNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    rdbxKeyCtxReset(p, &((RdbxToStat *) userData)->base.keyCtx, key, info);
    return RDB_OK;
}

static RdbRes toStatList(RdbParser *p, void *userData, RdbBulk item) {
    rdbxAccountElem(&((RdbxToStat *) userData)->base.keyCtx, RDB_bulkLen(p, item), 1);
    return RDB_OK;
}

static RdbRes toStatSet(RdbParser *p, void *userData, RdbBulk member) {
    rdbxAccountElem(&((RdbxToStat *) userData)->base.keyCtx, RDB_bulkLen(p, member), 1);
    return RDB_OK;
}

static RdbRes toStatZset(RdbParser *p, void *userData, RdbBulk member, double score) {
    UNUSED(score);
    rdbxAccountZset(&((RdbxToStat *) userData)->base.keyCtx, RDB_bulkLen(p, member));
    return RDB_OK;
}

static RdbRes toStatHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value, int64_t expireAt) {
    UNUSED(expireAt);
    rdbxAccountPair(&((RdbxToStat *) userData)->base.keyCtx,
                    RDB_bulkLen(p, field), RDB_bulkLen(p, value));
    return RDB_OK;
}

static RdbRes toStatModule(RdbParser *p, void *userData, RdbBulk name, size_t serializedSize) {
    UNUSED(p, name);
    rdbxAccountModule(&((RdbxToStat *) userData)->base.keyCtx, serializedSize);
    return RDB_OK;
}

static RdbRes toStatStreamItem(RdbParser *p, void *userData, RdbStreamID *id,
                               RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    UNUSED(id, itemsLeft);
    rdbxAccountPair(&((RdbxToStat *) userData)->base.keyCtx,
                    RDB_bulkLen(p, field), RDB_bulkLen(p, value));
    return RDB_OK;
}

static RdbRes toStatArrayElement(RdbParser *p, void *userData, uint64_t idx, RdbBulk value) {
    UNUSED(idx);
    rdbxAccountElem(&((RdbxToStat *) userData)->base.keyCtx, RDB_bulkLen(p, value), 1);
    return RDB_OK;
}

static RdbRes toStatEndKey(RdbParser *p, void *userData) {
    RdbxToStat *ctx = userData;

    if (ctx->base.keyCtx.skip == 0) {  /* aggregate types (strings handled at value) */
        rdbxComputeMemBytes(&ctx->base.keyCtx);
        foldKey(ctx);
    }
    RDB_bulkCopyFree(p, ctx->base.keyCtx.key);
    ctx->base.keyCtx.key = NULL;
    return RDB_OK;
}

static RdbRes toStatString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToStat *ctx = userData;
    rdbxKeyCtxSetString(&ctx->base.keyCtx, string, RDB_bulkLen(p, string));
    foldKey(ctx);
    ctx->base.keyCtx.skip = 1;   /* fully handled here; don't re-handle at endKey */
    return RDB_OK;
}

static RdbRes toStatEndRdb(RdbParser *p, void *userData) {
    UNUSED(p);
    renderPretty((RdbxToStat *) userData);
    return RDB_OK;
}

static void deleteStatCtx(RdbParser *p, void *data) {
    RdbxToStat *ctx = data;
    for (int i = 0; i < ctx->nTop; i++) RDB_free(p, ctx->top[i].key);
    RDB_free(p, ctx->top);
    rdbxBaseDestroy(p, &ctx->base);
    RDB_free(p, ctx);
}

/*** API ***/

RdbxToStat *RDBX_createHandlersToStat(RdbParser *p, int topN, long long nowSecs,
                                      const char *outFilename) {
    RdbxToStat *ctx = RDB_alloc(p, sizeof(RdbxToStat));
    memset(ctx, 0, sizeof(RdbxToStat));
    if (rdbxBaseInit(p, &ctx->base, outFilename)) {
        RDB_free(p, ctx);
        return NULL;
    }
    ctx->nowMs = (uint64_t) (nowSecs > 0 ? nowSecs : time(NULL)) * 1000ULL;
    ctx->topCap = (topN > 0) ? topN : STAT_TOPN_DEFAULT;
    ctx->top = RDB_alloc(p, sizeof(TopEntry) * ctx->topCap);
    ctx->nTop = 0;

    RdbHandlersDataCallbacks dataCb = {
            .handleNewDb        = toStatNewDb,
            .handleNewKey       = toStatNewKey,
            .handleEndKey       = toStatEndKey,
            .handleStringValue  = toStatString,
            .handleListItem     = toStatList,
            .handleSetMember    = toStatSet,
            .handleZsetMember   = toStatZset,
            .handleHashField    = toStatHash,
            .handleModule       = toStatModule,
            .handleStreamItem   = toStatStreamItem,
            .handleArrayElement = toStatArrayElement,
            .handleEndRdb       = toStatEndRdb,
    };

    RDB_createHandlersData(p, &dataCb, ctx, deleteStatCtx);
    return ctx;
}
