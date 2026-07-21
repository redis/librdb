#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "handlersCommon.h"

#define STAT_TOPN_DEFAULT 10

/* Per-type value distribution for p90/p99 reporting: a log-scale histogram with
 * HIST_SUB sub-buckets per power of two (~19% bucket width). */
#define HIST_LOG2_SUB  2                             /* sub-buckets per octave = 2^this (~19% bucket width) */
#define HIST_SUB       (1 << HIST_LOG2_SUB)          /* derived: 4 sub-buckets, keeps the two in lockstep   */
#define HIST_NBUCKETS  209                           /* 1 + HIST_SUB*52: value 0 + 52 octaves (2^0..2^51) */

typedef struct Hist {
    uint64_t bucket[HIST_NBUCKETS];
} Hist;

typedef struct TopEntry {
    char          *key;      /* owned copy (RDB_alloc), freed on delete */
    unsigned int   keyLen;
    RdbKeyInfo     info;
    unsigned long  items;
    uint64_t       memBytes;
    uint64_t       largest;
    int            dbnum;
} TopEntry;

/* Per-data-type running aggregate (one instance per RDB_DATA_TYPE_*). */
typedef struct TypeAgg {
    uint64_t count;
    uint64_t bytes;
    uint64_t items;
    uint64_t nVolatile;
    uint64_t nExpired;
    uint64_t maxItems;
    uint64_t maxMem;
    Hist     itemsHist;
    Hist     memHist;
} TypeAgg;

struct RdbxToStat {
    RdbxHandlersBase base;   /* MUST be first (shared callbacks cast userData) */
    int histFlags;                /* RDBX_STAT_HIST_* : which per-type histograms to append */
    uint64_t volatileBytes;       /* memory held by keys that carry an expiry */
    uint64_t nowMs;               /* reference time for expiry evaluation (ms) */
    uint64_t dbKeys;
    uint64_t dbExpires;           /* key/expiry counts of the current db */
    uint64_t keyspaceTableBytes;  /* accumulated keyspace dict bucket arrays */
    uint64_t expiresTableBytes;   /* accumulated expires dict bucket arrays  */
    TopEntry *top; 
    int topCap;
    int nTop;  /* top-N largest keys, kept as a min-heap (see heapTopInsert) */
    
    TypeAgg typeAgg[RDB_DATA_TYPE_MAX]; /* Aggregate statistics per type */
};

/* Bucket-array bytes of a hashtable holding `n` entries: next-power-of-two slots
 * (dict min 4) x pointer size, x1.5 for worst-case rehash headroom. This is the
 * keyspace/expires overhead not attributable to any single key. */
static uint64_t dictTableBytes(uint64_t n) {
    if (n == 0) return 0;
    uint64_t slots = 4;
    while (slots < n) slots <<= 1;
    return slots * 8 * 3 / 2;
}

/*** Per-type value distribution (p90 / p99) ***/

static int hbit(uint64_t v) {   /* index of highest set bit; v >= 1 */
#if defined(__GNUC__) || defined(__clang__)
    return 63 - __builtin_clzll(v);
#else
    int r = 0; while (v >>= 1) r++; return r;
#endif
}

/* Record one sample; small integers land in exact buckets, larger values in
 * log buckets (HIST_SUB sub-buckets per octave). */
static void histAdd(Hist *h, uint64_t v) {
    int idx;
    if (v == 0) idx = 0;
    else {
        int hi = hbit(v), shift = hi - HIST_LOG2_SUB;
        uint64_t mant = (shift >= 0) ? (v >> shift) : (v << -shift);
        idx = 1 + hi * HIST_SUB + (int) (mant & (HIST_SUB - 1));
        if (idx >= HIST_NBUCKETS) idx = HIST_NBUCKETS - 1;
    }
    h->bucket[idx]++;
}

static uint64_t histLow(int idx) {   /* bucket lower edge */
    int k = idx - 1, oct = k / HIST_SUB, sub = k % HIST_SUB;
    uint64_t base = 1ULL << oct;
    return base + (uint64_t) sub * base / HIST_SUB;
}

/* Representative value: midpoint of the bucket's [lower, next-lower) span.
 * Exact for small integers; within ~half a bucket (~10%) for large values. */
static uint64_t histRep(int idx) {
    if (idx == 0) return 0;
    uint64_t lo = histLow(idx);
    return lo + (histLow(idx + 1) - lo) / 2;
}

/* Nearest-rank percentile (pct in 1..100) over `total` recorded samples. */
static uint64_t histPct(const Hist *h, uint64_t total, unsigned pct) {
    if (total == 0) return 0;
    uint64_t rank = (total * pct + 99) / 100, cum = 0;
    for (int i = 0; i < HIST_NBUCKETS; i++) {
        cum += h->bucket[i];
        if (cum >= rank) return histRep(i);
    }
    return histRep(HIST_NBUCKETS - 1);
}

/*** Statistics folding ***/

/* Fill a top-N slot from the current key accumulator (owns a copy of the key). */
static void heapTopFill(RdbxToStat *ctx, TopEntry *e) {
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
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

static void heapTopSwap(TopEntry *a, TopEntry *b) { TopEntry t = *a; *a = *b; *b = t; }

/* The top-N set is a binary min-heap keyed by memBytes, so the smallest kept key
 * is always at the root: each new key costs O(log N) instead of an O(N) scan. */
static void heapTopShiftUp(TopEntry *h, int i) {
    for (int parent; i > 0 && h[parent = (i - 1) / 2].memBytes > h[i].memBytes; i = parent)
        heapTopSwap(&h[parent], &h[i]);
}

static void heapTopShiftDown(TopEntry *h, int n, int i) {
    for (;;) {
        int l = 2 * i + 1, r = 2 * i + 2, min = i;
        if (l < n && h[l].memBytes < h[min].memBytes) min = l;
        if (r < n && h[r].memBytes < h[min].memBytes) min = r;
        if (min == i) break;
        heapTopSwap(&h[min], &h[i]);
        i = min;
    }
}

/* Streaming top-N: keep only the N largest keys in min-heap */
static void heapTopInsert(RdbxToStat *ctx) {
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
    if (ctx->nTop < ctx->topCap) {          /* still filling: push and sift up */
        heapTopFill(ctx, &ctx->top[ctx->nTop]);
        heapTopShiftUp(ctx->top, ctx->nTop++);
    } else if (kc->memBytes > ctx->top[0].memBytes) {  /* bigger than the smallest kept */
        RDB_free(ctx->base.p, ctx->top[0].key);
        heapTopFill(ctx, &ctx->top[0]);
        heapTopShiftDown(ctx->top, ctx->nTop, 0);
    }
}

static void aggregateKey(RdbxToStat *ctx) {
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
    int t = kc->info.dataType;
    ctx->dbKeys++;
    if (kc->info.expiretime != -1) ctx->dbExpires++;
    if (t >= 0 && t < RDB_DATA_TYPE_MAX) {
        ctx->typeAgg[t].count++;
        ctx->typeAgg[t].bytes += kc->memBytes;
        ctx->typeAgg[t].items += kc->items;
        if (kc->items > ctx->typeAgg[t].maxItems) 
            ctx->typeAgg[t].maxItems = kc->items;
        if (kc->memBytes > ctx->typeAgg[t].maxMem)   
            ctx->typeAgg[t].maxMem   = kc->memBytes;
        histAdd(&ctx->typeAgg[t].itemsHist, kc->items);
        histAdd(&ctx->typeAgg[t].memHist, kc->memBytes);
        if (kc->info.expiretime != -1) {
            ctx->typeAgg[t].nVolatile++;
            ctx->volatileBytes += kc->memBytes;
            if ((uint64_t) kc->info.expiretime < ctx->nowMs)
                ctx->typeAgg[t].nExpired++;
        }
    }
    heapTopInsert(ctx);
}

/* qsort comparator for the final output pass (over min-heap) */
static int topCmpDesc(const void *a, const void *b) {
    const TopEntry *ea = a, *eb = b;
    if (ea->memBytes != eb->memBytes)
        return (ea->memBytes < eb->memBytes) - (ea->memBytes > eb->memBytes);
    /* Deterministic tie-break (qsort is not stable): equal-memory keys must
     * order the same on every platform, else the golden report diff spuriously
     * fails. Order by db, then key name. */
    if (ea->dbnum != eb->dbnum)
        return (ea->dbnum > eb->dbnum) - (ea->dbnum < eb->dbnum);
    return strcmp(ea->key, eb->key);
}

/* Human-readable byte size. Rotating buffers so several calls in one fprintf
 * (e.g. memory + avg) don't alias. */
static const char *human(uint64_t b) {
    static char ring[8][24]; static int r = 0;
    char *s = ring[r++ & 7];
    const char *u[] = {"B", "K", "M", "G", "T"};
    double v = (double) b; int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; i++; }
    if (i == 0) 
        snprintf(s, 24, "%lluB", (unsigned long long) b);
    else
        snprintf(s, 24, "%.1f%s", v, u[i]);
    
    return s;
}

/* Human-readable count (base 1000), or "-" when zero. */
static const char *humanCount(uint64_t n) {
    static char ring[8][24]; static int r = 0;
    char *s = ring[r++ & 7];
    const char *u[] = {"", "K", "M", "B", "T"};
    double v = (double) n; int i = 0;
    if (n == 0) return "-";
    while (v >= 1000 && i < 4) { v /= 1000; i++; }
    if (i == 0) snprintf(s, 24, "%llu", (unsigned long long) n);
    else        snprintf(s, 24, "%.1f%s", v, u[i]);
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

/* Optional appendix (--histogram): every non-empty bucket of every per-type
 * histogram, so the full items/memory distribution can be inspected. Buckets are
 * labelled by their lower bound (exact for small values, coarse for large). */
static void renderHistograms(RdbxToStat *ctx, const int *order, int nTypes) {
    FILE *o = ctx->base.outfile;
    fprintf(o, "\nHistograms (non-empty buckets; min = bucket lower bound, keys = key count, "
               "share = %% of type, cum%% = cumulative share):\n");
    for (int idx = 0; idx < nTypes; idx++) {
        int t = order[idx];
        uint64_t total = ctx->typeAgg[t].count;   /* every key is recorded once */
        for (int which = 0; which < 2; which++) {
            int want = which ? RDBX_STAT_HIST_MEM : RDBX_STAT_HIST_ITEMS;
            if (!(ctx->histFlags & want)) continue;
            const Hist *h = which ? &ctx->typeAgg[t].memHist : &ctx->typeAgg[t].itemsHist;
            int any = 0;
            for (int i = 0; i < HIST_NBUCKETS && !any; i++) any = (h->bucket[i] != 0);
            if (!any) continue;
            fprintf(o, "\n  %s / %s per key\n", rdbxTypeName(t), which ? "memory" : "items");
            fprintf(o, "    %10s   %12s  %6s  %7s\n", "min", "keys", "share", "cum%");
            uint64_t cum = 0;
            for (int i = 0; i < HIST_NBUCKETS; i++) {
                if (!h->bucket[i]) continue;
                cum += h->bucket[i];
                const char *label = (i == 0) ? "0"
                    : (which ? human(histLow(i)) : humanCount(histLow(i)));
                double pct  = total ? (h->bucket[i] * 100.0 / total) : 0;
                double cpct = total ? (cum * 100.0 / total) : 0;
                fprintf(o, "    %10s : %12llu  %5.1f%%  %6.1f%%\n",
                        label, (unsigned long long) h->bucket[i], pct, cpct);
            }
        }
    }
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
                int tmp = order[i]; 
                order[i] = order[j]; 
                order[j] = tmp;
            }

    uint64_t totalItems = 0, totalVol = 0, totalExp = 0;
    for (int i = 0; i < nTypes; i++) {
        int t = order[i];
        totalItems += ctx->typeAgg[t].items;
        totalVol   += ctx->typeAgg[t].nVolatile;
        totalExp   += ctx->typeAgg[t].nExpired;
    }

    fprintf(o, "Statistics (Memory is estimated):\n");
    /* Two-line header: each bracketed group label spans its columns exactly. The
     * 38-space pad, the single spaces between brackets, and the bracket widths all
     * track the row format below -- keep them in sync if column widths change. */
    fprintf(o, "%38s[     Expiry     ] [     Memory    ] [          Memory per key         ] [      Items per key       ]\n", "");
    fprintf(o, "  %-8s %12s %13s %9s %8s %10s %6s %8s %8s %8s %8s %6s %6s %6s %7s\n",
            "type", "keys", "items", "volatile", "expired", "mem", "mem%",
            "avg", "p90", "p99", "max", "avg", "p90", "p99", "max");
    for (int i = 0; i < nTypes; i++) {
        int t = order[i];
        uint64_t c = ctx->typeAgg[t].count, b = ctx->typeAgg[t].bytes, it = ctx->typeAgg[t].items;
        double pct = totalBytes ? (b * 100.0 / totalBytes) : 0;
        fprintf(o, "  %-8s %12llu %13s %9llu %8llu %10s %5.1f%% %8s %8s %8s %8s %6s %6s %6s %7s\n",
                rdbxTypeName(t), (unsigned long long) c, countOrDash(it),
                (unsigned long long) ctx->typeAgg[t].nVolatile,
                (unsigned long long) ctx->typeAgg[t].nExpired,
                human(b), pct,
                human(c ? b / c : 0),
                human(histPct(&ctx->typeAgg[t].memHist, c, 90)),
                human(histPct(&ctx->typeAgg[t].memHist, c, 99)),
                human(ctx->typeAgg[t].maxMem),
                humanCount(c ? it / c : 0),
                humanCount(histPct(&ctx->typeAgg[t].itemsHist, c, 90)),
                humanCount(histPct(&ctx->typeAgg[t].itemsHist, c, 99)),
                humanCount(ctx->typeAgg[t].maxItems));
    }
    fprintf(o, "  %-8s %12llu %13llu %9llu %8llu %10s %6s %8s %8s %8s %8s %6s %6s %6s %7s\n\n", "TOTAL",
            (unsigned long long) totalKeys, (unsigned long long) totalItems,
            (unsigned long long) totalVol, (unsigned long long) totalExp,
            human(totalBytes), "", "", "", "", "", "", "", "", "");

    if (ctx->volatileBytes) {
        double pct = totalBytes ? (ctx->volatileBytes * 100.0 / totalBytes) : 0;
        fprintf(o, "  Volatile keys hold %s (%.1f%% of memory)\n", human(ctx->volatileBytes), pct);
    }

    uint64_t overhead = ctx->keyspaceTableBytes + ctx->expiresTableBytes;
    fprintf(o, "  Estimated keyspace tables (dict overhead): %s\n", human(overhead));
    fprintf(o, "  Estimated dataset memory: %s (objects + tables; excludes server/client/frag)\n",
            human(totalBytes + overhead));

    if (ctx->nTop > 0) {
        qsort(ctx->top, ctx->nTop, sizeof(TopEntry), topCmpDesc);
        fprintf(o, "\nTop %d keys by memory:\n", ctx->nTop);
        fprintf(o, "  %12s %-8s %5s %12s %10s %8s  %s\n",
                "memory", "type", "db", "items", "avg item", "ttl", "key");
        for (int i = 0; i < ctx->nTop; i++) {
            TopEntry *e = &ctx->top[i];
            fprintf(o, "  %12s %-8s %5d %12s %10s %8s  %s\n", human(e->memBytes),
                    rdbxTypeName(e->info.dataType), e->dbnum,
                    countOrDash(e->items),
                    e->items ? human(e->memBytes / e->items) : "-",
                    humanDur(e->info.expiretime, ctx->nowMs), e->key);
        }
    }

    if (ctx->histFlags) renderHistograms(ctx, order, nTypes);
}

/*** Handling ***/

/* Close out the current db: its dict tables scale with its own key count, so fold
 * them per-db (keys arrive grouped by db) rather than off the grand total. */
static void finalizeDb(RdbxToStat *ctx) {
    ctx->keyspaceTableBytes += dictTableBytes(ctx->dbKeys);
    ctx->expiresTableBytes  += dictTableBytes(ctx->dbExpires);
    ctx->dbKeys = ctx->dbExpires = 0;
}

static RdbRes toStatNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(p);
    RdbxToStat *ctx = userData;
    finalizeDb(ctx);   /* fold the previous db (no-op on the first db) */
    ctx->base.dbnum = db;
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
        aggregateKey(ctx);
    }
    RDB_bulkCopyFree(p, ctx->base.keyCtx.key);
    ctx->base.keyCtx.key = NULL;
    return RDB_OK;
}

static RdbRes toStatString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToStat *ctx = userData;
    rdbxKeyCtxSetString(&ctx->base.keyCtx, string, RDB_bulkLen(p, string));
    aggregateKey(ctx);
    ctx->base.keyCtx.skip = 1;   /* fully handled here; don't re-handle at endKey */
    return RDB_OK;
}

static RdbRes toStatEndRdb(RdbParser *p, void *userData) {
    UNUSED(p);
    RdbxToStat *ctx = userData;
    finalizeDb(ctx);   /* fold the last db before rendering */
    renderPretty(ctx);
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
                                      int flags, const char *outFilename) {
    RdbxToStat *ctx = RDB_alloc(p, sizeof(RdbxToStat));
    memset(ctx, 0, sizeof(RdbxToStat));
    if (rdbxBaseInit(p, &ctx->base, outFilename)) {
        RDB_free(p, ctx);
        return NULL;
    }
    ctx->nowMs = (uint64_t) (nowSecs > 0 ? nowSecs : time(NULL)) * 1000ULL;
    ctx->histFlags = flags & (RDBX_STAT_HIST_ITEMS | RDBX_STAT_HIST_MEM);
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
