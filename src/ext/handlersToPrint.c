#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "handlersCommon.h"
#include "../../deps/redis/sha256.h"

struct RdbxToPrint {
    RdbxHandlersBase base;   /* MUST be first (shared callbacks cast userData) */
    const char *keyFmt;
    const char *auxFmt;
};

/*** Formatting ***/

/* Print first 4 bytes of sha256 of key, like __RDB_key() */
static char *printsha256(char *key, int len, char buf[9]) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*) key, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 4; i++) snprintf(buf + (i * 2), 3, "%02x", hash[i]);
    buf[8] = '\0';
    return buf;
}

/* Parses an optional printf-style width spec ("-"? digits) starting at p, sets
 * leftAlign/width, and returns the position of the specifier character. */
static const char *parseWidth(const char *p, int *leftAlign, int *width) {
    *leftAlign = 0; *width = 0;
    if (*p == '-') { *leftAlign = 1; p++; }
    while (*p >= '0' && *p <= '9') { *width = (*width * 10) + (*p - '0'); p++; }
    return p;
}

static void emitPadded(FILE *out, int leftAlign, int width, const char *s) {
    if (width > 0) fprintf(out, leftAlign ? "%-*s" : "%*s", width, s);
    else fputs(s, out);
}

/* Escape `src` into `dst` (same rules as outputPlainEscaping); used when a width
 * is requested on %k so the escaped text can be padded. */
static void escapeToBuf(char *dst, size_t dstsz, const char *src, size_t len) {
    size_t o = 0;
    while (len-- && o + 7 < dstsz) {
        unsigned char c = (unsigned char) *src++;
        switch (c) {
            case '\\': case '"': dst[o++] = '\\'; dst[o++] = (char) c; break;
            case '\n': dst[o++]='\\'; dst[o++]='n'; break;
            case '\f': dst[o++]='\\'; dst[o++]='f'; break;
            case '\r': dst[o++]='\\'; dst[o++]='r'; break;
            case '\t': dst[o++]='\\'; dst[o++]='t'; break;
            case '\b': dst[o++]='\\'; dst[o++]='b'; break;
            default:
                if (isprint(c)) dst[o++] = (char) c;
                else { int n = snprintf(dst + o, dstsz - o, "\\u%04x", c); if (n > 0) o += (size_t) n; }
        }
    }
    dst[o] = '\0';
}

/* Renders a single key line per `fmt`. Reads ctx->base.keyCtx + ctx->base.dbnum.
 * `string` is the string value or NULL. Specifiers accept an optional printf-style
 * width, e.g. %-20k, %10z. */
static void printKeyFmt(RdbxToPrint *ctx, const char *fmt, RdbBulk string, size_t stringLen) {
    char buf[1024];   /* scratch for one rendered field (incl. width-padded %k) */
    const char *p = fmt;
    RdbxKeyCtx *kc = &ctx->base.keyCtx;
    FILE *out = ctx->base.outfile;

    if (fmt == NULL || fmt[0] == '\0') return;

    while (*p) {
        if (*p != '%') { fputc(*p, out); p++; continue; }

        int leftAlign, width;
        p = parseWidth(p + 1, &leftAlign, &width);
        if (*p == '\0') break;

        const char *outStr = NULL;   /* rendered text to pad; NULL if already emitted */
        switch (*p) {
            case 'd': snprintf(buf, sizeof buf, "%d", ctx->base.dbnum); outStr = buf; break;
            case 'h': outStr = printsha256(kc->key, kc->keyLen, buf); break;
            case 'k':
                if (width > 0) { escapeToBuf(buf, sizeof buf, kc->key, kc->keyLen); outStr = buf; }
                else rdbxOutputPlainEscaping(out, kc->key, kc->keyLen);
                break;
            case 'v':  /* values may be large -> stream directly; width not applied */
                if (string) rdbxOutputPlainEscaping(out, string, stringLen);
                else fputs("{...}", out);
                break;
            case 'n': outStr = rdbxEncodingStr(kc->info.opcode); break;
            case 'z': snprintf(buf, sizeof buf, "%llu", (unsigned long long) kc->memBytes); outStr = buf; break;
            case 'g': snprintf(buf, sizeof buf, "%llu", (unsigned long long) kc->largest); outStr = buf; break;
            case 't': outStr = rdbxTypeName(kc->info.dataType); break;
            case 'e': snprintf(buf, sizeof buf, "%lld", kc->info.expiretime); outStr = buf; break;
            case 'r': snprintf(buf, sizeof buf, "%lld", kc->info.lruIdle); outStr = buf; break;
            case 'f': snprintf(buf, sizeof buf, "%d", kc->info.lfuFreq); outStr = buf; break;
            case 'm': snprintf(buf, sizeof buf, "%d", kc->info.numMeta); outStr = buf; break;
            case 'i': snprintf(buf, sizeof buf, "%ld", kc->items); outStr = buf; break;
            default:  buf[0] = '%'; buf[1] = *p; buf[2] = '\0'; outStr = buf; break;
        }
        if (outStr) emitPadded(out, leftAlign, width, outStr);
        p++;
    }
    fputc('\n', out);
}

static void printAuxFmt(RdbxToPrint *ctx, RdbBulk field, RdbBulk value) {
    const char *p = ctx->auxFmt;
    FILE *out = ctx->base.outfile;
    while (*p) {
        if (*p == '%') {
            p++;
            switch (*p) {
                case 'f': rdbxOutputPlainEscaping(out, field, RDB_bulkLen(ctx->base.p, field)); break;
                case 'v': rdbxOutputPlainEscaping(out, value, RDB_bulkLen(ctx->base.p, value)); break;
                default:  fprintf(out, "%%%c", *p);
            }
        } else {
            fputc(*p, out);
        }
        p++;
    }
    fputc('\n', out);
}

/*** Handling ***/

static RdbRes toPrintAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    UNUSED(p);
    printAuxFmt((RdbxToPrint *) userData, auxkey, auxval);
    return RDB_OK;
}

static RdbRes toPrintNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(p);
    ((RdbxToPrint *) userData)->base.dbnum = db;
    return RDB_OK;
}

static RdbRes toPrintNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    rdbxKeyCtxReset(p, &((RdbxToPrint *) userData)->base.keyCtx, key, info);
    return RDB_OK;
}

static RdbRes toPrintList(RdbParser *p, void *userData, RdbBulk item) {
    rdbxAccountElem(&((RdbxToPrint *) userData)->base.keyCtx, RDB_bulkLen(p, item), 1);
    return RDB_OK;
}

static RdbRes toPrintSet(RdbParser *p, void *userData, RdbBulk member) {
    rdbxAccountElem(&((RdbxToPrint *) userData)->base.keyCtx, RDB_bulkLen(p, member), 1);
    return RDB_OK;
}

static RdbRes toPrintZset(RdbParser *p, void *userData, RdbBulk member, double score) {
    UNUSED(score);
    rdbxAccountZset(&((RdbxToPrint *) userData)->base.keyCtx, RDB_bulkLen(p, member));
    return RDB_OK;
}

static RdbRes toPrintHash(RdbParser *p, void *userData, RdbBulk field, RdbBulk value, int64_t expireAt) {
    UNUSED(expireAt);
    rdbxAccountPair(&((RdbxToPrint *) userData)->base.keyCtx,
                    RDB_bulkLen(p, field), RDB_bulkLen(p, value));
    return RDB_OK;
}

static RdbRes toPrintModule(RdbParser *p, void *userData, RdbBulk name, size_t serializedSize) {
    UNUSED(p, name);
    rdbxAccountModule(&((RdbxToPrint *) userData)->base.keyCtx, serializedSize);
    return RDB_OK;
}

static RdbRes toPrintStreamItem(RdbParser *p, void *userData, RdbStreamID *id,
                                RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    UNUSED(id, itemsLeft);
    rdbxAccountPair(&((RdbxToPrint *) userData)->base.keyCtx,
                    RDB_bulkLen(p, field), RDB_bulkLen(p, value));
    return RDB_OK;
}

static RdbRes toPrintArrayElement(RdbParser *p, void *userData, uint64_t idx, RdbBulk value) {
    UNUSED(idx);
    rdbxAccountElem(&((RdbxToPrint *) userData)->base.keyCtx, RDB_bulkLen(p, value), 1);
    return RDB_OK;
}

static RdbRes toPrintEndKey(RdbParser *p, void *userData) {
    RdbxToPrint *ctx = userData;

    if (ctx->base.keyCtx.skip == 0) {  /* aggregate types (strings handled at value) */
        rdbxComputeMemBytes(&ctx->base.keyCtx);
        printKeyFmt(ctx, ctx->keyFmt, NULL, 0);
    }
    RDB_bulkCopyFree(p, ctx->base.keyCtx.key);
    ctx->base.keyCtx.key = NULL;
    return RDB_OK;
}

static RdbRes toPrintString(RdbParser *p, void *userData, RdbBulk string) {
    RdbxToPrint *ctx = userData;
    size_t len = RDB_bulkLen(p, string);

    rdbxKeyCtxSetString(&ctx->base.keyCtx, string, len);
    printKeyFmt(ctx, ctx->keyFmt, string, len);
    ctx->base.keyCtx.skip = 1;   /* fully handled here; don't re-handle at endKey */
    return RDB_OK;
}

static void deletePrintCtx(RdbParser *p, void *data) {
    RdbxToPrint *ctx = data;
    rdbxBaseDestroy(p, &ctx->base);
    RDB_free(p, ctx);
}

/*** API ***/

RdbxToPrint *RDBX_createHandlersToPrint(RdbParser *p,
                                        const char *auxFmt,
                                        const char *keyFmt,
                                        const char *outFilename)
{
    RdbxToPrint *ctx = RDB_alloc(p, sizeof(RdbxToPrint));
    memset(ctx, 0, sizeof(RdbxToPrint));
    if (rdbxBaseInit(p, &ctx->base, outFilename)) {
        RDB_free(p, ctx);
        return NULL;
    }
    ctx->auxFmt = auxFmt;
    ctx->keyFmt = keyFmt;

    RdbHandlersDataCallbacks dataCb = {
            .handleNewDb        = toPrintNewDb,
            .handleNewKey       = toPrintNewKey,
            .handleEndKey       = toPrintEndKey,
            .handleStringValue  = toPrintString,
            .handleListItem     = toPrintList,
            .handleSetMember    = toPrintSet,
            .handleZsetMember   = toPrintZset,
            .handleHashField    = toPrintHash,
            .handleModule       = toPrintModule,
            .handleStreamItem   = toPrintStreamItem,
            .handleArrayElement = toPrintArrayElement,
    };
    if (auxFmt)
        dataCb.handleAuxField = toPrintAuxField;

    RDB_createHandlersData(p, &dataCb, ctx, deletePrintCtx);
    return ctx;
}
