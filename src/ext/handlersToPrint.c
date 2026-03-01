#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "extCommon.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/sha256.h"

struct RdbxToPrint;

#define _STDOUT_STR "<stdout>"

struct RdbxToPrint {
    RdbParser *p;

    int dbnum;
    char *outfileName;  /* Holds output filename or equals _STDOUT_STR */    
    FILE *outfile;    
    const char *keyFmt;
    const char *auxFmt;

    struct {
        int skip;
        RdbBulkCopy key;
        unsigned int keyLen;
        RdbKeyInfo info;
        unsigned long items;
    } keyCtx;

};

static void deleteRdbToPrintCtx(RdbParser *p, void *data) {
    RdbxToPrint *ctx = data;

    RDB_bulkCopyFree(p, ctx->keyCtx.key);

    RDB_log(p, RDB_LOG_DBG, "handlersToPrint: Closing file %s", ctx->outfileName);

    if ((ctx->outfile) && (ctx->outfile != stdout))
        fclose(ctx->outfile);

    RDB_free(p, ctx->outfileName);
    RDB_free(p, ctx);
}

static RdbxToPrint *initRdbToPrintCtx(RdbParser *p, const char *auxFmt,
                                      const char *keyFmt,
                                      const char *outFilename) {
    FILE *f;

    if (outFilename == NULL) {
        f = stdout;
        outFilename = _STDOUT_STR;
    } else if (!(f = fopen(outFilename, "w"))) {
        RDB_reportError(p, RDB_ERR_FAILED_OPEN_FILE,
                        "HandlersRdbToPrint: Failed to open file `%s`. errno=%d: %s",
                        outFilename, errno, strerror(errno));
        return NULL;
    }

    RDB_log(p, RDB_LOG_DBG, "handlersToPrint: Opening file %s", outFilename);

    RdbxToPrint *ctx = RDB_alloc(p, sizeof(RdbxToPrint));
    memset(ctx, 0, sizeof(RdbxToPrint));
    ctx->p = p;
    ctx->auxFmt = auxFmt;
    ctx->keyFmt = keyFmt;
    ctx->outfile = f;
    ctx->outfileName = RDB_alloc(p, strlen(outFilename) + 1);
    strcpy(ctx->outfileName, outFilename);
    return ctx;
}

static void outputPlainEscaping(RdbxToPrint *ctx, char *p, size_t len) {
    while (len--) {
        switch (*p) {
            case '\\':
            case '"':
                fprintf(ctx->outfile, "\\%c", *p); break;
            case '\n': fprintf(ctx->outfile, "\\n"); break;
            case '\f': fprintf(ctx->outfile, "\\f"); break;
            case '\r': fprintf(ctx->outfile, "\\r"); break;
            case '\t': fprintf(ctx->outfile, "\\t"); break;
            case '\b': fprintf(ctx->outfile, "\\b"); break;
            default:
                fprintf(ctx->outfile, (isprint(*p)) ? "%c" : "\\u%04x", (unsigned char)*p);
        }
        p++;
    }
}

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

static void printKeyFmt(RdbxToPrint *ctx, RdbBulk string) {
    char buf[9];
    const char *p = ctx->keyFmt;

    if (ctx->keyFmt[0] == '\0') return; /* if not FMT for keys */

    while (*p) {
        if (*p == '%') {
            p++;
            switch (*p) {
                case 'd':
                    fprintf(ctx->outfile, "%d", ctx->dbnum);
                    break;
                case 'h':  // print sha256 of key
                    fprintf(ctx->outfile, "%s", printsha256(ctx->keyCtx.key,
                                                            ctx->keyCtx.keyLen,
                                                            buf));
                    break;
                case 'k':
                    outputPlainEscaping(ctx, ctx->keyCtx.key, ctx->keyCtx.keyLen);
                    break;
                case 'v':
                    if (string)
                        outputPlainEscaping(ctx, string, RDB_bulkLen(ctx->p, string));
                    else
                        fprintf(ctx->outfile, "{...}");
                    break;
                case 't':
                {
                    switch (ctx->keyCtx.info.dataType)
                    {
                        case RDB_DATA_TYPE_STRING:
                            fprintf(ctx->outfile, "string");
                            break;
                        case RDB_DATA_TYPE_LIST:
                            fprintf(ctx->outfile, "list");
                            break;
                        case RDB_DATA_TYPE_SET:
                            fprintf(ctx->outfile, "set");
                            break;
                        case RDB_DATA_TYPE_ZSET:
                            fprintf(ctx->outfile, "zset");
                            break;
                        case RDB_DATA_TYPE_HASH:
                            fprintf(ctx->outfile, "hash");
                            break;
                        case RDB_DATA_TYPE_STREAM:
                            fprintf(ctx->outfile, "stream");
                            break;
                        case RDB_DATA_TYPE_MODULE:
                            fprintf(ctx->outfile, "module");
                            break;
                        case RDB_DATA_TYPE_FUNCTION:
                            fprintf(ctx->outfile, "function");
                            break;
                        default:
                            fprintf(ctx->outfile, "unknown");
                    }

                }
                    break;
                case 'e':
                    fprintf(ctx->outfile, "%lld", ctx->keyCtx.info.expiretime);
                    break;
                case 'r':
                    fprintf(ctx->outfile, "%lld", ctx->keyCtx.info.lruIdle);
                    break;
                case 'f':
                    fprintf(ctx->outfile, "%d", ctx->keyCtx.info.lfuFreq);
                    break;
                case 'm':
                    fprintf(ctx->outfile, "%d", ctx->keyCtx.info.numMeta);
                    break;
                case 'i':
                    fprintf(ctx->outfile, "%ld", ctx->keyCtx.items);
                    break;
                default:
                    fprintf(ctx->outfile, "%%");
                    fprintf(ctx->outfile, "%c", *p);
            }
        } else {
            fputc(*p, ctx->outfile);
        }
        p++;
    }
    fputc('\n', ctx->outfile);
}

static void printAuxFmt(RdbxToPrint *ctx, RdbBulk field, RdbBulk value) {
    const char *p = ctx->auxFmt;
    while (*p) {
        if (*p == '%') {
            p++;
            switch (*p) {
                case 'f':
                    outputPlainEscaping(ctx, field, RDB_bulkLen(ctx->p, field));
                    break;
                case 'v':
                    outputPlainEscaping(ctx, value, RDB_bulkLen(ctx->p, value));
                    break;
                default:
                    fprintf(ctx->outfile, "%%");
                    fprintf(ctx->outfile, "%c", *p);
            }
        } else {
            fputc(*p, ctx->outfile);
        }
        p++;
    }
    fputc('\n', ctx->outfile);
}

/*** Handling common ***/

static RdbRes toPrintAuxField(RdbParser *p, void *userData, RdbBulk auxkey, RdbBulk auxval) {
    UNUSED(p);
    RdbxToPrint *ctx = userData;
    printAuxFmt(ctx, auxkey, auxval);
    return RDB_OK;
}

static RdbRes toPrintEndKey(RdbParser *p, void *userData) {
    RdbxToPrint *ctx = userData;

    /* Print the key now that we gather all the information */
    if (ctx->keyCtx.skip == 0)
        printKeyFmt(ctx, NULL);

    RDB_bulkCopyFree(p, ctx->keyCtx.key);
    ctx->keyCtx.key = NULL;
    return RDB_OK;
}

static RdbRes toPrintNewKey(RdbParser *p, void *userData, RdbBulk key, RdbKeyInfo *info) {
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.key = RDB_bulkClone(p, key);
    ctx->keyCtx.keyLen = RDB_bulkLen(p, key);
    ctx->keyCtx.info = *info;
    ctx->keyCtx.skip = 0;
    ctx->keyCtx.items = 0;
    return RDB_OK;
}

static RdbRes toPrintNewDb(RdbParser *p, void *userData, int db) {
    UNUSED(p);
    RdbxToPrint *ctx = userData;
    ctx->dbnum = db;
    return RDB_OK;
}

/*** Handling data ***/

static RdbRes toPrintString(RdbParser *p, void *userData, RdbBulk string) {
    UNUSED(p);
    RdbxToPrint *ctx = userData;
    /* print the key now that we gather all the information */
    printKeyFmt(ctx, string);
    ctx->keyCtx.skip = 1;
    return RDB_OK;
}

static RdbRes toPrintList(RdbParser *p, void *userData, RdbBulk item) {
    UNUSED(p, item);
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.items++;
    return RDB_OK;
}

static RdbRes toPrintSet(RdbParser *p, void *userData, RdbBulk member) {
    UNUSED(p, member);
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.items++;
    return RDB_OK;
}

static RdbRes toPrintZset(RdbParser *p, void *userData, RdbBulk member, double score) {
    UNUSED(p, member, score);
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.items++;
    return RDB_OK;
}

static RdbRes toPrintHash(RdbParser *p, void *userData, RdbBulk field,
                         RdbBulk value, int64_t expireAt)
{
    UNUSED(p, field, value, expireAt);
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.items++;
    return RDB_OK;
}

static RdbRes toPrintStreamItem(RdbParser *p, void *userData, RdbStreamID *id, RdbBulk field, RdbBulk value, int64_t itemsLeft) {
    UNUSED(p, id, field, value, itemsLeft);
    RdbxToPrint *ctx = userData;
    ctx->keyCtx.items++;
    return RDB_OK;
}

/*** API ***/

RdbxToPrint *RDBX_createHandlersToPrint(RdbParser *p,
                                        const char *auxFmt,
                                        const char *keyFmt,
                                        const char *outFilename)
{
    RdbxToPrint *ctx = initRdbToPrintCtx(p, auxFmt, keyFmt, outFilename);
    if (ctx == NULL) return NULL;

    RdbHandlersDataCallbacks dataCb = {
            NULL,
            NULL,
            toPrintNewDb,
            NULL, /*handleDbSize*/
            NULL, /*handleSlotInfo*/
            NULL, /*handleAuxField*/
            toPrintNewKey,
            toPrintEndKey,
            toPrintString,
            toPrintList,
            toPrintHash,
            toPrintSet,
            toPrintZset,
            NULL, /*handleFunction*/
            NULL, /*handleModule*/
        
            /*stream:*/
            NULL,              /*handleStreamMetadata*/
            toPrintStreamItem, /*handleStreamItem*/ 
            NULL,              /*handleStreamNewCGroup*/
            NULL,              /*handleStreamCGroupPendingEntry*/
            NULL,              /*handleStreamNewConsumer*/
            NULL,              /*handleStreamConsumerPendingEntry*/
            NULL,              /*handleStreamIdmpMeta*/
            NULL,              /*handleStreamIdmpProducer*/
            NULL,              /*handleStreamIdmpEntry*/
    };

    if (auxFmt)
        dataCb.handleAuxField = toPrintAuxField;

    RDB_createHandlersData(p, &dataCb, ctx, deleteRdbToPrintCtx);

    return ctx;
}
