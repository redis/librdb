#ifndef RDBX_HANDLERS_COMMON_H
#define RDBX_HANDLERS_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include "extCommon.h"   /* librdb-api.h + librdb-ext-api.h */

/* Shared by the `print` and `stat` handlers: key-size evaluation (accumulator +
 * element callbacks + estimator) and the file/lifecycle plumbing. This module
 * depends on neither flavor. */

/* Per-key size accumulator, filled by the shared value callbacks. */
typedef struct RdbxKeyCtx {
    RdbBulkCopy   key;          /* owned clone; freed at endKey */
    unsigned int  keyLen;
    RdbKeyInfo    info;
    unsigned long items;
    uint64_t      numStrings, sumStrBytes, largest, moduleBytes, memBytes;
    int           isIntStr;
    int           skip;         /* set when the string handler already finalized */
} RdbxKeyCtx;

/* Shared fields embedded (by composition) in RdbxToPrint and RdbxToStat. */
typedef struct RdbxHandlersBase {
    RdbParser    *p;
    int           dbnum;
    FILE         *outfile;      /* stdout or an opened file */
    char         *outfileName;  /* owned copy (incl. the "<stdout>" placeholder) */
    RdbxKeyCtx    keyCtx;
} RdbxHandlersBase;

/*** lifecycle ***/

/* Opens outfile (NULL => stdout) and initializes `base`. Returns 0 on success,
 * non-0 on open failure (after reporting RDB_ERR_FAILED_OPEN_FILE). */
int  rdbxBaseInit(RdbParser *p, RdbxHandlersBase *base, const char *outFilename);

/* Frees keyCtx.key, closes outfile (unless stdout), frees outfileName. */
void rdbxBaseDestroy(RdbParser *p, RdbxHandlersBase *base);

/*** key-size accumulation helpers ***
 *
 * The print and stat handlers each register their own data callbacks; the shared
 * measurement logic lives here. A flavor's newKey calls rdbxKeyCtxReset, each
 * value callback calls the matching rdbxAccount* helper, and endKey/string call
 * rdbxComputeMemBytes / rdbxKeyCtxSetString. */

/* Clone `key` and reset the accumulator for a new key. */
void rdbxKeyCtxReset(RdbParser *p, RdbxKeyCtx *kc, RdbBulk key, RdbKeyInfo *info);

/* One element with `strings` strings of total `len` bytes (list/set/array). */
void rdbxAccountElem(RdbxKeyCtx *kc, uint64_t len, unsigned strings);

/* A field/value (or stream field/value) pair: 2 strings, both tracked. */
void rdbxAccountPair(RdbxKeyCtx *kc, uint64_t flen, uint64_t vlen);

/* A zset member of `mlen` bytes (its score counts for memory, not for largest). */
void rdbxAccountZset(RdbxKeyCtx *kc, uint64_t mlen);

/* A module value of `serializedSize` bytes. */
void rdbxAccountModule(RdbxKeyCtx *kc, uint64_t serializedSize);

/* Finalize a string value (sets isIntStr/counters) and compute its memBytes. */
void rdbxKeyCtxSetString(RdbxKeyCtx *kc, const char *s, size_t len);

/* Compute memBytes from the accumulated counters (aggregate values). */
void rdbxComputeMemBytes(RdbxKeyCtx *kc);

/*** shared reporting utilities ***/

const char *rdbxTypeName(int dataType);
const char *rdbxEncodingStr(int opcode);

#endif /* RDBX_HANDLERS_COMMON_H */
