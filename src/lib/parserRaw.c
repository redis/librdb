#include <assert.h>
#include <string.h>
#include "../../deps/redis/lzf.h"
/*#include "../deps/redis/crc64.h"*/
#include "bulkAlloc.h"
#include "parser.h"
#include "defines.h"
#include "../../deps/redis/endianconv.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/listpack.h"
#include "../../deps/redis/ziplist.h"

#define MAX_STRING_WRITE_CHUNK (1024*63)
#define DATA_SIZE_UNKNOWN_AHEAD 0

#define RAW_AGG_MAX_NUM_BULKS 96
#define RAW_AGG_BULK_INDEX_UNINIT  -1
#define RAW_AGG_FIRST_EXTERN_BUFF_LEN (1024-1) /* minus one for additional '\0' */

static inline RdbStatus cbHandleBegin(RdbParser *p, size_t size);
static inline RdbStatus cbHandleFrag(RdbParser *p, BulkInfo *binfo);
static inline RdbStatus cbHandleEnd(RdbParser *p);

/* Aggregator of bulks for raw data until read entire key */
static inline void aggFlushBulks(RdbParser *p);
static inline void aggAllocFirstBulk(RdbParser *p);
static RdbStatus aggMakeRoom(RdbParser *p, size_t numBytesRq);
static RdbStatus aggUpdateWrittenCbFrag(RdbParser *p, size_t bytesWritten);

/*** init & release ***/

void parserRawInit(RdbParser *p) {
    RawContext *ctx = &p->rawCtx;
    ctx->bulkArray = (BulkInfo *) RDB_alloc(p, RAW_AGG_MAX_NUM_BULKS * sizeof(struct BulkInfo));
    ctx->curBulkIndex = RAW_AGG_BULK_INDEX_UNINIT;
}

void parserRawRelease(RdbParser *p) {
    RawContext *ctx = &p->rawCtx;

    if (!(ctx->bulkArray))
        return;

    if (ctx->curBulkIndex != RAW_AGG_BULK_INDEX_UNINIT) {
        for (int i = 0; i <= ctx->curBulkIndex; ++i)
            bulkUnmanagedFree(p, ctx->bulkArray + i);
    }
    RDB_free(p, ctx->bulkArray);
}

/****************************************************************
 * Sub-Element parsing
 *
 * The parser can handle one level of nested parsing-elements (PE), whereby a PE
 * may be called by another PE and control is returned to the caller once the
 * parsing of sub-element is complete.
 *
 * Currently, this functionality is only adapted and utilized by raw string element
 * which can also run as sub-element of other data-types. It takes care to write the
 * processed string to raw-aggregator, as part of RESTORE of current command.
 *
 * In addition it returns the string decoded by allocating bulkUnmanagedAlloc()
 * (The caller won't need to release returned data yet restrictd to use it within
 * its current parsing-element state).
 ****************************************************************/

RdbStatus subElementCall(RdbParser *p, ParsingElementType next, int returnState) {

    assert(p->callSubElm.callerElm == PE_MAX); /* prev sub-element flow ended */

    /* release bulk from previous flow of subElement */
    bulkUnmanagedFree(p, &p->callSubElm.bulkResult);

    p->callSubElm.callerElm = p->parsingElement;
    p->callSubElm.stateToReturn = returnState;
    return nextParsingElement(p, next);
}

RdbStatus subElementReturn(RdbParser *p, BulkInfo *bulkResult) {
    p->callSubElm.bulkResult = *bulkResult;
    return nextParsingElementState(p, p->callSubElm.callerElm, p->callSubElm.stateToReturn);
}

void subElementCallEnd(RdbParser *p, RdbBulk *bulkResult, size_t *len) {
    *bulkResult = p->callSubElm.bulkResult.ref;
    *len = p->callSubElm.bulkResult.len;
    p->callSubElm.callerElm = PE_MAX; /* mark as done */
}

/*** Parsing Elements ***/

RdbStatus elementRawNewKey(RdbParser *p) {

    /* call base implementation of new-key handling. Read key. */
    IF_NOT_OK_RETURN(elementNewKey(p));

    /*** ENTER SAFE STATE ***/

    p->rawCtx.aggType = AGG_TYPE_UNINIT;

    aggAllocFirstBulk(p);

    /* write type of 1 byte. No need to call aggMakeRoom(). First bulk is empty. */
    p->rawCtx.at[0] = p->currOpcode;

    return aggUpdateWrittenCbFrag(p, 1);
}

RdbStatus elementRawEndKey(RdbParser *p) {
    /*** ENTER SAFE STATE (no rdb read) ***/

    RawContext *ctx = &p->rawCtx;

    /* if aggregated entire type then only now parser knows to report totalSize */
    if (ctx->aggType == AGG_TYPE_ENTIRE_DATA) {
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleBegin, ctx->totalSize);
    }

    /* report leftover to cb handlers */
    for(int j = 0 ; j <= ctx->curBulkIndex ; ++j)
        cbHandleFrag(p, ctx->bulkArray + j);

    aggFlushBulks(p);

    IF_NOT_OK_RETURN(cbHandleEnd(p));

    /* now call base implementation of end-key handling */
    return elementEndKey(p);
}

RdbStatus elementRawList(RdbParser *p) {

    enum RAW_LIST_STATES {
        ST_RAW_LIST_HEADER=0, /* Retrieve number of nodes */
        ST_RAW_LIST_NEXT_NODE_CALL_STR, /* Process next node. Call PE_RAW_STRING as sub-element */
        ST_RAW_LIST_NEXT_NODE_STR_RETURN, /* integ check of the returned string from PE_RAW_STRING */
    } ;

    ElementRawListCtx *listCtx = &p->elmCtx.rawList;
    RawContext *rawCtx = &p->rawCtx;

    switch (p->elmCtx.state) {

        case ST_RAW_LIST_HEADER: {
            int headerLen = 0;

            aggMakeRoom(p, 10); /* worse case 9 bytes for len */

            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &listCtx->numNodes,
                (unsigned char *) rawCtx->at, &headerLen));

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));

            IF_NOT_OK_RETURN(aggUpdateWrittenCbFrag(p, headerLen));

        }

            updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR); /* fall-thru */

        case ST_RAW_LIST_NEXT_NODE_CALL_STR: {
            listCtx->container = QUICKLIST_NODE_CONTAINER_PACKED;

            if (listCtx->numNodes == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2) {
                int headerLen = 0;
                aggMakeRoom(p, 10); /* 9 bytes for len */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &listCtx->container,
                                           (unsigned char *) rawCtx->at, &headerLen));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWrittenCbFrag(p, headerLen));
            }

            /* call raw string as subelement */
            return subElementCall(p, PE_RAW_STRING, ST_RAW_LIST_NEXT_NODE_STR_RETURN);
        }

        case ST_RAW_LIST_NEXT_NODE_STR_RETURN: {

            /*** ENTER SAFE STATE (no rdb read)***/

            int ret;
            size_t len;
            unsigned char *encodedNode;

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedNode, &len);

            if (listCtx->container != QUICKLIST_NODE_CONTAINER_PLAIN) {
                if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2)
                    ret = lpValidateIntegrity(encodedNode, len, p->deepIntegCheck,
                                              NULL, NULL);
                else
                    ret = ziplistValidateIntegrity(encodedNode, len, p->deepIntegCheck, NULL, NULL);

                if (!ret) {
                    RDB_reportError(p, RDB_ERR_QUICK_LIST_INTEG_CHECK,
                                   "elementRawList(1): Quicklist integrity check failed");
                    return RDB_STATUS_ERROR;
                }
            }

            if (--listCtx->numNodes == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            return updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR);
        }

        default:
            RDB_reportError(p, RDB_ERR_QUICK_LIST_INVALID_STATE,
                           "elementRawList() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

/* either element or sub-element */
RdbStatus elementRawString(RdbParser *p) {

    enum RAW_STRING_STATES {
        ST_RAW_STRING_PASS_HEADER,
        ST_RAW_STRING_PASS_CHUNKS, /* no need to aggregate entire type. Stream it! */
        ST_RAW_STRING_PASS_AND_REPLY_CALLER, /* called on behalf another flow */
    } ;

    ElementRawStringCtx *strCtx = &p->elmCtx.rawString;
    RawContext *rawCtx = &p->rawCtx;

    switch  (p->elmCtx.state) {

        case ST_RAW_STRING_PASS_HEADER: {
            int headerlen = 0;

            aggMakeRoom(p, 16 * 3); /* worse case, 1 byte type + (9 bytes for len) * 3 */

            IF_NOT_OK_RETURN(rdbLoadLen(p, &strCtx->isencoded, &strCtx->len,
                (unsigned char *) rawCtx->at + headerlen, &headerlen));

            if (strCtx->isencoded) {
                strCtx->encoding = strCtx->len;
                switch(strCtx->encoding) {
                    case RDB_ENC_INT8: strCtx->len = 1; break;
                    case RDB_ENC_INT16: strCtx->len = 2; break;
                    case RDB_ENC_INT32: strCtx->len = 4; break;
                    case RDB_ENC_LZF:
                        IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &strCtx->len,
                                                    (unsigned char *) rawCtx->at + headerlen, &headerlen));
                        IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &strCtx->uclen,
                                                    (unsigned char *) rawCtx->at + headerlen, &headerlen));
                        break;
                    default:
                        RDB_reportError(p, RDB_ERR_STRING_UNKNOWN_ENCODING_TYPE,
                            "elementRawString(): Unknown RDB string encoding type: %llu", strCtx->len);
                        return RDB_STATUS_ERROR;
                }
            }

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(cbHandleBegin(p, 1 + headerlen + strCtx->len)); /*  type + hdr + string  */

            IF_NOT_OK_RETURN(aggUpdateWrittenCbFrag(p, headerlen));

            if (p->callSubElm.callerElm != PE_MAX)
                return updateElementState(p, ST_RAW_STRING_PASS_AND_REPLY_CALLER);
        }

            updateElementState(p, ST_RAW_STRING_PASS_CHUNKS); /* fall-thru */

        case ST_RAW_STRING_PASS_CHUNKS: {

            while(1) {
                BulkInfo *binfo;

                size_t bulkLen = strCtx->len > MAX_STRING_WRITE_CHUNK ? MAX_STRING_WRITE_CHUNK : strCtx->len;

                /* Load ctx->bulkArray with data. Assist BULK_TYPE_REF to be
                 * resilient from wait-more-data (rollback) flow */


                /* Populate ctx->bulkArray with data and ensure that flow can handle
                 * wait-more-data (rollback) in the middle by assisting BULK_TYPE_REF */
                IF_NOT_OK_RETURN(aggMakeRoom(p, bulkLen));
                IF_NOT_OK_RETURN(rdbLoad(p, bulkLen, RQ_ALLOC_REF, rawCtx->at, &binfo));

                /*** ENTER SAFE STATE ***/

                /* now safe to update ctx and be ready for another iteration */
                IF_NOT_OK_RETURN(aggUpdateWrittenCbFrag(p, bulkLen));

                /* update context for next iteration */
                strCtx->len -= bulkLen;

                if (!(strCtx->len))   /* stop condition */
                    return nextParsingElement(p, PE_RAW_END_KEY);

                updateElementState(p, ST_RAW_STRING_PASS_CHUNKS);
            }
        }

        case ST_RAW_STRING_PASS_AND_REPLY_CALLER: {
            BulkInfo *binfoEnc;
            BulkInfo binfoDec;

            /* Since String (sub)element is called on behalf another element. it loads the raw string
             * into the common aggregated buffers and optionally decompress the data via the returned value.
             * If `aggType` will only partially aggregate the data, then there is a chance that calling
             * aggUpdateWrittenCbFrag() will release aggregated data before it will reach back to the
             * caller element */
            assert(rawCtx->aggType == AGG_TYPE_ENTIRE_DATA);

            /* Populate ctx->bulkArray with data and ensure that flow can handle
             * wait-more-data (rollback) in the middle by assisting BULK_TYPE_REF */
            IF_NOT_OK_RETURN(aggMakeRoom(p, strCtx->len));
            IF_NOT_OK_RETURN(rdbLoad(p, strCtx->len, RQ_ALLOC_REF, rawCtx->at, &binfoEnc));
            char *encoded = rawCtx->at;

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(aggUpdateWrittenCbFrag(p, strCtx->len));

            if (!(strCtx->isencoded)) {
                BulkInfo binfoEncRef;
                bulkUnmanagedAlloc(p, binfoEnc->len, UNMNG_RQ_ALLOC_REF, binfoEnc->ref, &binfoEncRef);
                return subElementReturn(p, &binfoEncRef /* no decoding required */);
            }

            if (strCtx->encoding <= RDB_ENC_INT32) {
                char buf[LONG_STR_SIZE];
                long val = 0;
                if (strCtx->encoding == RDB_ENC_INT8)
                    val = (int8_t) (encoded[0]);
                else if (strCtx->encoding == RDB_ENC_INT16)
                    val = (int16_t) (encoded[0] | (encoded[1] << 8));
                else if (strCtx->encoding == RDB_ENC_INT32)
                    val = (int32_t) (encoded[0] | (encoded[1] << 8) | (encoded[2] << 16) | (encoded[3] << 24));

                int strLen = ll2string(buf, sizeof(buf), val);

                bulkUnmanagedAlloc(p, strLen, UNMNG_RQ_ALLOC, NULL, &binfoDec);
                memcpy(binfoDec.ref, buf, strLen);
                return subElementReturn(p, &binfoDec);
            }

            if (strCtx->encoding == RDB_ENC_LZF) {
                bulkUnmanagedAlloc(p, strCtx->uclen, UNMNG_RQ_ALLOC, NULL, &binfoDec);

                if (lzf_decompress(binfoEnc->ref, strCtx->len, binfoDec.ref, strCtx->uclen) != strCtx->uclen) {
                    RDB_reportError(p, RDB_ERR_STRING_INVALID_LZF_COMPRESSED,
                                   "elementRawString(): Invalid LZF compressed string");
                    return RDB_STATUS_ERROR;
                }
                return subElementReturn(p, &binfoDec);
            }

            RDB_reportError(p, RDB_ERR_STRING_UNKNOWN_ENCODING_TYPE,
                           "elementRawString(): Unknown RDB string encoding type: %llu", strCtx->encoding);
            return RDB_STATUS_ERROR;
        }

        default: {
            RDB_reportError(p, RDB_ERR_STRING_INVALID_STATE,
                           "elementRawString() : invalid parsing element state");
            return RDB_STATUS_ERROR;
        }
    }
}

RdbStatus elementRawZipList(RdbParser *p) {
    enum RAW_LIST_STATES {
        ST_RAW_ZIPLIST_START=0,
        ST_RAW_ZIPLIST_CALL_STR, /* Call PE_RAW_STRING as sub-element */
        ST_RAW_ZIPLIST_RET_FROM_STR, /* integ check of the returned string from PE_RAW_STRING */
    };

    switch  (p->elmCtx.state) {
        case ST_RAW_ZIPLIST_START:
            /* take care string won't propagate for having integrity check */
            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));

            /* call raw string as subelement */
            return subElementCall(p, PE_RAW_STRING, ST_RAW_ZIPLIST_RET_FROM_STR);

        case ST_RAW_ZIPLIST_RET_FROM_STR: {
            /*** ENTER SAFE STATE (no rdb read)***/

            size_t len;
            unsigned char *encodedNode;

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedNode, &len);

            if (!ziplistValidateIntegrity(((unsigned char*)encodedNode), len, p->deepIntegCheck, NULL, NULL)) {
                RDB_reportError(p, RDB_ERR_ZIP_LIST_INTEG_CHECK, "elementRawZipList() : ziplist integrity check failed");
                return RDB_STATUS_ERROR;
            }

            return nextParsingElement(p, PE_RAW_END_KEY); /* done */
        }

        default:
            RDB_reportError(p, RDB_ERR_ZIP_LIST_INVALID_STATE,
                            "elementRawZipList() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;

    }

    UNUSED(p);
    return RDB_STATUS_OK;
}

/*** various functions ***/

static inline RdbStatus cbHandleFrag(RdbParser *p, BulkInfo *binfo) {

    if (likely(binfo->written)) {
        /* Update current buffer len to be actual usage */
        binfo->len = binfo->written;
        ((char *)binfo->ref)[binfo->written] = '\0';

        registerAppBulkForNextCb(p, binfo);
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleFrag, binfo->ref);
    }

    return RDB_STATUS_OK;
}

static inline RdbStatus cbHandleBegin(RdbParser *p, size_t size) {

    /* if aggType already initialized, then it is sub-element call. Ignore. */
    if (p->rawCtx.aggType != AGG_TYPE_UNINIT)
        return RDB_STATUS_OK;

    if (size == DATA_SIZE_UNKNOWN_AHEAD) {
        p->rawCtx.aggType = AGG_TYPE_ENTIRE_DATA;

        /* TODO: add configuration to avoid aggregation, in case app doens't need
         * to know ahead the size of payload, for example, when it only stores
         * the data to a file */
    } else {
        /* we know the total size of type. No need to aggregate it entirely */
        p->rawCtx.aggType = AGG_TYPE_PARTIALLY;
        CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleBegin, size);
    }
    return RDB_STATUS_OK;
}

static inline RdbStatus cbHandleEnd(RdbParser *p) {
    CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleEnd);
    return RDB_STATUS_OK;
}

/*** raw aggregator of data ***/

static RdbStatus aggUpdateWrittenCbFrag(RdbParser *p, size_t bytesWritten) {
    RawContext *ctx = &p->rawCtx;

    p->rawCtx.at += bytesWritten;
    p->rawCtx.totalSize += bytesWritten;
    ctx->bulkArray[ctx->curBulkIndex].written += bytesWritten;

    /* if filled-up at least first buffer, only then it worth to forward */
    if (unlikely(ctx->curBulkIndex > 0)) {
        /* If not required to agg entire type data then pass what aggregated so far */
        if (ctx->aggType == AGG_TYPE_PARTIALLY) {
            for (int i = 0 ; i <= ctx->curBulkIndex ; ++i) {
                IF_NOT_OK_RETURN(cbHandleFrag(p, ctx->bulkArray + i));
            }

            aggFlushBulks(p);
            aggAllocFirstBulk(p);
        }
    }
    return RDB_STATUS_OK;
}

static RdbStatus aggMakeRoom(RdbParser *p, size_t numBytesRq) {
    RawContext *ctx = &p->rawCtx;
    BulkInfo *currBuff = ctx->bulkArray + ctx->curBulkIndex;
    size_t freeRoomLeft = currBuff->len - currBuff->written;

    /* fill-up current buffer before attempting to allocate new one */
    if (likely(freeRoomLeft >= numBytesRq))
        return RDB_STATUS_OK;

    if (unlikely(p->maxRawLen < ctx->totalSize + numBytesRq)) {
        RDB_reportError(p, RDB_ERR_MAX_RAW_LEN_EXCEEDED_FOR_KEY, "Maximum raw length exceeded for key (len=%lu)",
                        ctx->totalSize + numBytesRq);
        return RDB_STATUS_ERROR;
    }

    /* determine next buffer size to allocate. Factor x2 up-to 1mb, x1.5 upto
     * 256mb, or x1.2 above it. With 96 entries for bulkArray, it is sufficient
     * for at least 100TB */
    size_t len = (currBuff->len > numBytesRq) ? currBuff->len : numBytesRq;
    float factor = likely(len < (1<<20)) ? 2 : (len < (1<<28)) ? 1.5 : 1.2;
    size_t nextBufSize = (size_t) len * factor;

    ++(ctx->curBulkIndex);
    ++currBuff;

    bulkUnmanagedAlloc(p, nextBufSize, UNMNG_RQ_ALLOC_APP_BULK, NULL, currBuff);
    ctx->at = ctx->bulkArray[ctx->curBulkIndex].ref;
    return RDB_STATUS_OK;
}

static inline void aggFlushBulks(RdbParser *p) {
    RawContext *ctx = &p->rawCtx;

    /* skip first static buffer */
    for (int i = 0; i <= ctx->curBulkIndex ; ++i)
        bulkUnmanagedFree(p, ctx->bulkArray + i);
}

static inline void aggAllocFirstBulk(RdbParser *p) {
    RawContext *ctx = &p->rawCtx;

    /* Allocate first bulk in bulkArray */
    if (p->mem.bulkAllocType == RDB_BULK_ALLOC_EXTERN) {
        /* If app configured explicitly to allocate RdbBulks by external allocation
         * function then it will be a waste to use "internal buffer" and then copy
         * it to "external buffer" (in order to pass RdbBulk to callbacks). Better
         * to allocate from start "external buffer". */
        bulkUnmanagedAlloc(p,
                           RAW_AGG_FIRST_EXTERN_BUFF_LEN,
                           UNMNG_RQ_ALLOC_APP_BULK,
                           NULL,
                           ctx->bulkArray);
    } else {
        /* If not configured explicitly to allocate RdbBulks by external allocation,
         * then only reference staticBulk for the first buffer. Will be bigger
         * buffer than the case that RDB_BULK_ALLOC_EXTERN is configured, because
         * the buffer is static and not really allocated each time. '-1' is because
         * the '\0' termination which is not counted.  */
        bulkUnmanagedAlloc(p,
                           RAW_AGG_FIRST_STATIC_BUFF_LEN - 1,
                           UNMNG_RQ_ALLOC_APP_BULK_REF,
                           ctx->staticBulk,
                           ctx->bulkArray);
    }

    ctx->at = ctx->bulkArray[0].ref;
    ctx->curBulkIndex = 0;
    ctx->totalSize = 0;
}