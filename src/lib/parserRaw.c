/* parserRaw.c - implementation of core parser (LEVEL0)
 *
 * Whereas parsing-depth of file parser.c is LEVEL1 (RDB data-structures) and LEVEL2
 * (Redis data-types), this file parses LEVEL0 of raw data. The incentive to this
 * separation is that the similarity between LEVEL1 and LEVEL2 is higher which
 * expects structured data, whereas LEVEL0 is a dump of raw data that its main purpose
 * is to use it along with RESTORE command to play it against live Redis server.
 */

#include <assert.h>
#include <string.h>
#include "../../deps/redis/lzf.h"
#include "bulkAlloc.h"
#include "parser.h"
#include "defines.h"
#include "../../deps/redis/endianconv.h"
#include "../../deps/redis/util.h"
#include "../../deps/redis/listpack.h"
#include "../../deps/redis/ziplist.h"
#include "../../deps/redis/zipmap.h"
#include "../../deps/redis/intset.h"

#define MAX_STRING_WRITE_CHUNK (1024*63)
#define DATA_SIZE_UNKNOWN_AHEAD 0

#define RAW_AGG_MAX_NUM_BULKS 96
#define RAW_AGG_BULK_INDEX_UNINIT  -1
#define RAW_AGG_FIRST_EXTERN_BUFF_LEN (1024-1) /* minus one for additional '\0' */

static inline RdbStatus cbHandleBegin(RdbParser *p, size_t size);
static inline RdbStatus cbHandleFrag(RdbParser *p, BulkInfo *binfo);
static inline RdbStatus cbHandleEnd(RdbParser *p);

/* Aggregator of bulks for raw data until read entire key */
static inline void aggReset(RdbParser *p); /* On new key or start of aux-module */
static inline void aggFlushBulks(RdbParser *p);
static inline void aggAllocFirstBulk(RdbParser *p);
static RdbStatus aggMakeRoom(RdbParser *p, size_t numBytesRq);
static RdbStatus aggUpdateWritten(RdbParser *p, size_t bytesWritten);
void printAggAraryDbg(RdbParser *p);

static int ziplistValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p);
static int listpackValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p);
static int zipmapValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p);
static int intsetValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p);
typedef int (*singleStringTypeValidateCb)(unsigned char* str, size_t size, RdbParser *p); // return 0 for error
static RdbStatus singleStringTypeHandling(RdbParser *p, singleStringTypeValidateCb validateCb, char *callerName);
void moduleTypeNameByID(char *name, uint64_t moduleid);

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

    aggReset(p);

    /* write type of 1 byte. No need to call aggMakeRoom(). First bulk is empty. */
    p->rawCtx.at[0] = p->currOpcode;

    return aggUpdateWritten(p, 1);
}

RdbStatus elementRawEndKey(RdbParser *p) {
    /*** ENTER SAFE STATE (no rdb read) ***/

    IF_NOT_OK_RETURN(cbHandleEnd(p));

    /* now call base implementation of end-key handling */
    return elementEndKey(p);
}

RdbStatus elementRawList(RdbParser *p) {
    enum RAW_LIST_STATES {
        ST_RAW_LIST_HEADER=0,             /* Retrieve number of nodes */
        ST_RAW_LIST_NEXT_NODE_CALL_STR,   /* Process next node. Call PE_RAW_STRING as sub-element */
        ST_RAW_LIST_NEXT_NODE_STR_RETURN, /* integ check of the returned string from PE_RAW_STRING */
                                          /* If more items, goto state #1, else next PE is END_KEY */
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
            IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));

        }

        updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR, 0); /* fall-thru */

        case ST_RAW_LIST_NEXT_NODE_CALL_STR:
            return subElementCall(p, PE_RAW_STRING, ST_RAW_LIST_NEXT_NODE_STR_RETURN);

        case ST_RAW_LIST_NEXT_NODE_STR_RETURN: {

            /*** ENTER SAFE STATE (no rdb read)***/

            size_t len;
            unsigned char *encodedNode;

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedNode, &len);

            if (--listCtx->numNodes == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            return updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR, 1);
        }

        default:
            RDB_reportError(p, RDB_ERR_PLAIN_LIST_INVALID_STATE,
                            "elementRawList() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementRawQuickList(RdbParser *p) {

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

            IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));

        }

            updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR, 0); /* fall-thru */

        case ST_RAW_LIST_NEXT_NODE_CALL_STR: {
            listCtx->container = QUICKLIST_NODE_CONTAINER_PACKED;

            if (listCtx->numNodes == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            if (p->currOpcode == RDB_TYPE_LIST_QUICKLIST_2) {
                int headerLen = 0;
                IF_NOT_OK_RETURN(aggMakeRoom(p, 10)); /* 9 bytes for len */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &listCtx->container,
                                           (unsigned char *) rawCtx->at, &headerLen));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));
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
                                   "elementRawQuickList(1): Quicklist integrity check failed");
                    return RDB_STATUS_ERROR;
                }
            }

            if (--listCtx->numNodes == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            return updateElementState(p, ST_RAW_LIST_NEXT_NODE_CALL_STR, 0);
        }

        default:
            RDB_reportError(p, RDB_ERR_QUICK_LIST_INVALID_STATE,
                           "elementRawQuickList() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

/* run either as element or as sub-element */
RdbStatus elementRawString(RdbParser *p) {

    enum RAW_STRING_STATES {
        ST_RAW_STRING_PASS_HEADER,
        ST_RAW_STRING_PASS_CHUNKS, /* no need to aggregate entire type. Stream it! */
        ST_RAW_STRING_PASS_AND_REPLY_CALLER, /* called on behalf another element */
    } ;

    ElementRawStringCtx *strCtx = &p->elmCtx.rawString;
    RawContext *rawCtx = &p->rawCtx;

    switch  (p->elmCtx.state) {

        case ST_RAW_STRING_PASS_HEADER: {
            int headerlen = 0;

            IF_NOT_OK_RETURN(aggMakeRoom(p, 16 * 3)); /* worse case, 1 byte type + (9 bytes for len) * 3 */

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
                            "elementRawString(): Unknown RDB string encoding type: %lu", strCtx->len);
                        return RDB_STATUS_ERROR;
                }
            }

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(cbHandleBegin(p, 1 + headerlen + strCtx->len)); /*  type + hdr + string  */

            IF_NOT_OK_RETURN(aggUpdateWritten(p, headerlen));

            if (p->callSubElm.callerElm != PE_MAX)
                return updateElementState(p, ST_RAW_STRING_PASS_AND_REPLY_CALLER, 0);
        }

            updateElementState(p, ST_RAW_STRING_PASS_CHUNKS, 0); /* fall-thru */

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
                IF_NOT_OK_RETURN(aggUpdateWritten(p, bulkLen));

                /* update context for next iteration */
                strCtx->len -= bulkLen;

                if (!(strCtx->len))   /* stop condition */
                    return nextParsingElement(p, PE_RAW_END_KEY);

                updateElementState(p, ST_RAW_STRING_PASS_CHUNKS, 0);
            }
        }

        case ST_RAW_STRING_PASS_AND_REPLY_CALLER: {
            BulkInfo *binfoEnc;
            BulkInfo binfoDec;

            /* Since String (sub)element is called on behalf another element. it loads the raw string
             * into the common aggregated buffers and optionally decompress the data via the returned value.
             * If `aggType` will only partially aggregate the data, then there is a chance that calling
             * aggUpdateWritten() will release aggregated data before it will reach back to the
             * caller element */
            assert(rawCtx->aggType == AGG_TYPE_ENTIRE_DATA);

            /* Populate ctx->bulkArray with data and ensure that flow can handle
             * wait-more-data (rollback) in the middle by assisting BULK_TYPE_REF */
            IF_NOT_OK_RETURN(aggMakeRoom(p, strCtx->len));
            IF_NOT_OK_RETURN(rdbLoad(p, strCtx->len, RQ_ALLOC_REF, rawCtx->at, &binfoEnc));
            char *encoded = rawCtx->at;

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(aggUpdateWritten(p, strCtx->len));

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
                           "elementRawString(): Unknown RDB string encoding type: %lu", strCtx->encoding);
            return RDB_STATUS_ERROR;
        }

        default: {
            RDB_reportError(p, RDB_ERR_STRING_INVALID_STATE,
                           "elementRawString() : invalid parsing element state");
            return RDB_STATUS_ERROR;
        }
    }
}

RdbStatus elementRawListZL(RdbParser *p) {
    return singleStringTypeHandling(p, ziplistValidateIntegrityCb, "elementRawListZL");
}

RdbStatus elementRawHash(RdbParser *p) {
    uint64_t expireAt;
    int numDigits;
    size_t len;
    unsigned char *unusedData;

    enum RAW_HASH_STATES {
        ST_RAW_HASH_HEADER=0,            /* Retrieve number of nodes */
        ST_RAW_HASH_READ_NEXT_EXPIRE,    /* Read hash-field expiry (if PE_RAW_HASH_META) */
        ST_RAW_HASH_READ_NEXT_FIELD_STR, /* Call sub-element to read field */
        ST_RAW_HASH_READ_NEXT_VALUE_STR, /* Returned from sub-element. Done reading field.
                                          * Call sub-element to read value */
        ST_RAW_HASH_DONE_READ_VALUE_STR  /* Return from sub-element. Done reading value */
    } ;

    ElementRawHashCtx *hashCtx = &p->elmCtx.rawHash;
    RawContext *rawCtx = &p->rawCtx;

    switch (p->elmCtx.state) {

        case ST_RAW_HASH_HEADER:
            numDigits = 0;
            aggMakeRoom(p, 10); /* worse case 9 bytes for len */

            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &hashCtx->numFields,
                                        (unsigned char *) rawCtx->at, &numDigits));

            /*** ENTER SAFE STATE ***/

            hashCtx->visitField = 0;

            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
            IF_NOT_OK_RETURN(aggUpdateWritten(p, numDigits));

            if (hashCtx->numFields == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* empty-key */

            updateElementState(p, ST_RAW_HASH_READ_NEXT_EXPIRE, 0); /* fall-thru */

        case ST_RAW_HASH_READ_NEXT_EXPIRE:
            if (p->parsingElement == PE_RAW_HASH_META) {
                numDigits = 0;
                aggMakeRoom(p, 32);
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &expireAt,
                                            (unsigned char *) rawCtx->at,
                                            &numDigits));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(aggUpdateWritten(p, numDigits));
            }
            updateElementState(p, ST_RAW_HASH_READ_NEXT_FIELD_STR, 0); /* fall-thru */

        case ST_RAW_HASH_READ_NEXT_FIELD_STR:
            /*** ENTER SAFE STATE (no rdb read)***/
            return subElementCall(p, PE_RAW_STRING, ST_RAW_HASH_READ_NEXT_VALUE_STR);

        case ST_RAW_HASH_READ_NEXT_VALUE_STR:
            /*** ENTER SAFE STATE (no rdb read)***/
            /* returned from sub-element. Done reading field. */
            subElementCallEnd(p, (char **) &unusedData, &len);
            return subElementCall(p, PE_RAW_STRING, ST_RAW_HASH_DONE_READ_VALUE_STR);

        case ST_RAW_HASH_DONE_READ_VALUE_STR:
            /*** ENTER SAFE STATE (no rdb read)***/
            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &unusedData, &len);

            if (++hashCtx->visitField == hashCtx->numFields)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            /* More fields to read. Distinct between meta and plain hash */
            if (p->parsingElement == PE_RAW_HASH_META)
                return updateElementState(p, ST_RAW_HASH_READ_NEXT_EXPIRE, 0);
            else
                return updateElementState(p, ST_RAW_HASH_READ_NEXT_FIELD_STR, 0);

        default:
            RDB_reportError(p, RDB_ERR_PLAIN_HASH_INVALID_STATE,
                            "elementRawHash() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementRawHashZL(RdbParser *p) {
    return singleStringTypeHandling(p, ziplistValidateIntegrityCb, "elementRawHashZL");
}

RdbStatus elementRawHashLP(RdbParser *p) {
    return singleStringTypeHandling(p, listpackValidateIntegrityCb, "elementRawHashLP");
}

RdbStatus elementRawHashZM(RdbParser *p) {
    return singleStringTypeHandling(p, zipmapValidateIntegrityCb, "elementRawHashZM");
}

RdbStatus elementRawSetIS(RdbParser *p) {
    return singleStringTypeHandling(p, intsetValidateIntegrityCb, "elementRawSetIS");
}

RdbStatus elementRawSetLP(RdbParser *p) {
    return singleStringTypeHandling(p, listpackValidateIntegrityCb, "elementRawSetLP");
}

RdbStatus elementRawSet(RdbParser *p) {
    enum RAW_SET_STATES {
        ST_RAW_SET_HEADER=0,             /* Retrieve number of items */
        ST_RAW_SET_NEXT_ITEM_CALL_STR,   /* Process next item. Call PE_RAW_STRING as sub-element */
        ST_RAW_SET_NEXT_ITEM_STR_RETURN, /* integ check of the returned string from PE_RAW_STRING */
        /* If more items, goto state #1, else next PE is END_KEY */
    } ;

    ElementRawSetCtx *setCtx = &p->elmCtx.rawSet;
    RawContext *rawCtx = &p->rawCtx;

    switch (p->elmCtx.state) {

        case ST_RAW_SET_HEADER: {
            int headerLen = 0;

            aggMakeRoom(p, 10); /* worse case 9 bytes for len */

            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &setCtx->numItems,
                                        (unsigned char *) rawCtx->at, &headerLen));

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
            IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));
        }
        updateElementState(p, ST_RAW_SET_NEXT_ITEM_CALL_STR, 0); /* fall-thru */

        case ST_RAW_SET_NEXT_ITEM_CALL_STR:
            return subElementCall(p, PE_RAW_STRING, ST_RAW_SET_NEXT_ITEM_STR_RETURN);

        case ST_RAW_SET_NEXT_ITEM_STR_RETURN: {
            /*** ENTER SAFE STATE (no rdb read)***/

            size_t len;
            unsigned char *encodedItem;

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedItem, &len);

            if (--setCtx->numItems == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            return updateElementState(p, ST_RAW_SET_NEXT_ITEM_CALL_STR, 1);
        }

        default:
            RDB_reportError(p, RDB_ERR_PLAIN_SET_INVALID_STATE,
                            "elementRawSet() : invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementRawZsetLP(RdbParser *p) {
    return singleStringTypeHandling(p, listpackValidateIntegrityCb, "elementRawZsetLP");
}

RdbStatus elementRawZsetZL(RdbParser *p) {
    return singleStringTypeHandling(p, ziplistValidateIntegrityCb, "elementRawZsetZL");
}

RdbStatus elementRawZset(RdbParser *p) {
    enum RAW_ZSET_STATES {
        ST_RAW_ZSET_HEADER=0,    /* Retrieve number of members */
        ST_RAW_ZSET_READ_MEMBER, /* Read next member string */
        ST_RAW_ZSET_READ_SCORE,  /* Read score of the member */
    };

    ElementRawZsetCtx *zsetCtx = &p->elmCtx.rawZset;
    RawContext *rawCtx = &p->rawCtx;

    switch (p->elmCtx.state) {

        case ST_RAW_ZSET_HEADER: {
            int headerLen = 0;

            aggMakeRoom(p, 10); /* worse case 9 bytes for len */

            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &zsetCtx->numItems,
                                        (unsigned char *) rawCtx->at, &headerLen));

            /*** ENTER SAFE STATE ***/

            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
            IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));
        }
            updateElementState(p, ST_RAW_ZSET_READ_MEMBER, 0); /* fall-thru */

        case ST_RAW_ZSET_READ_MEMBER:
            return subElementCall(p, PE_RAW_STRING, ST_RAW_ZSET_READ_SCORE);

        case ST_RAW_ZSET_READ_SCORE: {
            size_t len;
            unsigned char *encodedItem;

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedItem, &len);

            /* For RDB_TYPE_ZSET, worst case < 255 */
            IF_NOT_OK_RETURN(aggMakeRoom(p, 255));

            if (p->currOpcode == RDB_TYPE_ZSET_2) {
                IF_NOT_OK_RETURN(rdbLoadBinaryDoubleValue(p, (double *) rawCtx->at));
                IF_NOT_OK_RETURN(aggUpdateWritten(p, sizeof(double)));
            } else {
                int written;
                IF_NOT_OK_RETURN(rdbLoadDoubleValueToBuff(p, rawCtx->at, &written));
                IF_NOT_OK_RETURN(aggUpdateWritten(p, written));
            }

            /*** ENTER SAFE STATE ***/


            if (--zsetCtx->numItems == 0)
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */

            return updateElementState(p, ST_RAW_ZSET_READ_MEMBER, 0);
        }
        default:
            RDB_reportError(p, RDB_ERR_PLAIN_ZSET_INVALID_STATE,
                            "elementRawZset(): invalid parsing element state: %d", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
}

RdbStatus elementRawModule(RdbParser *p) {

    typedef enum RAW_MODULE_STATES {
        /* Start handling module or module-aux */
        ST_START=0,
        /* Following enums are aligned to module-opcodes */
        ST_OPCODE_SINT=RDB_MODULE_OPCODE_SINT,
        ST_OPCODE_UINT=RDB_MODULE_OPCODE_UINT,
        ST_OPCODE_FLOAT=RDB_MODULE_OPCODE_FLOAT,
        ST_OPCODE_DOUBLE=RDB_MODULE_OPCODE_DOUBLE,
        ST_OPCODE_STRING_CALL_STR=RDB_MODULE_OPCODE_STRING,

        ST_OPCODE_STRING_STR_RETURN, /* return from sub-element string parsing */
        ST_NEXT_OPCODE,
        ST_AUX_START,
    } RAW_MODULE_STATES;

    RawContext *rawCtx = &p->rawCtx;

    while (1) {
        switch (p->elmCtx.state) {

            case ST_START: {
                int len = 0;

                if (p->currOpcode == RDB_TYPE_MODULE_2) {
                    uint64_t moduleid;
                    aggMakeRoom(p, 32);
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &moduleid, (unsigned char *) rawCtx->at, &len));
                    /*** ENTER SAFE STATE ***/
                    IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
                    IF_NOT_OK_RETURN(aggUpdateWritten(p, len));
                    updateElementState(p, ST_NEXT_OPCODE, 0);
                    break;
                } else {
                    assert(p->currOpcode == RDB_OPCODE_MODULE_AUX);

                    /* Init Aggregator of bulks here since no new-key precedes module aux */
                    aggReset(p);
                    updateElementState(p, ST_AUX_START, 0);
                }
            } /* fall-thru - only for of RDB_TYPE_MODULE_AUX */

            case ST_AUX_START: {
                int len = 0;
                ElementRawModuleAux *ma = &p->elmCtx.rawModAux;
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &ma->moduleid, NULL, &len));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &ma->when_opcode, NULL, NULL));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &ma->when, NULL, NULL));
                if (unlikely(ma->when_opcode != RDB_MODULE_OPCODE_UINT)) {
                    RDB_reportError(p, RDB_ERR_MODULE_INVALID_WHEN_OPCODE,
                                    "elementRawModule() : Invalid when opcode: %ld.", ma->when_opcode);
                    return RDB_STATUS_ERROR;
                }
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
                IF_NOT_OK_RETURN(aggUpdateWritten(p, len));
                updateElementState(p, ST_NEXT_OPCODE, 0);
                break;
            }

            case ST_OPCODE_SINT:
            case ST_OPCODE_UINT: {
                uint64_t val = 0;
                int len = 0;

                IF_NOT_OK_RETURN(aggMakeRoom(p, 32));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &val, (unsigned char *) rawCtx->at, &len));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(aggUpdateWritten(p, len));
                updateElementState(p, ST_NEXT_OPCODE, 0);
                break;
            }

            case ST_OPCODE_FLOAT: {
                IF_NOT_OK_RETURN(aggMakeRoom(p, sizeof(float)));
                IF_NOT_OK_RETURN(rdbLoadFloatValue(p, (float *) rawCtx->at));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(aggUpdateWritten(p, sizeof(float)));
                updateElementState(p, ST_NEXT_OPCODE, 0);
                break;
            }

            case ST_OPCODE_DOUBLE: {
                IF_NOT_OK_RETURN(aggMakeRoom(p, sizeof(double)));
                IF_NOT_OK_RETURN(rdbLoadBinaryDoubleValue(p, (double *) rawCtx->at));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(aggUpdateWritten(p, sizeof(double)));
                updateElementState(p, ST_NEXT_OPCODE, 0);
                break;
            }

            case ST_OPCODE_STRING_CALL_STR: {
                /* call raw string as subelement */
                return subElementCall(p, PE_RAW_STRING, ST_OPCODE_STRING_STR_RETURN);
            }

            case ST_OPCODE_STRING_STR_RETURN: {
                /*** ENTER SAFE STATE (no rdb read)***/
                size_t len;
                char *dataRet;
                subElementCallEnd(p, &dataRet, &len);
                updateElementState(p, ST_NEXT_OPCODE, 1);
                break;
            }

            case ST_NEXT_OPCODE: {
                int len = 0;
                uint64_t opcode = 0;

                IF_NOT_OK_RETURN(aggMakeRoom(p, 32));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &opcode, (unsigned char *) rawCtx->at, &len));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(aggUpdateWritten(p, len));

                if ((int) opcode != RDB_MODULE_OPCODE_EOF) {
                    /* Valid cast. Took care to align opcode with module states */
                    updateElementState(p, (RAW_MODULE_STATES) opcode, 0);
                    break;
                }

                /* EOF module/module-aux object */
                if (p->currOpcode == RDB_OPCODE_MODULE_AUX) {
                    /* module-aux is not stored as a key, thus indicate to end restore
                     * command here and transition the parser to next rdb type */
                    IF_NOT_OK_RETURN(cbHandleEnd(p));
                    return nextParsingElement(p, PE_NEXT_RDB_TYPE);
                } else {
                    return nextParsingElement(p, PE_RAW_END_KEY);
                }
            }

            default:
                /* if reached here, most probably because read invalid opcode from RDB */
                RDB_reportError(p, RDB_ERR_MODULE_INVALID_STATE,
                    "elementRawModule() : Invalid parsing element state: %d.", p->elmCtx.state);
                return RDB_STATUS_ERROR;
        }
    }
}

RdbStatus elementRawStreamLP(RdbParser *p) {

    enum RAW_STREAM_STATES {               /* STATES FLOW: (Indentation represent conceptual nested loop among states) */
        ST_READ_NUM_LP=0,                  /* Read number of LP (lpLeft) to load                                       */
        ST_LOAD_NEXT_LP_IS_MORE,           /* While more LP to load                                                    */
        ST_LOAD_NEXT_LP_STR1_RETURN,       /*   Complete loading node-key of next LP                                   */
        ST_LOAD_NEXT_LP_STR2_RETURN,       /*   Complete loading next LP                                               */
        ST_LOAD_METADATA,                  /* Load Stream metadata                                                     */
        ST_LOAD_NEXT_CG_IS_MORE,           /* While more CG (Consumer groups) to load                                  */
        ST_LOAD_NEXT_CG_STR_RETURN,        /*   Complete loading CG name                                               */
        ST_LOAD_GLOBAL_PEL,                /*   Load CG's global PEL (Pending Entries List)                            */
        ST_LOAD_NUM_CONSUMERS,             /*   Load number of consumers of current CG                                 */
        ST_LOAD_NEXT_CONSUMER,             /*     Load next consumer                                                   */
        ST_LOAD_NEXT_CONSUMER_STR_RETURN,  /*     Complete loading consumer name. Load consumer PEL.                   */
    } ;

    ElementRawStreamCtx *streamCtx = &p->elmCtx.rawStream;
    RawContext *rawCtx = &p->rawCtx;

    switch (p->elmCtx.state) {

        case ST_READ_NUM_LP: {
                int headerLen = 0;
                aggMakeRoom(p, 10); /* worse case 9 bytes for written */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &streamCtx->lpLeft,
                                            (unsigned char *) rawCtx->at, &headerLen));
                /*** ENTER SAFE STATE ***/
                IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));
                IF_NOT_OK_RETURN(aggUpdateWritten(p, headerLen));
            }
            updateElementState(p, ST_LOAD_NEXT_LP_IS_MORE, 0); /* fall-thru */

        case ST_LOAD_NEXT_LP_IS_MORE:
            /*** ENTER SAFE STATE ***/
            if (unlikely(!(streamCtx->lpLeft))) {
                /* if no more listpacks to load, jump to load stream metadata */
                return updateElementState(p, ST_LOAD_METADATA, 1);
            }
            streamCtx->lpLeft--;
            /* call raw string as sub-element to read nodekey */
            return subElementCall(p, PE_RAW_STRING, ST_LOAD_NEXT_LP_STR1_RETURN);

        case ST_LOAD_NEXT_LP_STR1_RETURN: {
                size_t nodekeySize;
                unsigned char *nodekeyUnused;
                subElementCallEnd(p, (char **) &nodekeyUnused, &nodekeySize);
                /* call raw string as sub-element to read listpack */
                return subElementCall(p, PE_RAW_STRING, ST_LOAD_NEXT_LP_STR2_RETURN);
            }

        case ST_LOAD_NEXT_LP_STR2_RETURN: {
                size_t lpSize;
                unsigned char *lpUnused;
                /*** ENTER SAFE STATE (no rdb read)***/
                subElementCallEnd(p, (char **) &lpUnused, &lpSize);
                if (!lpValidateIntegrity(lpUnused, lpSize, p->deepIntegCheck, NULL, 0)) {
                    RDB_reportError(p, RDB_ERR_STREAM_LP_INTEG_CHECK,
                                    "elementRawStreamLP(): LISTPACK integ check failed");
                    return RDB_STATUS_ERROR;
                }
            }
            return updateElementState(p, ST_LOAD_NEXT_LP_IS_MORE, 1);

        case ST_LOAD_METADATA: {
                uint64_t dummyVal;

                aggMakeRoom(p, LONG_STR_SIZE * 9);

                /* Load total number of items inside the stream. */
                int written = 0;
                IF_NOT_OK_RETURN( rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written),
                                             &written)); /* meta->length */

                /* Load the last entry ID. */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));

                if (p->currOpcode >= RDB_TYPE_STREAM_LISTPACKS_2) {
                    /* Load the first entry ID. */
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));

                    /* Load the maximal deleted entry ID. */
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));

                    /* Load entries added */
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                }

                /* Load total number of items inside the stream */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &streamCtx->cgroupsLeft,
                                            (unsigned char *) (rawCtx->at + written), &written));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWritten(p, written));
            }
            updateElementState(p, ST_LOAD_NEXT_CG_IS_MORE, 0); /* fall-thru */

        case ST_LOAD_NEXT_CG_IS_MORE:
            /*** ENTER SAFE STATE (no rdb read)***/
            if (unlikely(!(streamCtx->cgroupsLeft))) {
                /* if no more consumer-groups to load, then reached end of key */
                return nextParsingElement(p, PE_RAW_END_KEY); /* done */
            }
            streamCtx->cgroupsLeft--;
            /* call raw string as sub-element to read consumer-group name */
            return subElementCall(p, PE_RAW_STRING, ST_LOAD_NEXT_CG_STR_RETURN);

        case ST_LOAD_NEXT_CG_STR_RETURN: {
                int written = 0;
                size_t cgNameLen;
                uint64_t dummyVal;
                unsigned char *cgName;

                /* return from sub-element string parsing */
                subElementCallEnd(p, (char **) &cgName, &cgNameLen);
                aggMakeRoom(p, LONG_STR_SIZE * 4);

                /* read consumer-group lastid */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                /* Load group offset. */
                if (p->currOpcode >= RDB_TYPE_STREAM_LISTPACKS_2) {
                    IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + written), &written));
                }
                IF_NOT_OK_RETURN(
                        rdbLoadLen(p, NULL, &streamCtx->globPelLeft, (unsigned char *) (rawCtx->at + written), &written));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWritten(p, written));

                if (!(streamCtx->globPelLeft))
                    return updateElementState(p, ST_LOAD_NUM_CONSUMERS, 0);
            }

            updateElementState(p, ST_LOAD_GLOBAL_PEL, 0); /* fall-thru */

        case ST_LOAD_GLOBAL_PEL:
            while (streamCtx->globPelLeft) {
                uint64_t dummyVal;
                BulkInfo *binfo;
                int pelLen = 0;
                IF_NOT_OK_RETURN(aggMakeRoom(p, LONG_STR_SIZE * 2 + sizeof(RdbStreamID)));
                /* load streamid */
                IF_NOT_OK_RETURN(rdbLoad(p, sizeof(RdbStreamID), RQ_ALLOC_REF, rawCtx->at, &binfo));
                pelLen += sizeof(RdbStreamID);
                /* load millisec */
                IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC_REF, rawCtx->at + pelLen, &binfo));
                pelLen += 8;
                /* load delivery count */
                IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &dummyVal, (unsigned char *) (rawCtx->at + pelLen), &pelLen));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWritten(p, pelLen));

                streamCtx->globPelLeft--;
                updateElementState(p, ST_LOAD_GLOBAL_PEL, 0);
            }
            updateElementState(p, ST_LOAD_NUM_CONSUMERS, 0); /* fall-thru */

        case ST_LOAD_NUM_CONSUMERS: {
                int written = 0;
                IF_NOT_OK_RETURN(
                        rdbLoadLen(p, NULL, &streamCtx->consumersLeft, (unsigned char *) rawCtx->at, &written));

                /*** ENTER SAFE STATE ***/

                IF_NOT_OK_RETURN(aggUpdateWritten(p, written)); /* fall-thru */
            }
            updateElementState(p, ST_LOAD_NEXT_CONSUMER, 0); /* fall-thru */

        case ST_LOAD_NEXT_CONSUMER:
            /*** ENTER SAFE STATE (no rdb read) ***/
            if (streamCtx->consumersLeft) {
                streamCtx->consumersLeft--;
                /* call raw string as sub-element to read consumer name */
                return subElementCall(p, PE_RAW_STRING, ST_LOAD_NEXT_CONSUMER_STR_RETURN);
            }  else {
                return updateElementState(p, ST_LOAD_NEXT_CG_IS_MORE, 0);
            }

        case ST_LOAD_NEXT_CONSUMER_STR_RETURN: {
            size_t consNameLen;
            unsigned char *consName;
            uint64_t consPelSize, consLen = 0;
            BulkInfo *binfo;
            int written = 0;

            subElementCallEnd(p, (char **) &consName, &consNameLen);

            IF_NOT_OK_RETURN(aggMakeRoom(p, 8*2 + LONG_STR_SIZE));

            /* load millisec */
            IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC_REF, rawCtx->at + consLen, &binfo));
            consLen += 8;
            if (p->currOpcode >= RDB_TYPE_STREAM_LISTPACKS_3) {
                IF_NOT_OK_RETURN(rdbLoad(p, 8, RQ_ALLOC_REF, rawCtx->at + consLen, &binfo));
                consLen += 8;
            }
            /* load consumer PEL consNameLen */
            IF_NOT_OK_RETURN(rdbLoadLen(p, NULL, &consPelSize, (unsigned char *) rawCtx->at + consLen, &written));
            consLen += written;

            IF_NOT_OK_RETURN(aggMakeRoom(p, consPelSize * sizeof(RdbStreamID)));

            /* load consumer PELs */
            IF_NOT_OK_RETURN(rdbLoad(p, consPelSize * sizeof(RdbStreamID), RQ_ALLOC_REF, rawCtx->at + consLen, &binfo));
            consLen += consPelSize * sizeof(RdbStreamID);

            /*** ENTER SAFE STATE (no rdb read) ***/

            IF_NOT_OK_RETURN(aggUpdateWritten(p, consLen));

            return updateElementState(p, ST_LOAD_NEXT_CONSUMER, 0);
        }

        default:
            RDB_reportError(p, RDB_ERR_STREAM_INVALID_STATE,
                            "elementRawStreamLP() : Invalid parsing element state: %d.", p->elmCtx.state);
            return RDB_STATUS_ERROR;
    }
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
    /*** ENTER SAFE STATE (no rdb read) ***/
    ElementRawModuleAux *ma = &p->elmCtx.rawModAux;
    RawContext *ctx = &p->rawCtx;

    /* if aggregated entire type then only now parser knows to report totalSize */
    if (ctx->aggType == AGG_TYPE_ENTIRE_DATA) {

        /* if module-aux, then report special module-aux begin */
        if (p->currOpcode == RDB_OPCODE_MODULE_AUX) {
            BulkInfo *bulkName;
            IF_NOT_OK_RETURN(allocFromCache(p, 9, RQ_ALLOC_APP_BULK, NULL, &bulkName));
            moduleTypeNameByID(bulkName->ref,ma->moduleid);
            registerAppBulkForNextCb(p, bulkName);
            CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleBeginModuleAux,
                             bulkName->ref,
                             ma->moduleid&1023,
                             ma->when, ctx->totalSize);
        } else
            CALL_HANDLERS_CB(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleBegin, ctx->totalSize);
    }

    /* report entire/leftover to cb handlers */
    for(int j = 0 ; j <= ctx->curBulkIndex ; ++j)
        cbHandleFrag(p, ctx->bulkArray + j);

    aggFlushBulks(p);

    CALL_HANDLERS_CB_NO_ARGS(p, NOP, RDB_LEVEL_RAW, rdbRaw.handleEnd);
    return RDB_STATUS_OK;
}

static int ziplistValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p) {
    UNUSED(p);
    return ziplistValidateIntegrity(str, size, 1 /*p->deepIntegCheck*/, NULL, NULL);
}

static int listpackValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p) {
    UNUSED(p);
    return lpValidateIntegrity(str, size, 1 /*p->deepIntegCheck*/, NULL, NULL);
}

static int zipmapValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p) {
    UNUSED(p);
    return zipmapValidateIntegrity(str, size, 1 /*p->deepIntegCheck*/);
}

static int intsetValidateIntegrityCb(unsigned char* str, size_t size, RdbParser *p) {
    UNUSED(p);
    return intsetValidateIntegrity(str, size, 1);
}

static RdbStatus singleStringTypeHandling(RdbParser *p, singleStringTypeValidateCb validateCb, char *callerName) {

    enum RAW_SINGLE_STRING_TYPE_STATES {
        ST_RAW_SSTYPE_START=0,
        ST_RAW_SSTYPE_CALL_STR, /* Call PE_RAW_STRING as sub-element */
        ST_RAW_SSTYPE_RET_FROM_STR, /* integ check of the returned string from PE_RAW_STRING */
    };

    switch  (p->elmCtx.state) {
        case ST_RAW_SSTYPE_START:
            /* take care string won't propagate for having integrity check */
            IF_NOT_OK_RETURN(cbHandleBegin(p, DATA_SIZE_UNKNOWN_AHEAD));

            /* call raw string as subelement */
            return subElementCall(p, PE_RAW_STRING, ST_RAW_SSTYPE_RET_FROM_STR);

        case ST_RAW_SSTYPE_RET_FROM_STR: {
            size_t len;
            unsigned char *encodedNode;

            /*** ENTER SAFE STATE ***/

            /* return from sub-element string parsing */
            subElementCallEnd(p, (char **) &encodedNode, &len);

            if (!validateCb(((unsigned char*)encodedNode), len, p)) {
                RDB_reportError(p, RDB_ERR_SSTYPE_INTEG_CHECK, "%s() : integrity check failed", callerName);
                return RDB_STATUS_ERROR;
            }

            return nextParsingElement(p, PE_RAW_END_KEY); /* done */
        }

        default:
            RDB_reportError(p, RDB_ERR_SSTYPE_INVALID_STATE,
                            "%s() : invalid parsing element state: %d", callerName, p->elmCtx.state);
            return RDB_STATUS_ERROR;

    }
}

/*** raw aggregator of data ***/

static RdbStatus aggUpdateWritten(RdbParser *p, size_t bytesWritten) {
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

    if (unlikely(p->maxRawSize < ctx->totalSize + numBytesRq)) {
        RDB_reportError(p, RDB_ERR_MAX_RAW_LEN_EXCEEDED_FOR_KEY, "Maximum raw length exceeded for key (len=%lu)",
                        ctx->totalSize + numBytesRq);
        return RDB_STATUS_ERROR;
    }

    /* fill-up current buffer before attempting to allocate new one */
    if (likely(freeRoomLeft >= numBytesRq))
        return RDB_STATUS_OK;

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

static inline void aggReset(RdbParser *p) {
    aggAllocFirstBulk(p);
    p->rawCtx.aggType = AGG_TYPE_UNINIT;
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

void printAggAraryDbg(RdbParser *p) {
    RawContext *ctx = &p->rawCtx;
    for (int i = 0; i <= ctx->curBulkIndex ; ++i) {
        BulkInfo *b = ctx->bulkArray+i;
        printf("bulkArray[%d]: bulkType=%d ref=%p len=%lu written=%lu next=%p\n",
               i, b->bulkType, (void *)b->ref, b->len, b->written, (void *)b->next);
    }
}
