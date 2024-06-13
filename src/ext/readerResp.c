#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "readerResp.h"

#ifndef UNUSED
#define UNUSED(...) unused( (void *) NULL, __VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}
#endif

#define MAX_RSP_BULK_SIZE 1024*1024

/* This limit doesn't really exist in redis but at client side (hiredis) */
#define MAX_ARRAY_ELEMENTS ((1LL<<32) - 1)

typedef enum RespReplyType {
    RESP_REPLY_IDLE=0,
    RESP_REPLY_STRING,
    RESP_REPLY_ARRAY,
    RESP_REPLY_INTEGER,
    RESP_REPLY_NIL,
    RESP_REPLY_STATUS,
    RESP_REPLY_ERROR,
    RESP_REPLY_DOUBLE,
    RESP_REPLY_BOOL,
    RESP_REPLY_MAP,
    RESP_REPLY_SET,
    RESP_REPLY_ATTR,
    RESP_REPLY_PUSH,
    RESP_REPLY_BIGNUM,
    RESP_REPLY_VERB,
} RespReplyType;

/*** static functions (private) ***/

static size_t charToString(char *buf, size_t size, char byte) {
    size_t len = 0;

    switch(byte) {
        case '\\':
        case '"':
            len = snprintf(buf,size,"\"\\%c\"",byte);
            break;
        case '\n': len = snprintf(buf,size,"\"\\n\""); break;
        case '\r': len = snprintf(buf,size,"\"\\r\""); break;
        case '\t': len = snprintf(buf,size,"\"\\t\""); break;
        case '\a': len = snprintf(buf,size,"\"\\a\""); break;
        case '\b': len = snprintf(buf,size,"\"\\b\""); break;
        default:
            if (isprint(byte))
                len = snprintf(buf,size,"\"%c\"",byte);
            else
                len = snprintf(buf,size,"\"\\x%02x\"",(unsigned char)byte);
            break;
    }

    return len;
}

static void redisReaderSetErrorProtocolByte(RespReaderCtx *r, char byte) {
    char cbuf[8];
    charToString(cbuf,sizeof(cbuf),byte);
    snprintf(r->errorMsg,sizeof(r->errorMsg), "Protocol error, got %s as reply type byte", cbuf);
}

static RespRes readRespReplyLine(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {

    enum ProcessLineTypeStates {
        PROC_LINE_START=0,
        PROC_LINE_SEEK_CR=1,
        PROC_LINE_FOUND_CR, // '\r'
        PROC_LINE_FOUND_NEWLINE, // '\n'
        PROC_LINE_END
    };

    while (1) {
        if (buffInfo->at == buffInfo->len)
            return RESP_REPLY_PARTIAL;

        switch (ctx->typeState) {

            case PROC_LINE_START:
                ctx->typeState = PROC_LINE_SEEK_CR;
                /* fall-thru */
            case PROC_LINE_SEEK_CR:
                while (buffInfo->buff[(buffInfo->at)++] != '\r')
                    if (buffInfo->at == buffInfo->len)
                        return RESP_REPLY_PARTIAL;
                ctx->typeState = PROC_LINE_FOUND_CR;
                break;

            case PROC_LINE_FOUND_CR:
                if (buffInfo->buff[buffInfo->at] == '\n')
                    ctx->typeState = PROC_LINE_FOUND_NEWLINE;
                else
                    ctx->typeState = PROC_LINE_SEEK_CR;
                break;

            case PROC_LINE_FOUND_NEWLINE:
                ++(buffInfo->at);
                /* fall-thru */
            case PROC_LINE_END:
                ctx->typeState = 0;
                return RESP_REPLY_OK;
        }
    }
}

static RespRes readRespReplyError(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {
    int startAt = buffInfo->at;

    /* can return either RESP_REPLY_PARTIAL or RESP_REPLY_OK */
    RespRes res = readRespReplyLine(ctx, buffInfo);
    if (res == RESP_REPLY_ERR)
        return res;

    int bytesProcessed =  buffInfo->at - startAt;
    int errMsgFreeBytes = MAX_RESP_REPLY_ERR_MSG - ctx->errorMsgLen;
    /* trim if error msg is bigger than errorMsg[] */
    int lenToCopy = (bytesProcessed > errMsgFreeBytes) ? errMsgFreeBytes : bytesProcessed;

    for (int i = 0 ; i < lenToCopy ; ++i)
        ctx->errorMsg[ctx->errorMsgLen++] = buffInfo->buff[startAt + i];

    /* If end of error message then end string with '\0' and  indicate for an error */
    if (res == RESP_REPLY_OK) {
        /* If errorMsg ends with '\r\n' then replace with '\0'.
         * Else, it is too long and got trimmed. Replace last char with '\0' */
        if (ctx->errorMsg[ctx->errorMsgLen-1] == '\n')
            ctx->errorMsg[ctx->errorMsgLen - 2] = '\0';
        else
            ctx->errorMsg[ctx->errorMsgLen - 1] = '\0';

        res = RESP_REPLY_ERR;
    }

    return res;
}

RespRes readRespReplyBulk(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {
    char ch;
    UNUSED(buffInfo);

    /* Parsing : $<length>\r\n<data>\r\n */
    enum ProcessBulkReadStates {
        PROC_BULK_READ_INIT = 0,
        PROC_BULK_READ_LEN,    /* Read bulk length */
        PROC_BULK_READ_LEN_CR, /* Read CR */
        PROC_BULK_READ_LEN_NL, /* Read NL */
        PROC_BULK_READ,        /* Read data */
        PROC_BULK_READ_CR,     /* Read CR */
        PROC_BULK_READ_NL,     /* Read NL */
        PROC_BULK_READ_END,
    };

    while (1) {
        if (buffInfo->at == buffInfo->len)
            return RESP_REPLY_PARTIAL;

        switch (ctx->typeState) {
            case PROC_BULK_READ_INIT:
                ctx->bulkLen = 0;
                ctx->bulkAt = 0;
                ctx->typeState = PROC_BULK_READ_LEN; /* fall-thru */

            case PROC_BULK_READ_LEN:
                ch = buffInfo->buff[(buffInfo->at)];
                while ((ch >= '0') && (ch <= '9')) {
                    ctx->bulkLen = ctx->bulkLen * 10 + (ch - '0');

                    if (ctx->bulkLen > MAX_RSP_BULK_SIZE) {
                        snprintf(ctx->errorMsg, sizeof(ctx->errorMsg),
                                 "Response Bulk is bigger than MAX_RSP_BULK_SIZE (=%d)", MAX_RSP_BULK_SIZE);
                        return RESP_REPLY_ERR;
                    }

                    ch = buffInfo->buff[(++(buffInfo->at))];

                    if (buffInfo->at == buffInfo->len)
                        return RESP_REPLY_PARTIAL;
                }

                ctx->typeState = PROC_BULK_READ_LEN_CR;
                break;

            case PROC_BULK_READ_LEN_CR:
                if (buffInfo->buff[buffInfo->at++] != '\r') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg), "Invalid Bulk response. Failed to read bulk length");
                    return RESP_REPLY_ERR;
                }
                ctx->typeState = PROC_BULK_READ_LEN_NL;
                break;

            case PROC_BULK_READ_LEN_NL:
                if (buffInfo->buff[buffInfo->at++] != '\n') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg),
                             "Invalid Bulk response. Failed to read bulk length");
                    return RESP_REPLY_ERR;
                }

                /* If empty bulk */
                if (ctx->bulkLen == 0) {
                    ctx->typeState = PROC_BULK_READ_END;
                    break;
                }

                ctx->typeState = PROC_BULK_READ;
                break;

            case PROC_BULK_READ:
                while (ctx->bulkAt < ctx->bulkLen) {
                    if (buffInfo->at == buffInfo->len)
                        return RESP_REPLY_PARTIAL;

                    ++buffInfo->at; /* Not required to keep bulk. */
                    ++ctx->bulkAt;
                }

                ctx->typeState = PROC_BULK_READ_CR;
                break;

            case PROC_BULK_READ_CR:
                if (buffInfo->buff[buffInfo->at++] != '\r') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg), "Invalid Bulk response");
                    return RESP_REPLY_ERR;
                }
                ctx->typeState = PROC_BULK_READ_NL;
                break;

            case PROC_BULK_READ_NL:
                if (buffInfo->buff[buffInfo->at++] != '\n') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg), "Invalid Bulk response");
                    return RESP_REPLY_ERR;
                }

                ctx->typeState = PROC_BULK_READ_END;
                break;
        }

        if (ctx->typeState == PROC_BULK_READ_END) {
            ctx->typeState = PROC_BULK_READ_INIT;
            return RESP_REPLY_OK;
        }
    }
}

static RespRes readRespReplyBulkArray(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {
    char ch;
    RespRes res;
    UNUSED(buffInfo);

    enum ProcessBulkArrayReadStates {
        READ_INIT = 0,
        READ_NUM_BULKS,
        READ_NUM_BULKS_CR,
        READ_NUM_BULKS_NL,
        READ_NEXT_BULK_HDR,
        READ_NEXT_BULK,
        READ_NEXT_LINE, /* int, double, null, bool, bignum */
        READ_END,
    };

    while (1) {
        if (buffInfo->at == buffInfo->len)
            return RESP_REPLY_PARTIAL;

        switch (ctx->typeArrayState) {
            case READ_INIT:
                ctx->numBulksArray = 0;
                ctx->typeArrayState = READ_NUM_BULKS; /* fall-thru */

            case READ_NUM_BULKS:
                ch = buffInfo->buff[(buffInfo->at)];
                while ((ch >= '0') && (ch <= '9')) {
                    ctx->numBulksArray = ctx->numBulksArray * 10 + (ch - '0');

                    if (ctx->numBulksArray > MAX_ARRAY_ELEMENTS) {
                        snprintf(ctx->errorMsg, sizeof(ctx->errorMsg), "Multi-bulk length out of range");
                        return RESP_REPLY_ERR;
                    }
                    ch = buffInfo->buff[(++(buffInfo->at))];

                    if (buffInfo->at == buffInfo->len)
                        return RESP_REPLY_PARTIAL;
                }

                ctx->typeArrayState = READ_NUM_BULKS_CR;
                break;

            case READ_NUM_BULKS_CR:
                if (buffInfo->buff[buffInfo->at++] != '\r') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg),
                             "Invalid Multi-Bulk response. Failed to read number of bulks");
                    return RESP_REPLY_ERR;
                }
                ctx->typeArrayState = READ_NUM_BULKS_NL;
                break;

            case READ_NUM_BULKS_NL:
                if (buffInfo->buff[buffInfo->at++] != '\n') {
                    snprintf(ctx->errorMsg, sizeof(ctx->errorMsg),
                             "Invalid Bulk response. Failed to read bulk length");
                    return RESP_REPLY_ERR;
                }

                /* if empty array then jump to READ_END of array */
                if (ctx->numBulksArray == 0) {
                    ctx->typeArrayState = READ_END;
                    break;
                }

                ctx->typeArrayState = READ_NEXT_BULK_HDR;
                break;

            case READ_NEXT_BULK_HDR:
                if (buffInfo->buff[buffInfo->at] == '$') {
                    buffInfo->at++;
                    ctx->typeArrayState = READ_NEXT_BULK;
                    break;
                }

                if ((buffInfo->buff[buffInfo->at] == ':') || /*int*/
                    (buffInfo->buff[buffInfo->at] == ',') || /*double*/
                    (buffInfo->buff[buffInfo->at] == '_') || /*null*/
                    (buffInfo->buff[buffInfo->at] == '#') || /*bool*/
                    (buffInfo->buff[buffInfo->at] == '(')) /*bignum*/
                {
                    buffInfo->at++;
                    ctx->typeArrayState = READ_NEXT_LINE;
                    break;
                }

                snprintf(ctx->errorMsg, sizeof(ctx->errorMsg),
                         "Invalid Multi-Bulk response. Failed to read Bulk header.");
                return RESP_REPLY_ERR;

            case READ_NEXT_BULK:
                if ( (res = readRespReplyBulk(ctx, buffInfo)) != RESP_REPLY_OK)
                    return res;

                if (--ctx->numBulksArray) {
                    ctx->typeArrayState = READ_NEXT_BULK_HDR;
                    break;
                }
                ctx->typeArrayState = READ_END;
                break;

            case READ_NEXT_LINE:
                if ( (res = readRespReplyLine(ctx, buffInfo)) != RESP_REPLY_OK)
                    return res;

                if (--ctx->numBulksArray) {
                    ctx->typeArrayState = READ_NEXT_BULK_HDR;
                    break;
                }
                ctx->typeArrayState = READ_END;
                break;
        }

        if (ctx->typeArrayState == READ_END) {
            ctx->typeArrayState = READ_INIT;
            return RESP_REPLY_OK;
        }
    }
}

static RespRes readRespReply(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {

    /* check if we need to read type */
    if (ctx->type == RESP_REPLY_IDLE) {

        switch (buffInfo->buff[buffInfo->at]) {
            case '-':
                ctx->type = RESP_REPLY_ERROR;
                break;
            case '+':
                ctx->type = RESP_REPLY_STATUS;
                break;
            case ':':
                ctx->type = RESP_REPLY_INTEGER;
                break;
            case ',':
                ctx->type = RESP_REPLY_DOUBLE;
                break;
            case '_':
                ctx->type = RESP_REPLY_NIL;
                break;
            case '$':
                ctx->type = RESP_REPLY_STRING;
                break;
            case '*':
                ctx->type = RESP_REPLY_ARRAY;
                break;
            case '%':
                ctx->type = RESP_REPLY_MAP;
                break;
            case '~':
                ctx->type = RESP_REPLY_SET;
                break;
            case '#':
                ctx->type = RESP_REPLY_BOOL;
                break;
            case '=':
                ctx->type = RESP_REPLY_VERB;
                break;
            case '>':
                ctx->type = RESP_REPLY_PUSH;
                break;
            case '(':
                ctx->type = RESP_REPLY_BIGNUM;
                break;
            default:
                redisReaderSetErrorProtocolByte(ctx, buffInfo->buff[buffInfo->at]);
                return RESP_REPLY_ERR;
        }

        /* start read type */
        ctx->typeState = 0;
        ctx->typeArrayState = 0;
        ctx->errorMsgLen = 0;
        buffInfo->at++;
    }

    /* process typed reply */
    switch(ctx->type) {
        case RESP_REPLY_ERROR:
            return readRespReplyError(ctx, buffInfo);
        case RESP_REPLY_STATUS:
        case RESP_REPLY_INTEGER:
        case RESP_REPLY_DOUBLE:
        case RESP_REPLY_NIL:
        case RESP_REPLY_BOOL:
        case RESP_REPLY_BIGNUM:
            return readRespReplyLine(ctx, buffInfo);
        case RESP_REPLY_STRING:
        case RESP_REPLY_VERB:
            return readRespReplyBulk(ctx, buffInfo);
        case RESP_REPLY_ARRAY:
        case RESP_REPLY_MAP:
        case RESP_REPLY_SET:
        case RESP_REPLY_PUSH:
            return readRespReplyBulkArray(ctx, buffInfo);
        default:
            assert(NULL);
            return RESP_REPLY_ERR; /* Avoid warning. */
    }
}

/*** non-static functions (public) ***/

void readRespInit(RespReaderCtx *ctx) {
    ctx->type = 0;
    ctx->errorMsgLen = 0;
    ctx->countReplies = 0;
}

RespRes readRespReplies(RespReaderCtx *ctx, const char *buff, int buffLen) {
    int res=RESP_REPLY_OK;

    RespReplyBuff buffInfo = {.buff=buff, .len=buffLen, .at=0};

    while (buffInfo.at<buffLen) {

        if ((res = readRespReply(ctx, &buffInfo)) != RESP_REPLY_OK)
            break;

        ctx->countReplies++;
        ctx->type = RESP_REPLY_IDLE;
    }

    return res;
}
