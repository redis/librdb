#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "readerResp.h"

#ifndef UNUSED
#define UNUSED(...) unused( (void *) NULL, ##__VA_ARGS__);
inline void unused(void *dummy, ...) { (void)(dummy);}
#endif

typedef enum RespReplyType {
    RESP_REPLY_INIT=0,
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

typedef struct RespReplyBuff {
    const char *buff;
    int len;
    int at;
} RespReplyBuff;

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

    while (buffInfo->at < buffInfo->len) {
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
                return RESP_REPLY_OK;

        }
    }
    return RESP_REPLY_PARTIAL;
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

static RespRes readRespReplyBulk(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {
    UNUSED(buffInfo);

    /* Currently there are no commands, which sent by respToTcpLoader.c, that will cause to
     * get back bulk replies. Might change in the future */
    snprintf(ctx->errorMsg,sizeof(ctx->errorMsg),"Unexpected bulk reply");
    return RESP_REPLY_ERR;
}

static RespRes readRespReplyAggregate(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {
    UNUSED(buffInfo);

    /* Currently there are no commands, which sent by respToTcpLoader.c, that will cause to
     * get back aggregated replies. Might change in the future */
    snprintf(ctx->errorMsg,sizeof(ctx->errorMsg),"Unexpected aggregate reply");
    return RESP_REPLY_ERR;
}

static RespRes readRespReply(RespReaderCtx *ctx, RespReplyBuff *buffInfo) {

    /* check if we need to read type */
    if (ctx->type == RESP_REPLY_INIT) {

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
            return readRespReplyAggregate(ctx, buffInfo);
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
        ctx->type = RESP_REPLY_INIT;
    }

    return res;
}
