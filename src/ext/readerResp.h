#include <stdio.h>

#define MAX_RESP_REPLY_ERR_MSG 256

typedef enum RespReplyRes {
    RESP_REPLY_OK=0,
    RESP_REPLY_PARTIAL,
    RESP_REPLY_ERR,
} RespRes;

typedef struct RespReplyBuff {
    const char *buff;
    int len;
    int at;
} RespReplyBuff;

typedef struct {

/* PUBLIC: read-only */
    size_t countReplies;
    char errorMsg[MAX_RESP_REPLY_ERR_MSG+1];
    int errorMsgLen;

/* PRIVATE: */
    int type;
    int typeState;
    int typeArrayState;

    /* private bulk response state */
    unsigned int bulkLen;
    unsigned int bulkAt;

    /* private bulk-array response state */
    long long numBulksArray;

} RespReaderCtx;

void readRespInit(RespReaderCtx *ctx);

RespRes readRespReplies(RespReaderCtx *ctx, const char *buff, int buffLen);
