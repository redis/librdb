#include <stdio.h>

#define MAX_RESP_REPLY_ERR_MSG 256

typedef enum RespReplyRes {
    RESP_REPLY_OK=0,
    RESP_REPLY_PARTIAL,
    RESP_REPLY_ERR,
} RespRes;

typedef struct {
/* private: */
    int type;
    int typeState;

/* public: read-only */
    size_t countReplies;
    char errorMsg[MAX_RESP_REPLY_ERR_MSG+1];
    int errorMsgLen;
} RespReaderCtx;

void readRespInit(RespReaderCtx *ctx);

RespRes readRespReplies(RespReaderCtx *ctx, const char *buff, int buffLen);
