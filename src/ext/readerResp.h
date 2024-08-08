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

/* cb to report on RESP error. Returns 1 to propagate. 0 to mask. */
typedef int (*OnRespErrorCb) (void *callerCtx, char *msg);

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

    /* On RESP error callback */
    void *errCbCtx;
    OnRespErrorCb errCb;

} RespReaderCtx;

void readRespInit(RespReaderCtx *ctx);

/* Can register cb to decide whether to ignore given error or propagate it */
void setErrorCb(RespReaderCtx *respReaderCtx, void *errorCbCtx, OnRespErrorCb cb);

RespRes readRespReplies(RespReaderCtx *ctx, const char *buff, int buffLen);
