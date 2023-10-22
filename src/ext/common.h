#ifndef RDBX_COMMON_H
#define RDBX_COMMON_H

#include <stdio.h>
#include <stdlib.h>

/* Extension lib must rely only on API (and not core parser headers) */
#include "../../api/librdb-api.h"
#include "../../api/librdb-ext-api.h"

#define UNUSED(...) unused( (void *) NULL, __VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define IF_NOT_OK_RETURN(cmd) do {RdbRes s; s = cmd; if (unlikely(s!=RDB_OK)) return s;} while (0)

/*** IOVEC manipulation ***/
// INPUT: str="ABC"         OUTPUT: iov={ "ABC" , 3 }
#define IOV_CONST(iov, str)       iov_plain(iov, str, sizeof(str)-1)

// INPUT: str="ABC", len=3  OUTPUT: iov={ "ABC" , 3 }
#define IOV_STRING(iov, str, len) iov_plain(iov, str, len)

// INPUT: len=45678         OUTPUT: iov={ "\r\n$45678\r\n" , 10 }
#define IOV_LENGTH(iov, len, ar)  iov_length(iov, len, ar, sizeof(ar))

// INPUT: val=45678          OUTPUT: iov={ "45678\r\n" , 7 }
#define IOV_VALUE(iov, val, ar)   iov_value(iov, val, ar, sizeof(ar))

// INPUT: val=45678          OUTPUT: iov={{ "$5\r\n" , 4 } , { "45678\r\n" , 7 }}
#define IOV_LEN_AND_VAL(iov, val, ar1, ar2) \
   do {\
        int l = IOV_VALUE((iov)+1, val, ar2); \
        IOV_LENGTH( (iov), l, ar1); \
   } while (0);

int iov_value(struct iovec *iov, long long count, char *buf, int bufsize);

void iov_length(struct iovec *iov, long long length, char *buf, int bufsize);

static inline void iov_plain(struct iovec *iov, const char *s, size_t l) {
    iov->iov_base = (void *) s;
    iov->iov_len = l;
}

/* The api of RESP writer is rather simple as it expects a plain iovec. This
 * API is not sufficient when it comes to play the RESP against live server such
 * as the case of respToRedisLoader. In case of an error from the server it is
 * desired to report an informative message to the user of the problematic command
 * and key.
 *
 * In order to keep the RESP writer API simple, the command and key will passed
 * implicitly, hidden before iovec and the following struct reflects this layout.
 * Respectively, respToRedisLoader will have the logic to cast iovec back to iovecExt.
 */
typedef struct iovecExt {
    const char *cmd;
    const char *key;
    struct iovec iov[20];
} iovecExt;

#endif /*define RDBX_COMMON_H*/
