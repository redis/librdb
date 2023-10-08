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

/*** IOVEC manipulation ***/
#define IOV_CONST(iov, str)       iov_plain(iov, str, sizeof(str)-1)
#define IOV_STRING(iov, str, len) iov_plain(iov, str, len)
#define IOV_VALUE(iov, val, ar)   iov_value(iov, val, ar, sizeof(ar))
#define IOV_LEN_AND_VALUE(iov, val, ar1, ar2) \
   do {\
        int l = IOV_VALUE((iov)+1, val, ar2); \
        IOV_VALUE( (iov), l, ar1); \
   } while (0);

int iov_value(struct iovec *iov, long long count, char *buf, int bufsize);
inline void iov_plain(struct iovec *iov, const char *s, size_t l) {
    iov->iov_base = (void *) s;
    iov->iov_len = l;
}

#endif /*define RDBX_COMMON_H*/
