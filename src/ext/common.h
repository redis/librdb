#ifndef RDBX_COMMON_H
#define RDBX_COMMON_H

#include <stdio.h>
#include <stdlib.h>

/* Extension lib must rely only on API (and not core parser headers) */
#include "../../api/librdb-api.h"
#include "../../api/librdb-ext-api.h"

#define UNUSED(...) unused( (void *) NULL, ##__VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

typedef union CallbacksUnion {
    struct { HANDLERS_COMMON_CALLBACKS } common;
    RdbHandlersRawCallbacks rawCb;
    RdbHandlersStructCallbacks structCb;
    RdbHandlersDataCallbacks dataCb;
} CallbacksUnion;

#endif /*define RDBX_COMMON_H*/
