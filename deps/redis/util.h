#ifndef LIBRDB_UTIL_H
#define LIBRDB_UTIL_H

#include <stdint.h>
#include "librdb-hidden-api.h"

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/* Bytes needed for long -> str + '\0' */
#define LONG_STR_SIZE      21

/* The maximum number of characters needed to for d2string/fpconv_dtoa call.
 * Since it uses %g and not %f, some 40 chars should be enough. */
#define MAX_D2STRING_CHARS 128

int string2ll(const char *s, size_t slen, long long *value);
_LIBRDB_HIDDEN_API int ll2string(char *s, size_t len, long long value);
int ull2string(char *s, size_t len, unsigned long long value);
int lpStringToInt64(const char *s, unsigned long slen, int64_t *value);
unsigned int getEnvVar(const char* varName, unsigned int defaultVal);

/* This is the exact function that is used in redis zset implementation for
 * double <-> string conversions. Using some other function may result in
 * incompatibilities as you can also convert double to string that results in
 * loss of precision, or it might not represent inf, -inf or nan values
 * similar to this function output. */
_LIBRDB_HIDDEN_API int d2string(char *buf, size_t len, double value);

#endif /*LIBRDB_UTIL_H*/
