#ifndef LIBRDB_UTIL_H
#define LIBRDB_UTIL_H

#include <stdint.h>

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/* Bytes needed for long -> str + '\0' */
#define LONG_STR_SIZE      21

int ll2string(char *s, size_t len, long long value);
int ull2string(char *s, size_t len, unsigned long long value);
int lpStringToInt64(const char *s, unsigned long slen, int64_t *value);
unsigned int getEnvVar(const char* varName, unsigned int defaultVal);


/* long double to string conversion options */
typedef enum {
    LD_STR_AUTO,     /* %.17Lg */
    LD_STR_HUMAN,    /* %.17Lf + Trimming of trailing zeros */
    LD_STR_HEX       /* %La */
} ld2string_mode;

double zzlStrtod(unsigned char *vstr, unsigned int vlen);
int d2string(char *buf, size_t len, double value);

#endif /*LIBRDB_UTIL_H*/
