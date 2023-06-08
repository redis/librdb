#ifndef LIBRDB_UTILS_H
#define LIBRDB_UTILS_H

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

unsigned int getEnvVar(const char* varName, unsigned int defaultVal);



#endif /*LIBRDB_UTILS_H*/
