#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <ctype.h>
#include "util.h"
#include "fpconv_dtoa.h"

/* Return the number of digits of 'v' when converted to string in radix 10.
 * See ll2string() for more information. */
uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

/* Convert a unsigned long long into a string. Returns the number of
 * characters needed to represent the number.
 * If the buffer is not big enough to store the string, 0 is returned.
 *
 * Based on the following article (that apparently does not provide a
 * novel approach but only publicizes an already used technique):
 *
 * https://www.facebook.com/notes/facebook-engineering/three-optimization-tips-for-c/10151361643253920 */
int ull2string(char *dst, size_t dstlen, unsigned long long value) {
    static const char digits[201] =
            "0001020304050607080910111213141516171819"
            "2021222324252627282930313233343536373839"
            "4041424344454647484950515253545556575859"
            "6061626364656667686970717273747576777879"
            "8081828384858687888990919293949596979899";

    /* Check length. */
    uint32_t length = digits10(value);
    if (length >= dstlen) return 0;

    /* Null term. */
    uint32_t next = length - 1;
    dst[next + 1] = '\0';
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits. */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }

    return length;
}

/* Convert a long long into a string. Returns the number of
 * characters needed to represent the number.
 * If the buffer is not big enough to store the string, 0 is returned. */
int ll2string(char *dst, size_t dstlen, long long svalue) {
    unsigned long long value;
    int negative = 0;

    /* The ull2string function with 64bit unsigned integers for simplicity, so
     * we convert the number here and remember if it is negative. */
    if (svalue < 0) {
        if (svalue != LLONG_MIN) {
            value = -svalue;
        } else {
            value = ((unsigned long long) LLONG_MAX)+1;
        }
        if (dstlen < 2)
            return 0;
        negative = 1;
        dst[0] = '-';
        dst++;
        dstlen--;
    } else {
        value = svalue;
    }

    /* Converts the unsigned long long value to string*/
    int length = ull2string(dst, dstlen, value);
    if (length == 0) return 0;
    return length + negative;
}

/* Convert a string into a long long. Returns REDIS_OK if the string could be
 * parsed into a (non-overflowing) long long, REDIS_ERR otherwise. The value
 * will be set to the parsed value when appropriate.
 *
 * Note that this function demands that the string strictly represents
 * a long long: no spaces or other characters before or after the string
 * representing the number are accepted, nor zeroes at the start if not
 * for the string "0" representing the zero number.
 *
 * Because of its strictness, it is safe to use this function to check if
 * you can convert a string into a long long, and obtain back the string
 * from the number without any loss in the string representation. */
int string2ll(const char *s, size_t slen, long long *value) {
    const char *p = s;
    size_t plen = 0;
    int negative = 0;
    unsigned long long v;

    if (plen == slen)
        return 1;

    /* Special case: first and only digit is 0. */
    if (slen == 1 && p[0] == '0') {
        if (value != NULL) *value = 0;
        return 1;
    }

    if (p[0] == '-') {
        negative = 1;
        p++; plen++;

        /* Abort on only a negative sign. */
        if (plen == slen)
            return 1;
    }

    /* First digit should be 1-9, otherwise the string should just be 0. */
    if (p[0] >= '1' && p[0] <= '9') {
        v = p[0]-'0';
        p++; plen++;
    } else if (p[0] == '0' && slen == 1) {
        *value = 0;
        return 0;
    } else {
        return 1;
    }

    while (plen < slen && p[0] >= '0' && p[0] <= '9') {
        if (v > (ULLONG_MAX / 10)) /* Overflow. */
            return 1;
        v *= 10;

        if (v > (ULLONG_MAX - (p[0]-'0'))) /* Overflow. */
            return 1;
        v += p[0]-'0';

        p++; plen++;
    }

    /* Return if not all bytes were used. */
    if (plen < slen)
        return 1;

    if (negative) {
        if (v > ((unsigned long long)(-(LLONG_MIN+1))+1)) /* Overflow. */
            return 1;
        if (value != NULL) *value = -v;
    } else {
        if (v > LLONG_MAX) /* Overflow. */
            return 1;
        if (value != NULL) *value = v;
    }
    return 0;
}

unsigned int getEnvVar(const char* varName, unsigned int defaultVal) {
    const char* envValueStr = getenv(varName);
    if (envValueStr == NULL) {
        return defaultVal;
    }

    errno = 0;
    char* endptr = NULL;
    unsigned long longValue = strtoul(envValueStr, &endptr, 10);
    if (errno != 0 || endptr == envValueStr || *endptr != '\0' || longValue > UINT_MAX) {
        errno = 0;
        return defaultVal;
    }

    return (unsigned int) longValue;
}

/* Convert a string into a signed 64 bit integer.
 * The function returns 1 if the string could be parsed into a (non-overflowing)
 * signed 64 bit int, 0 otherwise. The 'value' will be set to the parsed value
 * when the function returns success.
 *
 * Note that this function demands that the string strictly represents
 * a int64 value: no spaces or other characters before or after the string
 * representing the number are accepted, nor zeroes at the start if not
 * for the string "0" representing the zero number.
 *
 * Because of its strictness, it is safe to use this function to check if
 * you can convert a string into a long long, and obtain back the string
 * from the number without any loss in the string representation. *
 *
 * -----------------------------------------------------------------------------
 *
 * Credits: this function was adapted from the Redis source code, file
 * "utils.c", function string2ll(), and is copyright:
 *
 * Copyright(C) 2011, Pieter Noordhuis
 * Copyright(C) 2011, Salvatore Sanfilippo
 *
 * The function is released under the BSD 3-clause license.
 */
int lpStringToInt64(const char *s, unsigned long slen, int64_t *value) {
    const char *p = s;
    unsigned long plen = 0;
    int negative = 0;
    uint64_t v;

    /* Abort if length indicates this cannot possibly be an int */
    if (slen == 0 || slen >= LONG_STR_SIZE)
        return 0;

    /* Special case: first and only digit is 0. */
    if (slen == 1 && p[0] == '0') {
        if (value != NULL) *value = 0;
        return 1;
    }

    if (p[0] == '-') {
        negative = 1;
        p++; plen++;

        /* Abort on only a negative sign. */
        if (plen == slen)
            return 0;
    }

    /* First digit should be 1-9, otherwise the string should just be 0. */
    if (p[0] >= '1' && p[0] <= '9') {
        v = p[0]-'0';
        p++; plen++;
    } else {
        return 0;
    }

    while (plen < slen && p[0] >= '0' && p[0] <= '9') {
        if (v > (UINT64_MAX / 10)) /* Overflow. */
            return 0;
        v *= 10;

        if (v > (UINT64_MAX - (p[0]-'0'))) /* Overflow. */
            return 0;
        v += p[0]-'0';

        p++; plen++;
    }

    /* Return if not all bytes were used. */
    if (plen < slen)
        return 0;

    if (negative) {
        if (v > ((uint64_t)(-(INT64_MIN+1))+1)) /* Overflow. */
            return 0;
        if (value != NULL) *value = -v;
    } else {
        if (v > INT64_MAX) /* Overflow. */
            return 0;
        if (value != NULL) *value = v;
    }
    return 1;
}

/* Returns 1 if the double value can safely be represented in long long without
 * precision loss, in which case the corresponding long long is stored in the out variable. */
static int double2ll(double d, long long *out) {
    (void) out;
#if (DBL_MANT_DIG >= 52) && (DBL_MANT_DIG <= 63) && (LLONG_MAX == 0x7fffffffffffffffLL)
    /* Check if the float is in a safe range to be casted into a
     * long long. We are assuming that long long is 64 bit here.
     * Also we are assuming that there are no implementations around where
     * double has precision < 52 bit.
     *
     * Under this assumptions we test if a double is inside a range
     * where casting to long long is safe. Then using two castings we
     * make sure the decimal part is zero. If all this is true we can use
     * integer without precision loss.
     *
     * Note that numbers above 2^52 and below 2^63 use all the fraction bits as real part,
     * and the exponent bits are positive, which means the "decimal" part must be 0.
     * i.e. all double values in that range are representable as a long without precision loss,
     * but not all long values in that range can be represented as a double.
     * we only care about the first part here. */
    if (d < (double)(-LLONG_MAX/2) || d > (double)(LLONG_MAX/2))
        return 0;
    long long ll = d;
    if (ll == d) {
        *out = ll;
        return 1;
    }
#else
    (void) out;
    (void) d;
#endif
    return 0;
}

/* Convert a double to a string representation. Returns the number of bytes
 * required. The representation should always be parsable by strtod(3).
 * This function does not support human-friendly formatting like ld2string
 * does. It is intended mainly to be used inside t_zset.c when writing scores
 * into a listpack representing a sorted set. */
int d2string(char *buf, size_t len, double value) {
    if (isnan(value)) {
        /* Libc in some systems will format nan in a different way,
         * like nan, -nan, NAN, nan(char-sequence).
         * So we normalize it and create a single nan form in an explicit way. */
        len = snprintf(buf,len,"nan");
    } else if (isinf(value)) {
        /* Libc in odd systems (Hi Solaris!) will format infinite in a
         * different way, so better to handle it in an explicit way. */
        if (value < 0)
            len = snprintf(buf,len,"-inf");
        else
            len = snprintf(buf,len,"inf");
    } else if (value == 0) {
        /* See: http://en.wikipedia.org/wiki/Signed_zero, "Comparisons". */
        if (1.0/value < 0)
            len = snprintf(buf,len,"-0");
        else
            len = snprintf(buf,len,"0");
    } else {
        long long lvalue;
        /* Integer printing function is much faster, check if we can safely use it. */
        if (double2ll(value, &lvalue))
            len = ll2string(buf,len,lvalue);
        else {
            len = fpconv_dtoa(value, buf);
            buf[len] = '\0';
        }
    }

    return len;
}
