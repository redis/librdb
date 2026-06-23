#include <ctype.h>
#include "extCommon.h"
#include "../../deps/redis/util.h"

void rdbxOutputPlainEscaping(FILE *out, char *p, size_t len) {
    while (len--) {
        switch (*p) {
            case '\\':
            case '"':
                fprintf(out, "\\%c", *p); break;
            case '\n': fprintf(out, "\\n"); break;
            case '\f': fprintf(out, "\\f"); break;
            case '\r': fprintf(out, "\\r"); break;
            case '\t': fprintf(out, "\\t"); break;
            case '\b': fprintf(out, "\\b"); break;
            default:
                fprintf(out, (isprint((unsigned char)*p)) ? "%c" : "\\u%04x", (unsigned char)*p);
        }
        p++;
    }
}

/* Example:: Input: length=123  return: buf="\r\n$123\r\n" */
void iov_length(struct iovec *iov, long long length, char *buf, int bufsize) {
    int len = 0;
    buf[0] = '\r';
    buf[1] = '\n';
    buf[2] = '$';
    len = ll2string(buf+3, bufsize-5, length);
    buf[len + 3] = '\r';
    buf[len + 4] = '\n';
    iov_plain(iov, buf, len+5);
}

/* For value 123 the function will return in buf: "123\r\n" */
int iov_value(struct iovec *iov, long long value, char *buf, int bufsize) {
    int len = 0;
    len = ll2string(buf, bufsize-2, value); /* -2 for: 'r' and '\n' */
    buf[len] = '\r';
    buf[len+1] = '\n';
    iov_plain(iov, buf, len+2);
    return len;
}
