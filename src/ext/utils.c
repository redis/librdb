#include <ctype.h>
#include <stdio.h>
#include "utils.h"

/* printHexDump() Generates a formatted hexadecimal and ASCII representation of binary
 * data. Given a memory address and its length, it produces a human-readable obuf,
 * displaying byte offsets in hexadecimal and replacing non-printable characters with
 * dots ('.').
 *
 * Returns how many bytes written to obuf buffer. -1 Otherwise.
 *
 * Output example for input: "A123456789B123456789C123456789D123456789"
 *    000000  41 31 32 33 34 35 36 37    38 39 42 31 32 33 34 35  A1234567  89B12345
 *    000010  36 37 38 39 43 31 32 33    34 35 36 37 38 39 44 31  6789C123  456789D1
 *    000020  32 33 34 35 36 37 38 39                             23456789
 */
int printHexDump(const char *input, size_t len, char *obuf, int obuflen) {
    size_t i;
    int iout=0, j, llen = 16; /* line len */
    unsigned char buff[llen + 10];

    if (input == NULL || len <= 0 || obuf == NULL || obuflen < 200 || obuflen > 0xFFFFFF)
        return -1;

    for (i = 0, j = 0; (i < len) && (iout + 100 < obuflen) ; i++) {
        if ((i % llen) == 0) {
            if (i > 0) {
                buff[j] = '\0';
                iout += snprintf(obuf + iout, obuflen - iout, "  %s\n", buff);
            }
            iout += snprintf(obuf + iout, obuflen - iout, "%06lx ", i);
            j = 0;
        }

        if (((int)i % llen) == (llen / 2)) { /* middle of the line */
            iout += snprintf(obuf + iout, obuflen - iout, "   ");
            buff[j++] = ' ';
            buff[j++] = ' ';
        }

        iout += snprintf(obuf + iout, obuflen - iout, " %02x", (unsigned char)input[i]);
        buff[j++] = (isprint(input[i])) ? input[i] : '.';
    }

    /* pad the last line */
    for (; (i % llen) != 0; i++) {
        iout += snprintf(obuf + iout, obuflen - iout, "   ");
        if (( (int)i % llen) == (llen / 2)) {
            iout += snprintf(obuf + iout, obuflen - iout, "   ");
        }
    }

    buff[j] = '\0';
    iout += snprintf(obuf + iout, obuflen - iout, "  %s\n", buff);
    if (i < len)
        iout += snprintf(obuf + iout, obuflen - iout, "...");
    return iout;
}
