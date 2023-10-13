#ifndef CRC64_H
#define CRC64_H

#include <stdint.h>
#include "librdb-hidden-api.h"

_LIBRDB_HIDDEN_API void crc64_init(void);
_LIBRDB_HIDDEN_API uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l);

#ifdef REDIS_TEST
int crc64Test(int argc, char *argv[], int flags);
#endif

#endif
