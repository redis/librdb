/* roaring.h - reader of a serialized 64-bit Roaring bitmap
 *
 * RDB_TYPE_BITMAP stores its value as CRoaring's 64-bit portable serialization
 * (RoaringFormatSpec and its extension for 64-bit implementations). This is a
 * minimal reader of that format: it walks the serialized containers in
 * ascending order, validates them, and can materialize each one into the bytes
 * of the plain string bitmap it stands for. It never builds an in-memory
 * Roaring bitmap, so librdb doesn't depend on CRoaring.
 *
 * A container covers 2^16 consecutive bits, that is ROARING_CHUNK_BYTES bytes
 * of the string bitmap. Roaring value 'v' is Redis bit offset 'v': byte v>>3,
 * counting bits from the most significant one.
 */

#ifndef LIBRDB_ROARING_H
#define LIBRDB_ROARING_H

#include <stddef.h>
#include <stdint.h>

/* Bytes of string bitmap covered by a single container */
#define ROARING_CHUNK_BYTES 8192

typedef struct RoaringReader {
    const unsigned char *at, *end;   /* cursor into the serialized blob */
    uint64_t bucketsLeft;            /* 32-bit bitmaps (distinct high 32 bits) left to open */
    int64_t prevHigh32;              /* -1 before the first bucket */
    uint32_t high32;                 /* of the open bucket */
    uint32_t numContainers;          /* in the open bucket */
    uint32_t nextContainer;          /* next one to read from the open bucket */
    int32_t prevKey;                 /* high 16 bits of previous container. -1 if none */
    const unsigned char *runFlags;   /* bitset marking run containers. NULL if none */
    const unsigned char *keyCards;   /* (key, cardinality-1) pair of each container */
} RoaringReader;

void roaringReaderInit(RoaringReader *r, const unsigned char *blob, size_t len);

/* Read the next container.
 *
 * Returns 1 if a container was read, 0 if reached a clean end of the blob and
 * -1 if the blob is malformed.
 *
 * On 1, 'high48' is the container index (its first byte in the string bitmap
 * is at offset high48 * ROARING_CHUNK_BYTES), and [first, last] is the range
 * of bytes, relative to the start of the container, that spans all its set
 * bits. Both edge bytes are non-zero since a valid container is never empty.
 *
 * If 'chunk' is not NULL, it must have room for ROARING_CHUNK_BYTES bytes and
 * the bytes [first, last] of it are filled with the corresponding bytes of the
 * string bitmap. The bytes outside that range are left untouched. */
int roaringReaderNext(RoaringReader *r, unsigned char *chunk,
                      uint64_t *high48, uint32_t *first, uint32_t *last);

#endif /* LIBRDB_ROARING_H */
