/* roaring.c - reader of a serialized 64-bit Roaring bitmap (see roaring.h)
 *
 * Layout (all integers little-endian):
 *
 *   [uint64 number of buckets]
 *   per bucket, in strictly increasing order of high32:
 *     [uint32 high32]
 *     [32-bit Roaring bitmap, standard portable format]:
 *       cookie   - uint32. If its low 16 bits are SERIAL_COOKIE, then the high
 *                  16 bits hold (number of containers - 1) and a bitset of
 *                  (containers + 7) / 8 bytes follows, flagging which of the
 *                  containers are run containers. Otherwise it must be
 *                  SERIAL_COOKIE_NO_RUNCONTAINER, followed by uint32 number of
 *                  containers.
 *       header   - per container: [uint16 key][uint16 cardinality - 1]
 *       offsets  - per container: [uint32]. Absent if there are run containers
 *                  and less than NO_OFFSET_THRESHOLD containers. Not needed
 *                  for a sequential read.
 *       containers, one of:
 *         run    - [uint16 number of runs] then per run [uint16 start][uint16 length - 1]
 *         bitset - (cardinality > 4096) 1024 words of uint64
 *         array  - (otherwise) cardinality sorted uint16 values
 *
 * The checks mirror the ones Redis applies on load (CRoaring's
 * roaring64_bitmap_portable_deserialize_safe() followed by
 * roaring64_bitmap_internal_validate()), so a blob that is accepted here is one
 * that Redis would have accepted.
 */

#include <string.h>
#include "roaring.h"

#define SERIAL_COOKIE_NO_RUNCONTAINER 12346
#define SERIAL_COOKIE                 12347
#define NO_OFFSET_THRESHOLD           4
#define ARRAY_MAX_CARDINALITY         4096   /* DEFAULT_MAX_SIZE of CRoaring */
#define MAX_CONTAINERS_IN_BUCKET      (1 << 16)

static inline uint16_t rdU16(const unsigned char *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

static inline uint32_t rdU32(const unsigned char *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline uint64_t rdU64(const unsigned char *p) {
    return (uint64_t) rdU32(p) | ((uint64_t) rdU32(p + 4) << 32);
}

static inline size_t bytesLeft(const RoaringReader *r) {
    return (size_t) (r->end - r->at);
}

/* A serialized bitset word keeps value 'i' at bit 'i', least significant first,
 * whereas a string bitmap counts bits from the most significant one. */
static inline unsigned char reverseBits(unsigned char v) {
    v = (unsigned char) (((v & 0xf0) >> 4) | ((v & 0x0f) << 4));
    v = (unsigned char) (((v & 0xcc) >> 2) | ((v & 0x33) << 2));
    v = (unsigned char) (((v & 0xaa) >> 1) | ((v & 0x55) << 1));
    return v;
}

static inline int popcount64(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll(v);
#else
    int c = 0;
    for (; v; v &= v - 1) c++;
    return c;
#endif
}

/* Set bits [from, to] (inclusive) of a string bitmap chunk */
static void setBitRange(unsigned char *chunk, uint32_t from, uint32_t to) {
    uint32_t firstByte = from >> 3, lastByte = to >> 3;
    unsigned char headMask = (unsigned char) (0xff >> (from & 7));
    unsigned char tailMask = (unsigned char) (0xff << (7 - (to & 7)));

    if (firstByte == lastByte) {
        chunk[firstByte] |= headMask & tailMask;
        return;
    }
    chunk[firstByte] |= headMask;
    memset(chunk + firstByte + 1, 0xff, lastByte - firstByte - 1);
    chunk[lastByte] |= tailMask;
}

/* Open the next bucket: read its high32 and the header of its 32-bit bitmap */
static int openBucket(RoaringReader *r) {
    uint32_t cookie, n;
    size_t runFlagsLen = 0, headerLen;

    if (bytesLeft(r) < 8) return -1;
    r->high32 = rdU32(r->at);
    cookie = rdU32(r->at + 4);
    r->at += 8;

    if ((int64_t) r->high32 <= r->prevHigh32) return -1;
    r->prevHigh32 = r->high32;

    if ((cookie & 0xFFFF) == SERIAL_COOKIE) {
        n = (cookie >> 16) + 1;
        runFlagsLen = (n + 7) / 8;
    } else if (cookie == SERIAL_COOKIE_NO_RUNCONTAINER) {
        if (bytesLeft(r) < 4) return -1;
        n = rdU32(r->at);
        r->at += 4;
        if (n > MAX_CONTAINERS_IN_BUCKET) return -1;
    } else {
        return -1;
    }

    /* run flags, (key, cardinality) pairs and, if present, the offsets */
    headerLen = runFlagsLen + (size_t) n * 4;
    if (!runFlagsLen || n >= NO_OFFSET_THRESHOLD)
        headerLen += (size_t) n * 4;
    if (bytesLeft(r) < headerLen) return -1;

    r->runFlags = runFlagsLen ? r->at : NULL;
    r->keyCards = r->at + runFlagsLen;
    r->at += headerLen;

    r->numContainers = n;
    r->nextContainer = 0;
    r->prevKey = -1;
    r->bucketsLeft--;
    return 0;
}

static int readRunContainer(RoaringReader *r, unsigned char *chunk, uint32_t *first, uint32_t *last) {
    uint32_t numRuns, lastEnd = 0;
    const unsigned char *runs;

    if (bytesLeft(r) < 2) return -1;
    numRuns = rdU16(r->at);
    r->at += 2;
    if (numRuns == 0 || bytesLeft(r) < (size_t) numRuns * 4) return -1;
    runs = r->at;
    r->at += (size_t) numRuns * 4;

    /* Runs are sorted, don't overlap and are not adjacent (those get merged) */
    for (uint32_t i = 0; i < numRuns; i++) {
        uint32_t start = rdU16(runs + i * 4);
        uint32_t end = start + rdU16(runs + i * 4 + 2) + 1;     /* exclusive */
        if (end > (1 << 16)) return -1;
        if (start < lastEnd || (start == lastEnd && lastEnd != 0)) return -1;
        lastEnd = end;
    }

    *first = rdU16(runs) >> 3;
    *last = (lastEnd - 1) >> 3;

    if (chunk) {
        memset(chunk + *first, 0, *last - *first + 1);
        for (uint32_t i = 0; i < numRuns; i++) {
            uint32_t start = rdU16(runs + i * 4);
            setBitRange(chunk, start, start + rdU16(runs + i * 4 + 2));
        }
    }
    return 0;
}

static int readBitsetContainer(RoaringReader *r, uint32_t cardinality, unsigned char *chunk,
                               uint32_t *first, uint32_t *last) {
    const unsigned char *words;
    uint32_t count = 0, f = 0, l = ROARING_CHUNK_BYTES - 1;

    if (bytesLeft(r) < ROARING_CHUNK_BYTES) return -1;
    words = r->at;
    r->at += ROARING_CHUNK_BYTES;

    for (uint32_t i = 0; i < ROARING_CHUNK_BYTES; i += 8)
        count += popcount64(rdU64(words + i));
    if (count != cardinality) return -1;

    /* cardinality > ARRAY_MAX_CARDINALITY, so there are non-zero bytes to stop at */
    while (words[f] == 0) f++;
    while (words[l] == 0) l--;
    *first = f;
    *last = l;

    if (chunk) {
        for (uint32_t i = f; i <= l; i++)
            chunk[i] = reverseBits(words[i]);
    }
    return 0;
}

static int readArrayContainer(RoaringReader *r, uint32_t cardinality, unsigned char *chunk,
                              uint32_t *first, uint32_t *last) {
    const unsigned char *values;

    if (bytesLeft(r) < (size_t) cardinality * 2) return -1;
    values = r->at;
    r->at += (size_t) cardinality * 2;

    for (uint32_t i = 1; i < cardinality; i++)
        if (rdU16(values + i * 2) <= rdU16(values + (i - 1) * 2)) return -1;

    *first = rdU16(values) >> 3;
    *last = rdU16(values + (cardinality - 1) * 2) >> 3;

    if (chunk) {
        memset(chunk + *first, 0, *last - *first + 1);
        for (uint32_t i = 0; i < cardinality; i++) {
            uint32_t v = rdU16(values + i * 2);
            chunk[v >> 3] |= (unsigned char) (0x80 >> (v & 7));
        }
    }
    return 0;
}

void roaringReaderInit(RoaringReader *r, const unsigned char *blob, size_t len) {
    memset(r, 0, sizeof(*r));
    r->at = blob;
    r->end = blob + len;
    r->prevHigh32 = -1;

    /* A blob too short to hold the number of buckets, or one that declares more
     * buckets than 32 bits can tell apart, is left with a cursor that cannot
     * reach a clean end, and gets reported by roaringReaderNext(). */
    if (len < 8) {
        r->bucketsLeft = 1;
        r->at = r->end;
        return;
    }
    r->bucketsLeft = rdU64(blob);
    r->at += 8;
    if (r->bucketsLeft > UINT32_MAX) {
        r->bucketsLeft = 1;
        r->at = r->end;
    }
}

int roaringReaderNext(RoaringReader *r, unsigned char *chunk,
                      uint64_t *high48, uint32_t *first, uint32_t *last) {
    uint32_t k, key, cardinality;
    int res;

    /* A bucket may hold no containers at all */
    while (r->nextContainer == r->numContainers) {
        if (r->bucketsLeft == 0)
            return (r->at == r->end) ? 0 : -1;  /* trailing bytes are not allowed */
        if (openBucket(r) != 0)
            return -1;
    }

    k = r->nextContainer++;
    key = rdU16(r->keyCards + k * 4);
    cardinality = (uint32_t) rdU16(r->keyCards + k * 4 + 2) + 1;

    if ((int32_t) key <= r->prevKey) return -1;
    r->prevKey = (int32_t) key;

    if (r->runFlags && (r->runFlags[k / 8] & (1 << (k % 8))))
        res = readRunContainer(r, chunk, first, last);
    else if (cardinality > ARRAY_MAX_CARDINALITY)
        res = readBitsetContainer(r, cardinality, chunk, first, last);
    else
        res = readArrayContainer(r, cardinality, chunk, first, last);

    if (res != 0) return -1;

    *high48 = ((uint64_t) r->high32 << 16) | key;
    return 1;
}
