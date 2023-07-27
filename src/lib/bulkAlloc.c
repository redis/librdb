#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../../deps/redis/util.h"
#include "bulkAlloc.h"

#define STACK_SIZE 100000
#define LEN_ALLOC_FROM_STACK_MAX_SIZE (1024*16 - 40)
#define INIT_QUEUE_SIZE 20
#define BULK_MAGIC 0xdead

typedef struct BulkStack {
    int size;
    char *buf;
    char *writePtr;
    RdbMemAlloc mem;
} BulkStack;

/* Heap allocation (with refcount) */
typedef struct {
    unsigned short magic;
    unsigned short refcount;
} BulkHeapHdr;

struct BulkPool {
    BulkInfo *queue;
    int writeIdx;
    int readIdx;
    int queueSize;

    RdbMemAlloc mem;
    BulkStack *stack;
};

/* BulkPool */
static inline BulkInfo *bulkPoolEnqueue(BulkPool *pool);
static inline BulkType bulkPoolResolveAllocType(RdbParser *p, AllocTypeRq rq);

/* BulkHeap */
static inline RdbBulk bulkHeapAlloc(RdbParser *p, size_t size);
static inline RdbBulk bulkHeapIncrRef(RdbBulk b);
static inline void bulkHeapDecrRef(RdbParser *p, RdbBulk b);

/* BulkStack */
static RdbBulk bulkStackAlloc(BulkStack *stack, unsigned short buf_size);
static inline void bulkStackFlush(BulkStack *stack);
static BulkStack * bulkStackInit(RdbMemAlloc *mem, int size);
static void bulkStackRelease(BulkStack *stack);

/* BulkUnmanaged */
static inline BulkType bulkUnmanagedResolveAllocType(RdbParser *p, AllocUnmngTypeRq rq);

/*** LIB API functions ***/

_LIBRDB_API void RDB_bulkCopyFree(RdbParser *p, RdbBulkCopy b) {
    switch (p->mem.bulkAllocType) {
        case RDB_BULK_ALLOC_STACK:
            /* fall through - Note that even when bulkAllocType is set to RDB_BULK_ALLOC_STACK,
             * calling to RDB_bulkClone() will return allocation on heap
             */
        case RDB_BULK_ALLOC_HEAP:
            bulkHeapDecrRef(p, (RdbBulk) b);
            break;
        case RDB_BULK_ALLOC_EXTERN:
        case RDB_BULK_ALLOC_EXTERN_OPT:
            p->mem.appBulk.free( (RdbBulk) b);
            break;
        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                "RDB_bulkCopyFree(): Invalid bulk allocation type: %d", p->mem.bulkAllocType);
            break;
    }
}

_LIBRDB_API  RdbBulkCopy RDB_bulkCopyClone(RdbParser *p, RdbBulkCopy b, size_t len) {

    /* copy of RdbBulk (BulkCopy) must be alloccated either heap or externally  */
    switch (p->mem.bulkAllocType) {
        case RDB_BULK_ALLOC_STACK:
        case RDB_BULK_ALLOC_HEAP:
            return (RdbBulkCopy) bulkHeapIncrRef( (RdbBulk) b);

        case RDB_BULK_ALLOC_EXTERN:
        case RDB_BULK_ALLOC_EXTERN_OPT:
            return (RdbBulkCopy) p->mem.appBulk.clone( (void *) b, len + 1 /* add termination */ );

        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                            "RDB_bulkCopyClone(): Invalid bulk allocation type: %d", p->mem.bulkAllocType);
            return NULL;
    }
}

/*** BulkPool ***/

BulkPool *bulkPoolInit(RdbMemAlloc *mem) {

    BulkPool *pool = (BulkPool *) mem->malloc(sizeof(BulkPool));
    pool->queue = (BulkInfo *) mem->malloc(INIT_QUEUE_SIZE * sizeof(BulkInfo));
    pool->readIdx = pool->writeIdx = 0;
    pool->queueSize = INIT_QUEUE_SIZE;
    pool->stack = bulkStackInit(mem, STACK_SIZE);
    pool->mem = *mem;
    return pool;
}

void bulkPoolRelease(RdbParser *p) {
    BulkPool *pool = p->cache;
    if (!pool) return;

    bulkPoolFlush(p);
    RDB_free(p, pool->queue);
    bulkStackRelease(pool->stack);
    RDB_free(p, pool);
    p->cache = NULL;
}

static void bulkPoolAllocNew(RdbParser *p, size_t len, BulkType type, char *refBuf, BulkInfo *binfo) {
    size_t lenIncStringTerm = len + 1;
    binfo->len = len;
    binfo->written = 0;

    switch(type) {
        case BULK_TYPE_STACK:
            if ((lenIncStringTerm < LEN_ALLOC_FROM_STACK_MAX_SIZE) &&
                (binfo->ref = bulkStackAlloc(p->cache->stack, lenIncStringTerm)) != NULL) {
                binfo->bulkType = BULK_TYPE_STACK;
                break;
            }

            /* fall through - `len` too big or stack is full. Alloc from heap instead */
        case BULK_TYPE_HEAP:
            binfo->ref = bulkHeapAlloc(p, lenIncStringTerm);
            binfo->bulkType = BULK_TYPE_HEAP;
            break;

        case BULK_TYPE_EXTERN:
            binfo->ref = p->cache->mem.appBulk.alloc(lenIncStringTerm);
            binfo->bulkType = BULK_TYPE_EXTERN;
            break;

        case BULK_TYPE_REF:
            assert (refBuf !=  NULL);
            binfo->ref = refBuf;
            binfo->bulkType = BULK_TYPE_REF;
            break;

        default:
            RDB_reportError(p, RDB_ERR_BULK_ALLOC_INVALID_TYPE,
                            "bulkPoolAllocNew() received invalid allocation type request: %d", type);
            assert(0);
    }
    /* add string termination */
    ((unsigned char *) binfo->ref)[len] = '\0';
}

/* Allocate memory, either new buffer or retrieve from queue. If requested to allocate
 * application bulk (RQ_ALLOC_APP_BULK) then lookup what bulk allocation type is
 * configured by the application (can be either stack, heap or external). Otherwise it
 * is just an internal allocation of the parser, either from stack or heap.
 */
BulkInfo *bulkPoolAlloc(RdbParser *p, size_t len, AllocTypeRq typeRq, char *refBuf) {
    BulkInfo *binfo;
    BulkPool *pool = p->cache;

    /* if no cached buffers in queue (i.e. first time to read this data)
     * then allocate new buffer and fill it from reader */
    if (pool->readIdx == pool->writeIdx) {
        binfo = bulkPoolEnqueue(pool);
        BulkType type = bulkPoolResolveAllocType(p, typeRq);
        bulkPoolAllocNew(p, len, type, refBuf, binfo);

        /* if requested ref another memory but forced to allocate a new buffer since configured
         * RDB_BULK_ALLOC_EXTERN, then copy referenced data to the new allocated buffer */
        if (unlikely(typeRq == RQ_ALLOC_APP_BULK_REF) && (type != BULK_TYPE_REF))
            memcpy(binfo->ref, refBuf, len);

    } else {
        binfo = &(pool->queue[pool->readIdx]);

        /* assert allocation request (after rollback) has exact same length as before */
        if (len != pool->queue[pool->readIdx].len)
            assert (len == pool->queue[pool->readIdx].len);
    }


    ++pool->readIdx;
    return binfo;
}

void bulkPoolFlush(RdbParser *p) {
    BulkPool *pool = p->cache;
    for (int i = 0 ; i < pool->writeIdx ; ++i) {
        /* release all bulks that are not allocated in stack */
        switch(pool->queue[i].bulkType) {
            case BULK_TYPE_REF:
                break;
            case BULK_TYPE_STACK:
                break;
            case BULK_TYPE_HEAP:
                bulkHeapDecrRef(p, pool->queue[i].ref);
                break;
            case BULK_TYPE_EXTERN:
                pool->mem.appBulk.free(pool->queue[i].ref);
                break;
            default:
                RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                                "bulkPoolFlush(): Invalid bulk allocation type: %d", pool->queue[i].bulkType);
                break;
        }
    }
    pool->readIdx = pool->writeIdx = 0;
    bulkStackFlush(pool->stack);
}

void bulkPoolRollback(RdbParser *p) {
    BulkPool *pool = p->cache;
    pool->readIdx = 0;
}

void bulkPoolPrintDbg(RdbParser *p) {
    BulkPool *pool = p->cache;
    printf("*********************************************************\n");
    printf("BulkPool Info:\n");
    printf("  queue size: %d\n", pool->queueSize);
    printf("  queue address: %p\n", (void *) pool->queue);
    printf("  queue read index: %d\n", pool->readIdx);
    printf("  queue write index: %d\n", pool->writeIdx);
    printf("  stack start address: %p\n", pool->stack->buf);
    printf("  stack write address: %p\n", pool->stack->writePtr);

    printf("BulkPool - Queue items: \n");
    for (int i = 0; i != pool->writeIdx ; ++i)
        printf(" - [allocType=%d] [written=%lu] %p: \"0x%X 0x%X ...\":\"%s\" (len=%lu) \n",
               pool->queue[i].bulkType,
               pool->queue[i].written,
               pool->queue[i].ref,
               ((unsigned char *)pool->queue[i].ref)[0],
               ((unsigned char *)pool->queue[i].ref)[1],
               (unsigned char *)pool->queue[i].ref, pool->queue[i].len);
    printf("\n*********************************************************\n");
}

RdbBulkCopy bulkClone(RdbParser *p, BulkInfo *binfo) {
    size_t lenIncNewline = binfo->len + 1;
    switch(binfo->bulkType) {
        case BULK_TYPE_HEAP: {
            /* if buffer allocated on heap, just incref counter */
            return (RdbBulkCopy) bulkHeapIncrRef(binfo->ref);
        }
        case BULK_TYPE_EXTERN:
            /* use external clone() */
            return (RdbBulkCopy) p->mem.appBulk.clone(binfo->ref, lenIncNewline);

        /* referenced bulk or allocated on stack. We have to malloc and copy */
        case BULK_TYPE_STACK:
        case BULK_TYPE_REF: {
            RdbBulkCopy bulkcopy;

            /* need to use configured bulk allocator */
            switch (p->mem.bulkAllocType) {
                case RDB_BULK_ALLOC_STACK:
                case RDB_BULK_ALLOC_HEAP:
                    bulkcopy = bulkHeapAlloc(p, lenIncNewline);
                    return memcpy(bulkcopy, binfo->ref, lenIncNewline);

                case RDB_BULK_ALLOC_EXTERN:
                case RDB_BULK_ALLOC_EXTERN_OPT:
                    bulkcopy = p->mem.appBulk.alloc(lenIncNewline);
                    return memcpy(bulkcopy, binfo->ref, lenIncNewline);

                default:
                    RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                        "bulkClone(): Invalid bulk allocation type: %d", p->mem.bulkAllocType);
                    return NULL;
            }
        }

        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                "bulkClone() Invalid bulk allocation type: %d", binfo->bulkType);
            return NULL;
    }
}

int bulkPoolIsNewNextAllocDbg(RdbParser *p) {
    BulkPool *pool = p->cache;
    return (pool->writeIdx == pool->readIdx) ? 1 : 0;
}

void bulkPoolAssertFlushedDbg(RdbParser *p) {
    BulkPool *pool = p->cache;
    assert(pool->writeIdx == 0);
}

static inline BulkInfo *bulkPoolEnqueue(BulkPool *pool) {
    pool->writeIdx += 1;
    if (unlikely(pool->writeIdx == pool->queueSize)) {
        pool->queueSize *= 2;
        pool->queue = realloc(pool->queue, pool->queueSize * sizeof(BulkInfo));
    }
    return &(pool->queue[pool->writeIdx - 1]);
}

static inline BulkType bulkPoolResolveAllocType(RdbParser *p, AllocTypeRq typeRq) {

    static const BulkType rqAlloc2bulkType[RQ_ALLOC_MAX][RDB_BULK_ALLOC_MAX] = {

        /* parser request alloc for internal use. Better try alloc from stack than heap */
        [RQ_ALLOC] = {
                BULK_TYPE_STACK,         /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_STACK,         /* RDB_BULK_ALLOC_HEAP */
                BULK_TYPE_STACK,         /* RDB_BULK_ALLOC_EXTERN */
                BULK_TYPE_STACK,         /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

        /* For internal use, parser request to ref another memory (in order to rdbLoad() it
         * with data from RDB source and be resilient in case of rollback flow) */
        [RQ_ALLOC_REF] = {
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_HEAP */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

        /* parser requests alloc RdbBulk that will be given to app callbacks */
        [RQ_ALLOC_APP_BULK] = {
                BULK_TYPE_STACK,         /* RDB_BULK_ALLOC_STACK - App configured stack. Try use internal stack alloc */
                BULK_TYPE_HEAP,          /* RDB_BULK_ALLOC_HEAP - App configured heap. Use heap allocation */
                BULK_TYPE_EXTERN,        /* RDB_BULK_ALLOC_EXTERN - App configured external allocator */
                BULK_TYPE_EXTERN,        /* RDB_BULK_ALLOC_EXTERN_OPT */
        },


        /* parser requests to alloc RdbBulk that only reference to another memory */
        [RQ_ALLOC_APP_BULK_REF] = {
                /* If an application configured for heap or stack allocation in an effort to enhance
                 * its performance, we can safely return a reference-bulk. This is because
                 * we do not copy any data in either case, and the application cannot differentiate
                 * since memory allocation function was configured internally.
                 */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_HEAP */

                /* if app configure specific external allocator for bulks, then parser must obey,
                 * even at the cost of another copy */
                BULK_TYPE_EXTERN,         /* RDB_BULK_ALLOC_EXTERN */

                /* if app configured RDB_BULK_ALLOC_EXTERN_OPT, then let's just return reference
                 * bulk when possible. In this case the application callbacks cannot make any
                 * assumption about the allocated memory layout of RdbBulk. It can assist function
                 * RDB_isRefBulk to resolve whether given bulk was allocated by its external
                 * allocator or optimized with reference bulk.
                 */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN_OPT */
        },
    };

    return rqAlloc2bulkType[typeRq][p->mem.bulkAllocType];
}

/*** BulkStack ***/

static BulkStack * bulkStackInit(RdbMemAlloc *mem, int size) {
    BulkStack *stack = (BulkStack *) mem->malloc(sizeof(BulkStack));
    stack->buf = mem->malloc(size);
    stack->writePtr = stack->buf;
    stack->size = size;
    stack->mem = *mem;
    return stack;
}

static void bulkStackRelease(BulkStack *stack) {
    stack->mem.free(stack->buf);
    stack->mem.free(stack);
}

static RdbBulk bulkStackAlloc(BulkStack *stack, unsigned short buf_size) {
    int written = stack->writePtr - stack->buf;

    if (unlikely( buf_size > stack->size - written)) {
        return NULL;
    }

    void *ptr = stack->writePtr;
    stack->writePtr += buf_size;
    return ptr;
}

static inline void bulkStackFlush(BulkStack *stack) {
    stack->writePtr = stack->buf;
}

/*** BulkHeap ***/

static inline RdbBulk bulkHeapAlloc(RdbParser *p, size_t size) {

    BulkHeapHdr *header = (BulkHeapHdr *)RDB_alloc(p, sizeof(BulkHeapHdr) + size);
    header->magic = BULK_MAGIC;
    header->refcount = 1;
    return (RdbBulk) (header + 1);
}

static inline void bulkHeapDecrRef(RdbParser *p, RdbBulk b) {
    BulkHeapHdr *header = (BulkHeapHdr *)b - 1;
    assert(header->magic == BULK_MAGIC);
    if (--header->refcount == 0) {
        p->mem.free(header);
    }
}

static inline RdbBulk bulkHeapIncrRef(RdbBulk b) {
    BulkHeapHdr *header = (BulkHeapHdr *)b - 1;
    assert(header->magic == BULK_MAGIC);
    header->refcount++;
    return b;
}

/*** BulkUnmanaged - not to be deleted on state transition ***/


static inline BulkType bulkUnmanagedResolveAllocType(RdbParser *p, AllocUnmngTypeRq rq) {
    static const BulkType rqAlloc2bulkType[UNMNG_RQ_ALLOC_MAX][RDB_BULK_ALLOC_MAX] = {

        /* parser request alloc RdbBulk for internal use. Only alloc from heap
         * (Stack is flushed on each state transition) */
        [UNMNG_RQ_ALLOC] = {
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_HEAP */
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_EXTERN */
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

        /* parser requests alloc RdbBulk that will be given to app callbacks */
        [UNMNG_RQ_ALLOC_APP_BULK] = {
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_HEAP,       /* RDB_BULK_ALLOC_HEAP */
                BULK_TYPE_EXTERN,     /* RDB_BULK_ALLOC_EXTERN */
                BULK_TYPE_EXTERN,     /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

        /* parser requests to alloc RdbBulk that only ref another memory */
        [UNMNG_RQ_ALLOC_APP_BULK_REF] = {
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_HEAP */

                /* if app configure specific external allocator for bulks, then parser
                 * must obey, even at the cost of another copy */
                BULK_TYPE_EXTERN,    /* RDB_BULK_ALLOC_EXTERN */

                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

        /* parser request REF for internal use. Trivially released by bulkUnmanagedFree() */
        [UNMNG_RQ_ALLOC_REF] = {
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_STACK */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_HEAP */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN */
                BULK_TYPE_REF,       /* RDB_BULK_ALLOC_EXTERN_OPT */
        },

    };
    return rqAlloc2bulkType[rq][p->mem.bulkAllocType];
}

void bulkUnmanagedAlloc(RdbParser *p, size_t len, AllocUnmngTypeRq rq, char *refBuf, BulkInfo *bi) {
    BulkType type = bulkUnmanagedResolveAllocType(p, rq);
    bulkPoolAllocNew(p, len, type, refBuf, bi);
}

void bulkUnmanagedFree(RdbParser *p, BulkInfo *binfo) {

    if (unlikely(binfo->ref == NULL))
        return;

    switch(binfo->bulkType) {
        case BULK_TYPE_REF:
            /* nothing to do */
            break;
        case BULK_TYPE_HEAP:
            bulkHeapDecrRef(p, binfo->ref);
            break;
        case BULK_TYPE_EXTERN:
            p->mem.appBulk.free(binfo->ref);
            break;
        case BULK_TYPE_STACK:
            /* fall through */
        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                           "bulkUnmanagedFree(): Invalid bulk allocation type: %d", binfo->bulkType);
            break;
    }
    binfo->ref = NULL;
}