#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"
#include "bulkAlloc.h"

#define STACK_SIZE 100000
#define LEN_ALLOC_FROM_STACK_MAX_SIZE (1024*16 - 40)
#define INIT_QUEUE_SIZE 20
#define BULK_MAGIC 0xdead

typedef struct SerializedStack {
    int size;
    char *buf;
    char *writePtr;
    RdbMemAlloc mem;
} SerializedStack;

/* Heap allocation (with refcount) */
typedef struct {
    unsigned short magic;
    unsigned short refcount;
} BulkHeapHdr;

struct SerializedPool {
    BulkInfo *queue;
    int writeIdx;
    int readIdx;
    int queueSize;

    RdbMemAlloc mem;
    SerializedStack *stack;
};

/* Serialized Pool */
static inline BulkInfo *serPoolEnqueue(SerializedPool *sp);
static inline BulkType serPoolResolveAllocType(RdbParser *p, AllocTypeRq typeRq);

/* Heap bulk */
static inline RdbBulk heapBulkAlloc(RdbParser *p, size_t size);
static inline RdbBulk heapBulkIncrRef(RdbBulk b);
static inline void heapBulkDecrRef(RdbParser *p, RdbBulk b);

/* Serialized Stack */
static RdbBulk serStackAlloc(SerializedStack *stack, unsigned short buf_size);
static inline void serStackFlush(SerializedStack *stack);
static SerializedStack * sertackInit(RdbMemAlloc *mem, int size);
static void serStackRelease(SerializedStack *stack);

/*** LIB API functions ***/

_LIBRDB_API void RDB_bulkFree(RdbParser *p, RdbBulkCopy b) {
    switch (p->mem.bulkAllocType) {
        case RDB_BULK_ALLOC_STACK:
            /* fall through - Note that even when bulkAllocType is set to RDB_BULK_ALLOC_STACK,
             * calling to RDB_bulkClone() will return allocation on heap
             */
        case RDB_BULK_ALLOC_HEAP:
            heapBulkDecrRef(p, (RdbBulk) b);
            break;
        case RDB_BULK_ALLOC_EXTERN:
        case RDB_BULK_ALLOC_EXTERN_OPT:
            p->mem.appBulk.free( (RdbBulk) b);
            break;
        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                "RDB_bulkFree(): Invalid bulk allocation type: %d", p->mem.bulkAllocType);
            break;
    }
}

/*** Serialized Pool ***/

SerializedPool *serPoolInit(RdbMemAlloc *mem) {

    SerializedPool *sp = (SerializedPool *) mem->malloc(sizeof(SerializedPool));
    sp->queue = (BulkInfo *) mem->malloc(INIT_QUEUE_SIZE * sizeof(BulkInfo));
    sp->readIdx = sp->writeIdx = 0;
    sp->queueSize = INIT_QUEUE_SIZE;
    sp->stack = sertackInit(mem, STACK_SIZE);
    sp->mem = *mem;
    return sp;
}

void serPoolRelease(RdbParser *p) {
    SerializedPool *sp = p->cache;
    if (!sp) return;

    serPoolFlush(p);
    RDB_free(p, sp->queue);
    serStackRelease(sp->stack);
    RDB_free(p, sp);
    p->cache = NULL;
}

static void serPoolAllocNew(RdbParser *p, size_t len, BulkType type, char *refBuf, BulkInfo *binfo) {
    size_t lenIncNewline = len + 1;
    binfo->len = len;
    binfo->written = 0;

    switch(type) {
        case BULK_TYPE_STACK:
            if ((lenIncNewline < LEN_ALLOC_FROM_STACK_MAX_SIZE) &&
                (binfo->ref = serStackAlloc(p->cache->stack, lenIncNewline)) != NULL) {
                binfo->bulkType = BULK_TYPE_STACK;
                break;
            }

            /* fall through - `len` too big or stack is full. Alloc from heap instead */
        case BULK_TYPE_HEAP:
            binfo->ref = heapBulkAlloc(p, lenIncNewline);
            binfo->bulkType = BULK_TYPE_HEAP;
            break;

        case BULK_TYPE_EXTERN:
            binfo->ref = p->cache->mem.appBulk.alloc(lenIncNewline);
            binfo->bulkType = BULK_TYPE_EXTERN;
            break;

        case BULK_TYPE_REF:
            assert (refBuf !=  NULL);
            binfo->ref = refBuf;
            binfo->bulkType = BULK_TYPE_REF;
            break;

        default:
            RDB_reportError(p, RDB_ERR_SP_INVALID_ALLOCATION_TYPE,
                           "serPoolAllocNew() Serialized pool received invalid allocation type request: %d", type);
            assert(0);
    }
}

/* Allocate memory, either new buffer or retrieve from queue. If requested to allocate
 * application bulk (RQ_ALLOC_APP_BULK) then lookup what bulk allocation type is
 * configured by the application (can be either stack, heap or external). Otherwise it
 * is just an internal allocation of the parser, either from stack or heap.
 *
 * Note that for most cases internal allocations of the parser will be on stack. The
 * few cases that it will allocate it on heap is when it needs to preserve data
 * across states.
 */
BulkInfo *serPoolAlloc(RdbParser *p, size_t len, AllocTypeRq typeRq, RdbBulk refBuf) {
    BulkInfo *binfo;
    SerializedPool *sp = p->cache;

    /* if no cached buffers in queue (i.e. first time to read this data)
     * then allocate new buffer and fill it from reader */
    if (sp->readIdx == sp->writeIdx) {
        binfo = serPoolEnqueue(sp);
        BulkType type = serPoolResolveAllocType(p, typeRq);
        serPoolAllocNew(p, len, type, refBuf, binfo);
    } else {
        binfo = &(sp->queue[sp->readIdx]);

        /* assert allocation request (after rollback) has exact same length as before */
        if (len != sp->queue[sp->readIdx].len)
            assert (len == sp->queue[sp->readIdx].len);
    }


    ++sp->readIdx;
    return binfo;
}

void serPoolFlush(RdbParser *p) {
    SerializedPool *sp = p->cache;
    for (int i = 0 ; i < sp->writeIdx ; ++i) {
        /* release all bulks that are not allocated in stack */
        switch(sp->queue[i].bulkType) {
            case BULK_TYPE_REF:
                break;
            case BULK_TYPE_STACK:
                break;
            case BULK_TYPE_HEAP:
                heapBulkDecrRef(p, sp->queue[i].ref);
                break;
            case BULK_TYPE_EXTERN:
                sp->mem.appBulk.free(sp->queue[i].ref);
                break;
            default:
                RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                    "serPoolFlush(): Invalid bulk allocation type: %d", sp->queue[i].bulkType);
                break;
        }
    }
    sp->readIdx = sp->writeIdx = 0;
    serStackFlush(sp->stack);
}

void serPoolRollback(RdbParser *p) {
    SerializedPool *sp = p->cache;
    sp->readIdx = 0;
}

void serPoolPrintDbg(RdbParser *p) {
    SerializedPool *sp = p->cache;
    printf("*********************************************************\n");
    printf("Serialized Pool Info:\n");
    printf("  queue size: %d\n", sp->queueSize);
    printf("  queue address: %p\n", (void *) sp->queue);
    printf("  queue read index: %d\n", sp->readIdx);
    printf("  queue write index: %d\n", sp->writeIdx);
    printf("  stack start address: %p\n", sp->stack->buf);
    printf("  stack write address: %p\n", sp->stack->writePtr);

    printf("Serialized Pool - Queue items: \n");
    for ( int i = 0; i != sp->writeIdx ; ++i)
        printf(" - [allocType=%d] [written=%lu] %p: \"0x%X 0x%X ...\":\"%s\" (len=%lu) \n",
               sp->queue[i].bulkType,
               sp->queue[i].written,
               sp->queue[i].ref,
               ((unsigned char *)sp->queue[i].ref)[0],
               ((unsigned char *)sp->queue[i].ref)[1],
               (unsigned char *)sp->queue[i].ref, sp->queue[i].len);
    printf("\n*********************************************************\n");
}

RdbBulkCopy bulkClone(RdbParser *p, BulkInfo *binfo) {
    size_t lenIncNewline = binfo->len + 1;
    switch(binfo->bulkType) {
        case BULK_TYPE_HEAP: {
            /* if buffer allocated on heap, just incref counter */
            return (RdbBulkCopy) heapBulkIncrRef(binfo->ref);
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
                    bulkcopy = heapBulkAlloc(p, lenIncNewline);
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

int serPoolIsNewNextAllocDbg(RdbParser *p) {
    SerializedPool *sp = p->cache;
    return (sp->writeIdx == sp->readIdx) ? 1 : 0;
}

static inline BulkInfo *serPoolEnqueue(SerializedPool *sp) {
    sp->writeIdx += 1;
    if (unlikely(sp->writeIdx == sp->queueSize)) {
        sp->queueSize *= 2;
        sp->queue = realloc(sp->queue, sp->queueSize * sizeof(BulkInfo));
    }
    return &(sp->queue[sp->writeIdx-1]);
}

static inline BulkType serPoolResolveAllocType(RdbParser *p, AllocTypeRq typeRq) {

    static const BulkType rqAlloc2spAllocType[RQ_ALLOC_MAX][RDB_BULK_ALLOC_MAX] = {

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

    return rqAlloc2spAllocType[typeRq][p->mem.bulkAllocType];
}

/*** Serialized Stack ***/

static SerializedStack * sertackInit(RdbMemAlloc *mem, int size) {
    SerializedStack *stack = (SerializedStack *) mem->malloc(sizeof(SerializedStack));
    stack->buf = mem->malloc(size);
    stack->writePtr = stack->buf;
    stack->size = size;
    stack->mem = *mem;
    return stack;
}

static void serStackRelease(SerializedStack *stack) {
    stack->mem.free(stack->buf);
    stack->mem.free(stack);
}

static RdbBulk serStackAlloc(SerializedStack *stack, unsigned short buf_size) {
    int written = stack->writePtr - stack->buf;

    if (unlikely( buf_size > stack->size - written)) {
        return NULL;
    }

    void *ptr = stack->writePtr;
    stack->writePtr += buf_size;
    return ptr;
}

static inline void serStackFlush(SerializedStack *stack) {
    stack->writePtr = stack->buf;
}

/*** Heap Bulk ***/

static inline RdbBulk heapBulkAlloc(RdbParser *p, size_t size) {

    BulkHeapHdr *header = (BulkHeapHdr *)RDB_alloc(p, sizeof(BulkHeapHdr) + size);
    header->magic = BULK_MAGIC;
    header->refcount = 1;
    return (RdbBulk) (header + 1);
}

static inline void heapBulkDecrRef(RdbParser *p, RdbBulk b) {
    BulkHeapHdr *header = (BulkHeapHdr *)b - 1;
    assert(header->magic == BULK_MAGIC);
    if (--header->refcount == 0) {
        p->mem.free(header);
    }
}

static inline RdbBulk heapBulkIncrRef(RdbBulk b) {
    BulkHeapHdr *header = (BulkHeapHdr *)b - 1;
    assert(header->magic == BULK_MAGIC);
    header->refcount++;
    return b;
}

/*** unmanaged allocations ***/

static inline BulkType resolveAllocTypeUnmanaged(RdbParser *p, AllocUnmngTypeRq rq) {
    static const BulkType rqAlloc2spAllocType[UNMNG_RQ_ALLOC_MAX][RDB_BULK_ALLOC_MAX] = {

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

    };
    return rqAlloc2spAllocType[rq][p->mem.bulkAllocType];
}

void unmngAllocBulk(RdbParser *p, size_t len, AllocUnmngTypeRq rq, char *refBuf, BulkInfo *bi) {
    BulkType type = resolveAllocTypeUnmanaged(p, rq);
    serPoolAllocNew(p, len, type, refBuf, bi);
}

void unmngFreeBulk(RdbParser *p, BulkInfo *binfo) {

    if (unlikely(binfo->ref == NULL))
        return;

    switch(binfo->bulkType) {
        case BULK_TYPE_REF:
            /* nothing to do */
            break;
        case BULK_TYPE_HEAP:
            heapBulkDecrRef(p, binfo->ref);
            break;
        case BULK_TYPE_EXTERN:
            p->mem.appBulk.free(binfo->ref);
            break;
        case BULK_TYPE_STACK:
            /* fall through */
        default:
            RDB_reportError(p, RDB_ERR_INVALID_BULK_ALLOC_TYPE,
                           "serPoolFlush(): Invalid bulk allocation type: %d", binfo->bulkType);
            break;
    }
    binfo->ref = NULL;
}