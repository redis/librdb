/*
 * This API propose two ways to allocate and release bulks of memory:
 *
 *  1) Unmanaged RdbBulk allocation (aka. BulkUnmanaged)
 *
 *  Unmanaged bulk allocation is a method of allocating memory where the parser
 *  manages the allocation and deallocation of memory rather than relying on a data
 *  structure like the bulk-pool (Gets flushed on each state transition. more below).
 *  This method is useful when the application has RdbBulk allocations that needs
 *  to live behind current state of the parser.
 *
 *
 *  2) Bulk-pool (aka. BulkPool)
 *
 * This customized data structure is useful in the context of RDBParser that support
 * asynchronous execution (but not only). In such cases, the parser might receive
 * only partial data and needs to preserve its last valid state and return. BulkPool
 * helps preserve the partial data already read from the RDB source, which cannot
 * be re-read such as in the case of streaming. The data can then be "replayed"
 * later once more data becomes available to complete the parsing-element state.
 *
 * The Bulk-Pool support 3 commands:
 *
 * a) Allocate   - Allocates memory per caller request and store a reference
 *                 to the allocation in a sequential queue.
 * b) Rollback   - The "Rollback" command rewinds the queue and allows the exact same
 *                 sequence of allocation requests to be "replayed" to the caller.
 *                 However, instead of creating new allocations, the allocator returns
 *                 the next item in the queue.
 * c) Flush      - Clean the entire queue and deletes corresponding referenced buffers.
 *
 * The bulk-pool utilizes 3 distinct types of allocators:
 *
 * 1) STACK ALLOCATOR
 * The Stack Allocator is specifically designed to work in tandem with the BulkPool
 * and supports the Allocate, Rollback, and Flush commands. When the pool
 * receives small allocation requests and the application has not restricted
 * allocation to a specific type, it prefers to allocate from the stack. If
 * the parser fails to reach a new state, the stack will be rolled back in order
 * to replay. If the parser reaches a new state, then the stack will be flushed
 * along with the pool.
 *
 * 2) HEAP ALLOCATOR
 * The Heap Allocator allocates memory from the heap with refcount support.
 *
 * 3) EXTERNAL ALLOCATOR
 * The External Allocator is not mandatory and can be provided by the application
 * client to allocate only the buffers that will be passed to the application's
 * callbacks. These buffers are referred to as RQ_ALLOC_APP_BULK within this API.
 *
 * In addition, the pool supports Reference allocator of a Bulk. It expects to
 * receive pre-allocated memory and record it as a referenced bulk. The first use
 * case for it is when there is allocated memory that is already initialized with
 * data and the parser just want to optimize and pass it as RdbBulk to callbacks.
 * Another use case is when memory was allocated, but it is not loaded with data
 * yet by rdbLoad functions, then by registration to the pool it will be able to
 * load it safely with rdbLoad functions without worry from rollback flows.
 *
 */

#ifndef BULK_ALLOC_H
#define BULK_ALLOC_H

#include "parser.h"

/*** BulkPool ***/
BulkPool *bulkPoolInit(RdbMemAlloc *mem);
void bulkPoolRelease(RdbParser *p);
BulkInfo *bulkPoolAlloc(RdbParser *p, size_t len, AllocTypeRq typeRq, char *refBuf);
void bulkPoolFlush(RdbParser *p);
void bulkPoolRollback(RdbParser *p);

/*** BulkUnmanaged ***/
void bulkUnmanagedAlloc(RdbParser *p, size_t len, AllocUnmngTypeRq rq, char *refBuf, BulkInfo *bi);
void bulkUnmanagedFree(RdbParser *p, BulkInfo *binfo);

/* cloning RdbBulk */
RdbBulkCopy bulkClone(RdbParser *p, BulkInfo *binfo);

/* debug */
void bulkPoolPrintDbg(RdbParser *p);
int bulkPoolIsNewNextAllocDbg(RdbParser *p);
void bulkPoolAssertFlushedDbg(RdbParser *p);

#endif /*BULK_ALLOC_H*/
