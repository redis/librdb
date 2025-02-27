#ifndef DEFINES_H
#define DEFINES_H

/* This file should include only RDB related defines. Might be read in the
 * future from Redis repo */

/* Map object types to RDB object types. Macros starting with OBJ_ are for
 * memory storage and may change. Instead RDB types must be fixed because
 * we store them on disk. */
#define RDB_TYPE_STRING 0
#define RDB_TYPE_LIST   1
#define RDB_TYPE_SET    2
#define RDB_TYPE_ZSET   3
#define RDB_TYPE_HASH   4
#define RDB_TYPE_ZSET_2 5 /* ZSET version 2 with doubles stored in binary. */
#define RDB_TYPE_MODULE_PRE_GA 6 /* Used in 4.0 release candidates */
#define RDB_TYPE_MODULE_2 7 /* Module value with annotations for parsing without
                               the generating module being loaded. */

/* Object types for encoded objects. */
#define RDB_TYPE_HASH_ZIPMAP        9
#define RDB_TYPE_LIST_ZIPLIST       10
#define RDB_TYPE_SET_INTSET         11
#define RDB_TYPE_ZSET_ZIPLIST       12
#define RDB_TYPE_HASH_ZIPLIST       13
#define RDB_TYPE_LIST_QUICKLIST     14
#define RDB_TYPE_STREAM_LISTPACKS   15
#define RDB_TYPE_HASH_LISTPACK      16
#define RDB_TYPE_ZSET_LISTPACK      17
#define RDB_TYPE_LIST_QUICKLIST_2   18
#define RDB_TYPE_STREAM_LISTPACKS_2 19
#define RDB_TYPE_SET_LISTPACK       20
#define RDB_TYPE_STREAM_LISTPACKS_3 21
#define RDB_TYPE_HASH_METADATA_PRE_GA 22      /* Hash with HFEs. Doesn't attach min TTL at start (7.4 RC) */
#define RDB_TYPE_HASH_LISTPACK_EX_PRE_GA 23   /* Hash LP with HFEs. Doesn't attach min TTL at start (7.4 RC) */
#define RDB_TYPE_HASH_METADATA      24        /* Hash with HFEs. Attach min TTL at start */
#define RDB_TYPE_HASH_LISTPACK_EX   25        /* Hash LP with HFEs. Attach min TTL at start */
#define RDB_TYPE_MAX                26


/* Special RDB opcodes (saved/loaded with rdbSaveType/rdbLoadType). */
#define RDB_OPCODE_SLOT_INFO  244   /* Individual slot info, such as slot id and size (cluster mode only). */
#define RDB_OPCODE_FUNCTION2  245   /* function library data */
#define RDB_OPCODE_FUNCTION   246   /* old function library data for 7.0 rc1 and rc2 */
#define RDB_OPCODE_MODULE_AUX 247   /* Module auxiliary data. */
#define RDB_OPCODE_IDLE       248   /* LRU idle time. */
#define RDB_OPCODE_FREQ       249   /* LFU frequency. */
#define RDB_OPCODE_AUX        250   /* RDB aux field. */
#define RDB_OPCODE_RESIZEDB   251   /* Hash table resize hint. */
#define RDB_OPCODE_EXPIRETIME_MS 252    /* Expire time in milliseconds. */
#define RDB_OPCODE_EXPIRETIME 253       /* Old expire time in seconds. */
#define RDB_OPCODE_SELECTDB   254   /* DB number of the following keys. */
#define RDB_OPCODE_EOF        255   /* End of the RDB file. */

/* Garantia V1002 RDB opcodes -- used to read older version RDB files. */
/*#define REDIS_RDB_2_OPCODE_GD_DICT    249*/
#define REDIS_RDB_2_OPCODE_GOPTIONS   250
#define REDIS_RDB_2_OPCODE_GCAS       251
#define REDIS_RDB_2_OPCODE_GFLAGS     252

/* Garantia V1006 (current) opcodes */
/*#define RDB_OPCODE_GD_DICT        100*/
#define RDB_OPCODE_GCAS             101
#define RDB_OPCODE_GFLAGS           102
#define __RDB_OPCODE_RAM_LRU        107 /* Available only in Redis Enterprise */

/* Defines related to the dump file format. To store 32 bits lengths for short
 * keys requires a lot of space, so we check the most significant 2 bits of
 * the first byte to interpreter the length:
 *
 * 00|XXXXXX => if the two MSB are 00 the len is the 6 bits of this byte
 * 01|XXXXXX XXXXXXXX =>  01, the len is 14 bits, 6 bits + 8 bits of next byte
 * 10|000000 [32 bit integer] => A full 32 bit len in net byte order will follow
 * 10|000001 [64 bit integer] => A full 64 bit len in net byte order will follow
 * 11|OBKIND this means: specially encoded object will follow. The six bits
 *           number specify the kind of object that follows.
 *           See the RDB_ENC_* defines.
 *
 * Lengths up to 63 are stored using a single byte, most DB keys, and may
 * values, will fit inside. */
#define RDB_6BITLEN 0
#define RDB_14BITLEN 1
#define RDB_32BITLEN 0x80
#define RDB_64BITLEN 0x81
#define RDB_ENCVAL 3
#define RDB_LENERR UINT64_MAX

/* When a length of a string object stored on disk has the first two bits
 * set, the remaining six bits specify a special encoding for the object
 * accordingly to the following defines: */
#define RDB_ENC_INT8 0        /* 8 bit signed integer */
#define RDB_ENC_INT16 1       /* 16 bit signed integer */
#define RDB_ENC_INT32 2       /* 32 bit signed integer */
#define RDB_ENC_LZF 3         /* string compressed with FASTLZ */
/*#define RDB_ENC_GD 4           string is a gdcompressed entry */

/* quicklist node container formats */
#define QUICKLIST_NODE_CONTAINER_PLAIN 1
#define QUICKLIST_NODE_CONTAINER_PACKED 2

/* Module serialized values sub opcodes */
#define RDB_MODULE_OPCODE_EOF   0   /* End of module value. */
#define RDB_MODULE_OPCODE_SINT  1   /* Signed integer. */
#define RDB_MODULE_OPCODE_UINT  2   /* Unsigned integer. */
#define RDB_MODULE_OPCODE_FLOAT 3   /* Float. */
#define RDB_MODULE_OPCODE_DOUBLE 4  /* Double. */
#define RDB_MODULE_OPCODE_STRING 5  /* String. */

#define UNINIT_STREAM_ENTRIES_READ (-2)
#endif /*DEFINES_H*/
