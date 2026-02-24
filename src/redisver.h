/*
 * Redis to RDB Version Mapping
 * 
 * This table maps Redis versions to their corresponding RDB format versions.
 * Entries are ordered from newest to oldest Redis version.
 * Multiple Redis versions may share the same RDB format version.
 * 
 * This Helps determine which commands can be applied. Particularly crucial if 
 * support-restore being used as RESTORE is closely tied to specific RDB versions. 
 */

#ifndef REDIS_VER_H
#define REDIS_VER_H

#define VER_VAL(maj,min) ((maj) * 100 + (min))
#define VAL_MAJOR(val) ((val) / 100)
#define VAL_MINOR(val) ((val) % 100)

/* Redis Version Mapping */
typedef struct {
    const char *redisStr;
    unsigned int redis;
    int rdb;
} RedisToRdbVersion;

static const RedisToRdbVersion redisToRdbVersion[] = {
        {"8.6", VER_VAL(8,6), 13},
        {"7.4", VER_VAL(7,4), 12}, // + 8.0, 8.2, 8.4
        {"7.2", VER_VAL(7,2), 11},
        {"7.0", VER_VAL(7,0), 10},
        {"5.0", VER_VAL(5,0), 9},  // + 6.0, 6.2
        {"4.0", VER_VAL(4,0), 8},
        {"3.2", VER_VAL(3,2), 7},
        {"2.6", VER_VAL(2,6), 6},  // + 2.8
        {"2.4", VER_VAL(2,4), 5},
};

#define REDIS_TO_RDB_VERSION_COUNT (sizeof(redisToRdbVersion) / sizeof(redisToRdbVersion[0]))
#define LIBRDB_SUPPORT_MAX_RDB_VER (redisToRdbVersion[0].rdb)

#endif /* REDIS_VER_H */
