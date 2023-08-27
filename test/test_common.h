#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../api/librdb-api.h"  /* RDB library header */
#include "../api/librdb-ext-api.h" /* RDB library extension header */

#define UNUSED(...) unused( (void *) NULL, ##__VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}

#define QUOTE(...) #__VA_ARGS__

#define DUMP_FOLDER(file) "./test/dumps/"file
#define TMP_FOLDER(file) "./test/tmp/"file

/* system() commands */
void runSystemCmd(const char *cmdFormat, ...);
void runSystemCmdRetry(int seconds, const char *cmdFormat, ...);

/* assert */
void assert_json_equal(const char *f1, const char *f2, int ignoreListOrder);
void assert_payload_file(const char *filename, char *expPayload, char *charsToSkip);

/* setup external Redis Server */
extern int redisPort;
extern const char *redisInstallFolder;
int isExternalRedisSupported();
void setupRedisServer();
void teardownRedisServer();

/* test groups */
int group_rdb_to_redis();
int group_test_rdb_cli();
int group_rdb_to_resp();
int group_main();
int group_rdb_to_json();
int group_mem_management();
int group_pause();
int group_bulk_ops();
int group_test_resp_reader();

/* simulate external malloc */
void *xmalloc(size_t size);
void *xclone(void *str, size_t len);
void xfree(void *ptr);
void *xrealloc(void *ptr, size_t size);

char *readFile(const char *filename, size_t *len);
void cleanTmpFolder();
void setEnvVar (const char *name, const char *val);
