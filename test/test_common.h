#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../api/librdb-api.h"  /* RDB library header */
#include "../api/librdb-ext-api.h" /* RDB library extension header */

#define UNUSED(...) unused( (void *) NULL, ##__VA_ARGS__);
inline void unused(void *dummy, ...) { (void)(dummy);}

#define QUOTE(...) #__VA_ARGS__

#define DUMP_FOLDER(file) "./test/dumps/"file
#define TMP_FOLDER(file) "./test/tmp/"file

/* system() commands */
void runSystemCmd(const char *cmdFormat, ...);
void runSystemCmdRetry(int seconds, const char *cmdFormat, ...);

/* assert */
void assert_json_equal(const char *f1, const char *f2);
void assert_payload_file(const char *filename, char *expPayload, char *charsToSkip);

/* setup external Redis Server */
extern int redisPort;
extern const char *redisInstallFolder;
int isExternalRedisSupported();
void setupRedisServer();
void teardownRedisServer();

/* test groups */
extern int group_rdb_to_loader();
extern int group_test_cli();
extern int group_rdb_to_resp();
extern int group_main(void);
extern int group_rdb_to_json(void);
extern int group_mem_management(void);
extern int group_pause(void);
extern int group_bulk_ops(void);

/* simulate external malloc */
void *xmalloc(size_t size);
void *xclone(void *str, size_t len);
void xfree(void *ptr);
void *xrealloc(void *ptr, size_t size);

char *readFile(const char *filename, size_t *len);
void cleanTmpFolder();
