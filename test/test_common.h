#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../deps/hiredis/hiredis.h"
#include "../api/librdb-api.h"  /* RDB library header */
#include "../api/librdb-ext-api.h" /* RDB library extension header */

#define UNUSED(...) unused( (void *) NULL, __VA_ARGS__);
static inline void unused(void *dummy, ...) { (void)(dummy);}

#define DUMP_FOLDER(file) "./test/dumps/"file
#define TMP_FOLDER(file) "./test/tmp/"file

#define STR_AND_SIZE(str) str, (sizeof(str)-1)

typedef enum MatchType {
    M_PREFIX,
    M_ENTIRE,
    M_SUFFIX,
    M_SUBSTR
} MatchType;

/* system() commands */
void runSystemCmd(const char *cmdFormat, ...);

/* assert */
void assert_json_equal(const char *f1, const char *f2, int ignoreListOrder);

/* Test against Redis Server */
void setRedisInstallFolder(const char *path);
int getRedisPort(void);
void setupRedisServer(const char *extraArgs);
void teardownRedisServer(void);
int isSetRedisServer(void);
char *sendRedisCmd(char *cmd, int expRetType, char *expRsp);
int isSupportRestoreModuleAux(void);

/* test groups */
int group_rdb_to_redis(void);
int group_test_rdb_cli(void);
int group_rdb_to_resp(void);
int group_examples(void);
int group_main(void);
int group_rdb_to_json(void);
int group_mem_management(void);
int group_pause(void);
int group_bulk_ops(void);
int group_test_resp_reader(void);

/* simulate external malloc */
void *xmalloc(size_t size);
void *xclone(void *str, size_t len);
void xfree(void *ptr);
void *xrealloc(void *ptr, size_t size);

char *readFile(const char *filename, size_t *len);
void cleanTmpFolder(void);
void setEnvVar (const char *name, const char *val);
char *substring(char *str, size_t len, char *substr);
void assert_file_payload(const char *filename, char *expData, int expLen, MatchType matchType, int expMatch);

int printHexDump(const char *addr, size_t len, char *obuf, int obuflen);
