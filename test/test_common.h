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

void runSystemCmd(const char *cmdFormat, ...);
void runSystemCmdRetry(int seconds, const char *cmdFormat, ...);
char *readFile(const char *filename, size_t *len);
void assert_json_equal(const char *f1, const char *f2);
void assert_payload_file(const char *filename, char *expPayload, char *charsToSkip);
int findFreePort(int startPort, int endPort);

extern int group_rdb_to_loader(const char *redisServerFolder);
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

extern int redisPort;