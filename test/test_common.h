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

#define PATH_DUMP_FOLDER(file) "./test/dumps/"file
#define PATH_TMP_FOLDER(file) "./test/tmp/"file

void assert_json_file(const char *filename, char *expJson);
void parseBuffOneCharEachTime(RdbParser *p, unsigned char *buff, size_t size, int isEOF);
void readFileToBuff(const char* filename, unsigned char** buffer, size_t* length);

void testVariousCases(const char *rdbfile,
                      const char *jsonfile,
                      char *expJson,
                      RdbHandlersLevel parseLevel);

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
