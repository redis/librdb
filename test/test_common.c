/* feature-test-macros POSIX.1-2008 for: kill(), strdup(), setenv() */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <dirent.h>
#include "../deps/hiredis/hiredis.h"
#include "test_common.h"
#include "../src/ext/utils.c" /* for printHexDump() */

/* Live Redis server for some of the tests (Optional) */
redisContext *redisConnContext = NULL;
int          redisPort=0;
pid_t        redisPID = 0;

void runSystemCmd(const char *cmdFormat, ...) {
    char cmd[1024];
    va_list args;
    va_start(args, cmdFormat);
    vsnprintf(cmd, sizeof(cmd)-1, cmdFormat, args);
    va_end(args);

    //printf ("runSystemCmd(): %s\n", cmd);
    int res = system(cmd);
    if (res) {
        printf("\nFailed to run command: %s\n", cmd);
        assert_true(0);
    }
}

char *readFile(const char *filename,  size_t *length) {
    FILE* fp;
    char* str;
    size_t size;

    assert_non_null(fp = fopen(filename, "r"));

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek (fp, 0, SEEK_SET);
    assert_non_null(str = (char*) malloc(size + 1));

    size_t readBytes = fread(str, 1, size, fp);
    assert_int_equal(readBytes, size);

    str[size] = '\0';
    fclose(fp);

    if (length) *length = size;

    return str;
}

void cleanTmpFolder() {
    const char *folder_path = "./test/tmp";

    DIR *dir = opendir(folder_path);
    assert_true(dir != NULL);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            (strcmp(entry->d_name, ".gitkeep") == 0))
            continue;

        char file_path[1024];
        snprintf(file_path, sizeof(file_path), "%s/%s", folder_path, entry->d_name);
        assert_true (remove(file_path) != -1);
    }

    closedir(dir);
}

void setEnvVar (const char *name, const char *val) {
    setenv(name, val, 1);
}

char *substring(char *str, size_t len, char *substr) {
    size_t sublen = strlen(substr);

    if (sublen > len)
        return NULL;

    for (size_t cmpFromOffest = 0; cmpFromOffest < len - sublen; cmpFromOffest++) {
        if (strncmp(&str[cmpFromOffest], substr, sublen) == 0) {
            return &str[cmpFromOffest];
        }
    }
    return NULL;
}

void assert_file_payload(const char *filename, char *expData, int expLen, MatchType matchType, int expMatch) {
    const char *matchTypeName, *errMsg;
    size_t filelen;
    char *filedata = readFile(filename, &filelen);
    int result=1;

    switch (matchType) {
        case M_PREFIX:
            matchTypeName = "prefix";
            errMsg = "Error: Prefix of file is not as expected";
            result = strncmp(filedata, expData, expLen);
            break;
        case M_ENTIRE:
            errMsg = "Error: File payload is not as expected";
            matchTypeName = "payload";
            result = strncmp(filedata, expData, expLen);
            break;
        case M_SUFFIX:
            errMsg = "Error: Suffix of file is not as expected";
            matchTypeName = "suffix";
            result = strncmp(filedata + filelen - expLen, expData, expLen);
            break;
        case M_SUBSTR:
            errMsg = "Error: File does not contains expected substring";
            matchTypeName = "substr";
            result = (substring(filedata, filelen, expData)) ? 0 : 1;
            break;
        default:
            assert_true(0);
            return;
    }

    if (((result != 0) && (expMatch)) || ((result == 0) && (!expMatch))) {
        char buf[10000];
        printf("%s\n---- file [%s] ----\n", errMsg, filename);
        printHexDump(filedata, filelen, buf, (int) sizeof(buf));
        printf("%s", buf);
        printf("\n---- Expected %s ----\n", matchTypeName);
        printHexDump(expData, expLen, buf, (int) sizeof(buf));
        printf("%s", buf);
        printf("\n------------\n");
        assert_true(0);
    }
    free(filedata);
}

/*** Setup Redis Server ***/

int findFreePort(int startPort, int endPort) {
    int reuse = 1;
    int port;

    for (port = startPort; port <= endPort; ++port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("Socket creation failed");
            exit(1);
        }

        /* ensure that Redis can immediately capture it without encountering failures or timeouts */
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
            perror("Setsockopt failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        int bindResult = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        close(sockfd);

        if (bindResult == 0) {
            return port; /* Found a free port */
        }
    }

    assert_true(0); /* No free port found within the range */
    return -1;
}

void cleanupRedisServer() {
    if (redisPID)
        kill(redisPID, SIGTERM);
}

size_t serializeRedisReply(const redisReply *reply, char *buffer, size_t bsize) {
    size_t written = 0;

    switch (reply->type) {
        case REDIS_REPLY_STRING:
        case REDIS_REPLY_STATUS:
        case REDIS_REPLY_ERROR:
            return snprintf(buffer, bsize, "%s", reply->str);
            break;
        case REDIS_REPLY_INTEGER:
            return snprintf(buffer, bsize, "%lld", reply->integer);
        case REDIS_REPLY_ARRAY:
            for (size_t i = 0; i < reply->elements; i++) {
                written += serializeRedisReply(reply->element[i], buffer + written, bsize - written);
                if (written + 1 >= bsize)
                    return written;
                if (i < reply->elements - 1)
                    written += snprintf(buffer + written, bsize - written, " ");
            }
            return written;
        default:
            assert_true(0);
            return 0;
    }
}

/*
 * For array-responses check 'expRsp' is a substring. Otherwise check match entirely.
 *
 * Return the response serialized
 */
char *sendRedisCmd(char *cmd, int expRetType, char *expRsp) {
    static char rspbuf[1000];

    assert_non_null(redisConnContext);

    redisReply *reply = redisCommand(redisConnContext, cmd);

    //printf ("Command:%s\n", cmd);

    assert_non_null(reply);
    assert_int_equal(reply->type, expRetType);

    size_t written = serializeRedisReply(reply, rspbuf, sizeof(rspbuf)-1);

    if (expRsp) {
        /* For complex responses, check `expRsp` is a substring. Otherwise, exact match */
        if (expRetType != REDIS_REPLY_ARRAY)
            assert_string_equal(reply->str, expRsp);
        else
            assert_non_null(substring(rspbuf, written, expRsp));
    }

    freeReplyObject(reply);
    return rspbuf;
}

void setupRedisServer(const char *installFolder) {
    pid_t pid = fork();
    assert_int_not_equal (pid, -1);

    redisPort = findFreePort(6500, 6600);

    if (pid == 0) { /* child */
        char redisPortStr[10], fullpath[256], testrdbModulePath[256];

        printf("Found free port to run Redis: %d\n", redisPort);

        snprintf(fullpath, sizeof(fullpath), "%s/redis-server", installFolder);
        snprintf(testrdbModulePath, sizeof(testrdbModulePath), "%s/../tests/modules/testrdb.so", installFolder);
        snprintf(redisPortStr, sizeof(redisPortStr), "%d", redisPort);

        /* if module testrdb.so exists (ci.yaml takes care to build testrdb), part
         * of redis repo testing, then load it for test_rdb_to_redis_module. The
         * test will run only if testrdb appear in the server "MODULE LIST",
         * otherwise skipped gracefully. */
        if (access(testrdbModulePath, F_OK) != -1) {
            execl(fullpath, fullpath,
                  "--port", redisPortStr,
                  "--dir", "./test/tmp/",
                  "--logfile", "./redis.log",
                  "--loadmodule", testrdbModulePath, "4",
                  (char *) NULL);
        } else {
            execl(fullpath, fullpath,
                  "--port", redisPortStr,
                  "--dir", "./test/tmp/",
                  "--logfile", "./redis.log",
                  (char *) NULL);
       }

        /* If execl returns, an error occurred! */
        perror("execl");
        exit(1);
    } else { /* parent */
        int retryCount = 3;

        redisConnContext = redisConnect("localhost", redisPort);
        while ((!redisConnContext) || (redisConnContext->err)) {

            if (redisConnContext) redisFree(redisConnContext);

            if (--retryCount == 0) {
                perror("Failed to run Redis Server");
                exit(1);
            }

            /* Sleep 50msec */
            struct timespec req = {0, 50000*1000}, rem;
            nanosleep(&req, &rem);

            redisConnContext = redisConnect("localhost", redisPort);
        }

        redisPID = pid;

        /* Close any subprocess in case of exit due to error flow */
        atexit(cleanupRedisServer);
    }
}

void teardownRedisServer() {
    if (redisConnContext) {
        assert_non_null(redisConnContext);
        assert_null(redisCommand(redisConnContext, "SHUTDOWN"));
        redisFree(redisConnContext);
        redisConnContext = NULL;
        wait(NULL);
    }
}

int isSetRedisServer() {
    return (redisConnContext != NULL);
}

/* Redis OSS does not support restoring module auxiliary data. This feature
 * is currently available only in Redis Enterprise. There are plans to bring
 * this functionality to Redis OSS in the near future. */
int isSupportRestoreModuleAux() {
    static int supported = -1;   /* -1=UNINIT, 0=NO, 1=YES */
    if (supported == -1) {
        char *res = sendRedisCmd("RESTOREMODAUX", REDIS_REPLY_ERROR, NULL);
        supported = (strstr( res, "wrong number of arguments" ) ) ? 1 : 0;
    }
    return supported;
}

/*** simulate external malloc with verification ***/

#define MAGIC_VALUE      0xDEADBEE

void *xmalloc(size_t size) {
    void *ptr = malloc(size + sizeof(int));
    assert_non_null(ptr);
    *(int *)ptr = MAGIC_VALUE;
    return (char *)ptr + sizeof(int);
}

void *xclone(void *str, size_t len) {
    void *ptr = xmalloc(len);
    memcpy(ptr, str, len);
    return ptr;
}

void xfree(void *ptr) {
    int *header = (int *)((char *)ptr - sizeof(int));
    assert_int_equal(*header, MAGIC_VALUE);
    free(header);
}

void *xrealloc(void *ptr, size_t size) {
    if (ptr == NULL)
        return xmalloc(size);

    int *header = (int *)((char *)ptr - sizeof(int));
    assert_int_equal(*header, MAGIC_VALUE);

    void *new_ptr = realloc(header, size + sizeof(int));
    assert_non_null(new_ptr);
    *(int *)new_ptr = MAGIC_VALUE;
    return (char *)new_ptr + sizeof(int);
}

/*** compare json files ***/

static void sanitize_json_line(char* line) {
    size_t length = strlen(line);

    /* remove \n from end of line, if exist */
    if (length > 0 && (line[length - 1] == '\n') ) {
        line[length - 1] = '\0';
        length--;
    }

    /* remove trailing spaces */
    while ((0 < length) && (line[length-1] == ' ')) --length;

    /* remove comma at the end of line, if exist */
    if (length > 0 && (line[length - 1] == ',') ) {
        line[length - 1] = '\0';
        length--;
    }

    size_t j = 0, i = 0;
    /* skip leading spaces */
    while ((i<length) && (line[i] == ' ')) ++i;
    /* shift the string to the start of line */
    while (i < length) line[j++] = line[i++];
    line[j] = '\0';
}

int compare_json_lines(const void* line1, const void* line2) {
    return strcmp(*(const char**)line1, *(const char**)line2);
}

static unsigned char xorstr(const char *str) {
    unsigned char result = 0;

    while (*str) {
        if ((*str != ' ') && (*str != '\t') )
        result ^= *str;
        str++;
    }

    return result;
}

/* sanitize, sort, and compare */
#define MAX_LINE_LENGTH  4096
void assert_json_equal(const char* filename1, const char* filename2, int ignoreListOrder) {
    char line1[MAX_LINE_LENGTH];
    char line2[MAX_LINE_LENGTH];
    char* lines1[MAX_LINE_LENGTH];
    char* lines2[MAX_LINE_LENGTH];
    int lineCount1 = 0;
    int lineCount2 = 0;
    int res = -1;

    FILE* file1 = fopen(filename1, "r");
    assert_non_null(file1);

    FILE* file2 = fopen(filename2, "r");
    assert_non_null(file2);

    while (fgets(line1, MAX_LINE_LENGTH, file1)) {
        sanitize_json_line(line1);
        if (strlen(line1) != 0)
            lines1[lineCount1++] = strdup(line1);
    }

    while (fgets(line2, MAX_LINE_LENGTH, file2)) {
        sanitize_json_line(line2);
        if (strlen(line2) != 0)
            lines2[lineCount2++] = strdup(line2);
    }

    if (lineCount1 != lineCount2) goto end_cmp;

    qsort(lines1, lineCount1, sizeof(char *), compare_json_lines);
    qsort(lines2, lineCount2, sizeof(char *), compare_json_lines);

    for (int i = 0; i < lineCount1; i++) {
        /* simplify cmp for ignoreListOrder */
        if ( ((ignoreListOrder) && (xorstr(lines1[i]) != xorstr(lines2[i]))) ||
             ((!ignoreListOrder) && (strcmp(lines1[i], lines2[i]) != 0)) )
        {
            printf("strcmp fail: [%s] [%s]\n", lines1[i], lines2[i]);
            goto end_cmp;
        }
    }

    res = 0;

end_cmp:
    for (int i = 0; i < lineCount1; i++)
        free(lines1[i]);
    for (int i = 0; i < lineCount2; i++)
        free(lines2[i]);

    fclose(file1);
    fclose(file2);

    if (res == 0) return;

    printf("Json files not equal.\n");
    printf("---- %s ----\n", filename1);
    char *f1 = readFile(filename1, NULL);
    printf ("%s", f1);
    free(f1);

    printf("\n---- %s ----\n", filename2);
    char *f2 = readFile(filename2, NULL);
    printf ("%s", f2);
    free(f2);
    printf("\n------------\n");

    assert_true(0);
}
