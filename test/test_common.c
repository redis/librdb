/* feature-test-macros POSIX.1-2008 for: kill(), strdup(), setenv() */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <dirent.h>
#include "../deps/hiredis/hiredis.h"
#include "../src/redisver.h"
#include "test_common.h"

/* Live Redis server for some of the tests (Optional) */
#define MAX_NUM_REDIS_INST         3

#define RDB_CLI_VALGRIND_LOG_FILE  "test/log/rdb-cli-valgrind.log"
#define RDB_CLI_CMD                "./bin/rdb-cli"
#define RDB_CLI_VALGRIND_CMD       "/usr/bin/valgrind --track-origins=yes --leak-check=full --leak-resolution=high --error-exitcode=1 --log-file="RDB_CLI_VALGRIND_LOG_FILE" "RDB_CLI_CMD

int          useValgrind = 0;
int          currRedisInst = -1;
redisContext *redisServersStack[MAX_NUM_REDIS_INST] = {0};
int          redisPort[MAX_NUM_REDIS_INST]= {0};
int          redisTlsPort[MAX_NUM_REDIS_INST] = {0};  /* TLS ports for TLS tests */
pid_t        redisPID[MAX_NUM_REDIS_INST] = {0};
const char   *redisInstallFolder  = NULL;
char         redisVer[10];
int          redisVersionInit, redisVerMajor, redisVerMinor;

void checkValgrindLog(const char *filename);

const char *getTargetRedisVersion(int *major, int *minor) {
    /* must be called only after setupRedisServer() */
    assert(redisVersionInit == 1);
    if (major) *major = redisVerMajor;
    if (minor) *minor = redisVerMinor;
    return redisVer;
}

/* Run provided command and return its output. Panic on failure. */
char *runSystemCmd(const char *cmdFormat, ...) {
    static char output[16384];
    char cmd[2048];
    va_list args;
    static int setup = 0;

    /* setup env-var, specifically $RDB_CLI_CMD, that might be used by the command */
    if (!setup) {
        setenv("RDB_CLI_CMD", (useValgrind) ? RDB_CLI_VALGRIND_CMD : RDB_CLI_CMD, 1);
        setup = 1;
    }

    va_start(args, cmdFormat);
    vsnprintf(cmd, sizeof(cmd)-1, cmdFormat, args);
    va_end(args);

    /* remove any valgrind log file leftover from previous test */
    if (useValgrind) remove(RDB_CLI_VALGRIND_LOG_FILE);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("\nFailed to run command: %s\n", cmd);
        assert_true(0);
    }

    /* Read the output into the buffer */
    size_t bytesRead = fread(output, 1, sizeof(output) - 1, fp);
    output[bytesRead] = '\0';

    int res = pclose(fp);
    if (res) {
        printf("Failed to run command: %s\n", cmd);
        assert_true(0);
    }

    /* Confirm no errors when running 'rdb-cli' with 'valgrind'. Note: We check valgrind
     * log due to potential issues with '--error-exitcode=1' and pipelines ('|'). */
    if (useValgrind && strstr(cmd, "$RDB_CLI_CMD"))
        checkValgrindLog(RDB_CLI_VALGRIND_LOG_FILE);

    return output;
}

char *readFile(const char *filename,  size_t *length, char *ignoredCh) {
    FILE* fp;
    char* str;
    size_t size, i = 0;

    assert_non_null(fp = fopen(filename, "r"));

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek (fp, 0, SEEK_SET);
    assert_non_null(str = (char*) malloc(size + 1));

    char ch;
    while (fread(&ch, 1, 1, fp) == 1) {
        int incr = 1;
        str[i] = ch;
        for (int j = 0 ; (ignoredCh) && (ignoredCh[j] != '\0') && (incr) ; ++j)
            incr = (ignoredCh[j] == ch) ? 0 : 1;
        i += incr;
    }

    str[i] = '\0';
    fclose(fp);

    if (length) *length = i;
    return str;
}

void cleanTmpFolder(void) {
    const char *folder_path = "./test/tmp";

    DIR *dir = opendir(folder_path);
    if (dir == NULL) {
        printf("Failed to open directory: %s\n", folder_path);
        assert_true(0);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            (strcmp(entry->d_name, ".gitkeep") == 0))
            continue;

        char file_path[1024];
        snprintf(file_path, sizeof(file_path), "%s/%s", folder_path, entry->d_name);
        assert_true (remove(file_path) == 0);
    }

    closedir(dir);
}

void setEnvVar(const char *name, const char *val) {
    setenv(name, val, 1);
}

char *substring(char *str, size_t len, char *substr) {
    size_t sublen = strlen(substr);

    if (sublen > len)
        return NULL;

    for (size_t cmpFromOffest = 0; cmpFromOffest <= len - sublen; cmpFromOffest++) {
        if (strncmp(&str[cmpFromOffest], substr, sublen) == 0) {
            return &str[cmpFromOffest];
        }
    }
    return NULL;
}

void assert_file_payload(const char *filename, char *expData, int expLen, MatchType matchType, int expMatch) {
    const char *matchTypeName, *errMsg;
    size_t filelen;
    char *filedata = readFile(filename, &filelen, NULL);
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
        char buf[8192];
        printf("%s\n---- file [%s] ----\n", errMsg, filename);
        printHexDump(filedata, filelen, buf, (int) sizeof(buf));
        printf("%s", buf);
        printf("\n---- Expected %s %s ----\n", matchTypeName, (expMatch) ? "" : "NOT to match");
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

void cleanupRedisServer(void) {
    for (int i=0 ; i <=currRedisInst ; ++i ) {
        if (redisPID[i])
            kill(redisPID[i], SIGTERM);
    }

}

size_t serializeRedisReply(const redisReply *reply, char *buffer, size_t bsize) {
    size_t written = 0;

    switch (reply->type) {
        case REDIS_REPLY_NIL:
            return 0; /* nothing to write */
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
            printf("serializeRedisReply() : Unknown reply type: %d\n", reply->type);
            assert_true(0);
            return 0;
    }
}

/*
 * For array-responses check 'expRsp' is a substring. Otherwise check match entirely.
 *
 * Return the response serialized
 */
char *sendRedisCmd(const char *cmd, int expRetType, char *expRsp) {
    static char rspbuf[1024];

    assert_int_not_equal(currRedisInst, -1);

    redisReply *reply = redisCommand(redisServersStack[currRedisInst], cmd);

    //printf ("Command:%s\n", cmd);

    assert_non_null(reply);
    assert_int_equal(reply->type, expRetType);

    size_t written = serializeRedisReply(reply, rspbuf, sizeof(rspbuf)-1);

    /* Check if the response contains the expected substring */
    if (expRsp) {
        if (expRetType == REDIS_REPLY_INTEGER) {
            char str[21];
            sprintf(str, "%lld", reply->integer);
            assert_string_equal(str, expRsp);
        } else if (expRetType != REDIS_REPLY_ARRAY) {
            assert_string_equal(reply->str, expRsp);
        } else {
            if (NULL == substring(rspbuf, written, expRsp)) {
                printf("Error: Response does not contain expected substring.\n");
                printf("Actual Response: %s\n", rspbuf);
                printf("Expected Substring: %s\n", expRsp);
                assert_true(0);
            }
        }
    }

    freeReplyObject(reply);
    return rspbuf;
}

void setRedisInstallFolder(const char *path) {
    redisInstallFolder = path;
}

/* Extract Redis version.  Aborts on any failure. */
void get_redis_version(redisContext *c, int *majorptr, int *minorptr) {
#define REDIS_VERSION_FIELD "redis_version:"
    redisReply *reply;
    char *eptr, *s, *e;
    int major, minor;

    reply = redisCommand(c, "INFO");
    if (reply == NULL || c->err || reply->type != REDIS_REPLY_STRING)
        goto abort;
    if ((s = strstr(reply->str, REDIS_VERSION_FIELD)) == NULL)
        goto abort;

    s += strlen(REDIS_VERSION_FIELD);

    /* We need a field terminator and at least 'x.y.z' (5) bytes of data */
    if ((e = strstr(s, "\r\n")) == NULL || (e - s) < 5)
        goto abort;

    /* Extract version info */
    major = strtol(s, &eptr, 10);
    if (*eptr != '.') goto abort;
    minor = strtol(eptr+1, NULL, 10);

    /* Push info the caller wants */
    if (majorptr) *majorptr = major;
    if (minorptr) *minorptr = minor;

    freeReplyObject(reply);
    return;

    abort:
    freeReplyObject(reply);
    fprintf(stderr, "Error:  Cannot determine Redis version, aborting\n");
    exit(1);
}

#define MAX_ARGS 50
int setupRedisServer(const char *extraArgs, int useTls) {
    if (!redisInstallFolder) return 0;

    const char *_extraArgs = (extraArgs) ? extraArgs : "--loglevel verbose";

    int port = findFreePort(6500, 6600);
    int tlsPort = 0;  /* TLS port if TLS is enabled */

    /* If TLS is requested, find a second port for TLS (different from the regular port) */
    if (useTls) {
        tlsPort = findFreePort(port + 1, 6600);
        if (tlsPort == -1) {
            /* If no port found after 'port', try before it */
            tlsPort = findFreePort(6500, port - 1);
        }
    }

    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0) { /* child */
        char redisPortStr[10], tlsPortStr[10];
        char fullpath[PATH_MAX], testrdbModulePath[PATH_MAX], testKeyMetaModulePath[PATH_MAX];

        snprintf(fullpath, sizeof(fullpath), "%s/redis-server", redisInstallFolder);
        snprintf(redisPortStr, sizeof(redisPortStr), "%d", port);

        // Tokenize extraArgs and build the arguments list
        char *args[MAX_ARGS];
        int argIndex = 0;

        args[argIndex++] = fullpath;
        args[argIndex++] = "--port";
        args[argIndex++] = redisPortStr;

        /* If TLS is requested, add TLS port and configuration */
        if (useTls) {
            /* For TLS mode: enable both regular port (for test framework) and TLS port (for TLS tests) */
            snprintf(tlsPortStr, sizeof(tlsPortStr), "%d", tlsPort);
            args[argIndex++] = "--tls-port";
            args[argIndex++] = tlsPortStr;    /* TLS port for TLS tests */
            args[argIndex++] = "--tls-cert-file";
            args[argIndex++] = "../tls/server.crt";
            args[argIndex++] = "--tls-key-file";
            args[argIndex++] = "../tls/server.key";
            args[argIndex++] = "--tls-ca-cert-file";
            args[argIndex++] = "../tls/ca.crt";
            args[argIndex++] = "--tls-auth-clients";
            args[argIndex++] = "no";
        }

        args[argIndex++] = "--dir";
        args[argIndex++] = "./test/tmp/";
        args[argIndex++] = "--logfile";
        args[argIndex++] = "./redis.log";

        /* Load testrdb module if exists */
        snprintf(testrdbModulePath, 
            sizeof(testrdbModulePath), 
            "%s/../tests/modules/testrdb.so", 
            redisInstallFolder);
        if (access(testrdbModulePath, F_OK) != -1) {
            args[argIndex++] = "--loadmodule";
            args[argIndex++] = testrdbModulePath;
            args[argIndex++] = "6"; /* 6 = CONF_AUX_OPTION_BEFORE_KEYSPACE | CONF_AUX_OPTION_AFTER_KEYSPACE */
        }
        
        /* Load test_keymeta module if exists */
        snprintf(testKeyMetaModulePath,
            sizeof(testKeyMetaModulePath),
            "%s/../tests/modules/test_keymeta.so",
            redisInstallFolder);
        if (access(testKeyMetaModulePath, F_OK) != -1) {
            args[argIndex++] = "--loadmodule";
            args[argIndex++] = testKeyMetaModulePath;
        }

        /* Tokenize extraArgs and add to the arguments list */
        char *extraArgsCopy = strdup(_extraArgs);
        char *token = strtok(extraArgsCopy, " ");
        while (token && argIndex < MAX_ARGS - 1) {
            args[argIndex++] = token;
            token = strtok(NULL, " ");
        }
        args[argIndex] = NULL;

        execvp(fullpath, args);

        /* If execvp returns, an error occurred */
        perror("execvp");
        exit(1);
    } else { /* parent */
        int retryCount = 3;
        static char *prefixVer = "";

        redisContext *redisConnContext = redisConnect("localhost", port);
        while ((!redisConnContext) || (redisConnContext->err)) {

            if (redisConnContext) redisFree(redisConnContext);

            if (--retryCount == 0) {
                /* Failed to connect - kill the child process and return failure */
                kill(pid, SIGTERM);
                waitpid(pid, NULL, 0);
                return 0;
            }

            /* Sleep 500msec */
            struct timespec req = {0, 500000*1000}, rem;
            nanosleep(&req, &rem);

            redisConnContext = redisConnect("localhost", port);
        }

        assert_true(++currRedisInst<MAX_NUM_REDIS_INST);
        redisPort[currRedisInst] = port;
        redisTlsPort[currRedisInst] = tlsPort;  /* Store TLS port (0 if TLS not enabled) */
        redisServersStack[currRedisInst] = redisConnContext;
        redisPID[currRedisInst]  = pid;

        if (!redisVersionInit) {
            get_redis_version(redisConnContext, &redisVerMajor, &redisVerMinor);
            snprintf(redisVer, sizeof(redisVer), "%d.%d", redisVerMajor, redisVerMinor);
            if ((redisVerMajor == 255) && (redisVerMinor == 255)) {/* unstable version? */
                strncpy(redisVer, redisToRdbVersion[0].redisStr, sizeof(redisVer));
                prefixVer = "Unresolved Version. Assumed ";
                redisVerMajor = VAL_MAJOR(redisToRdbVersion[0].redis);
                redisVerMinor = VAL_MINOR(redisToRdbVersion[0].redis);
            }
            redisVersionInit = 1;
        }

        if (useTls) {
            printf(">> Redis Server(%d) started on port %d (TLS port %d) with PID %d (%sVersion=%s)\n",
                   currRedisInst, port, tlsPort, pid, prefixVer, redisVer);
        } else {
            printf(">> Redis Server(%d) started on port %d with PID %d (%sVersion=%s)\n",
                   currRedisInst, port, pid, prefixVer, redisVer);
        }

        /* Close any subprocess in case of exit due to error flow */
        atexit(cleanupRedisServer);
        return 1;
    }
}

void teardownRedisServer(void) {
    if (currRedisInst>=0) {
        redisContext *ctx = redisServersStack[currRedisInst];
        assert_non_null(ctx);
        assert_null(redisCommand(ctx, "SHUTDOWN"));
        redisFree(ctx);
        --currRedisInst;
        wait(NULL);
    }
}

int isSetRedisServer(void) {
    return (currRedisInst>=0);
}

int getRedisPort(void) {
    assert_true(currRedisInst>=0);
    return redisPort[currRedisInst];
}

int getRedisTlsPort(void) {
    assert_true(currRedisInst>=0);
    return redisTlsPort[currRedisInst];
}

void setValgrind(void) {
    useValgrind = 1;
}

/* Setup Redis server with TLS enabled - returns 1 on success, 0 on failure
 * Redis will listen on both regular port (for test framework) and TLS port (for TLS tests) */
int setupRedisServerTls(const char *extraArgs) {
    if (!redisInstallFolder) {
        fprintf(stderr, "Warning: LIBRDB_REDIS_FOLDER not set. Skipping TLS tests.\n");
        return 0;
    }

    /* Try to start Redis with TLS enabled - will return 0 if it fails */
    int result = setupRedisServer(extraArgs, 1);  /* 1 = enable TLS */

    if (!result) {
        fprintf(stderr, "Warning: Redis did not start successfully with TLS. "
                        "This likely means Redis was not compiled with TLS support (BUILD_TLS=yes). "
                        "Skipping TLS tests.\n");
    }

    return result;
}

void checkValgrindLog(const char *filename) {
    const char *expectedSummary = "ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n";
    char buffer[512];
    FILE *file;

    if ( (file = fopen(filename, "r")) == NULL) return;

    /* Read the file line by line until the end */
    while (fgets(buffer, sizeof(buffer), file) != NULL);
    fclose(file);

    /* summary string appear at the last line, after "==<PID>==" and a space */
    char *spaceAt = strchr(buffer, ' ');
    if ((spaceAt == NULL) || (strcmp(spaceAt+1, expectedSummary) != 0)) {
        char *f = readFile(filename, NULL, NULL);
        printf ("rdb-cli failure:\n%s", f);
        free(f);
        assert_true(0);
    }
}

/* Redis OSS does not support restoring module auxiliary data. This feature
 * is currently available only in Redis Enterprise. There are plans to bring
 * this functionality to Redis OSS in the near future. */
int isSupportRestoreModuleAux(void) {
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

void sanitizeString(char* str, const char* charSet) {
    int j = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (strchr(charSet, str[i]) == NULL) {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
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

/*
 * Start a python service that reads JSON filename from its STDIN, generates its
 * signature, ignoring elements order, and prints SHA256 signature to its STDOUT.
 * The reason it is running as a service is to avoid the overhead of starting a
 * new process for each evaluation and the intensive use of it.
 */
#define BUFFER_SIZE 1024
static int pipe_in[2], pipe_out[2];
static pid_t pid = -1;
void start_json_sign_service(void) {
    if (pipe(pipe_in) == -1 || pipe(pipe_out) == -1) {
        perror("pipe failed");
        exit(1);
    }

    if ( (pid = fork()) == -1) {
        perror("fork failed");
        exit(1);
    }

    if (pid == 0) {
        /*child*/
        close(pipe_in[1]);  /* Close write end of pipe_in */
        close(pipe_out[0]); /* Close read end of pipe_out */
        dup2(pipe_in[0], STDIN_FILENO); /* Redirect child STDIN */
        dup2(pipe_out[1], STDOUT_FILENO); /* Redirect child STDOUT */
        /* now replace child process with python service */
        execlp("python3", "python3", "./test/json_signature_generator.py", NULL);
        perror("execlp");
        exit(1);
    } else {
        /*Parent*/
        close(pipe_in[0]);  /* Close read end of pipe_in */
        close(pipe_out[1]); /* Close write end of pipe_out */
    }
}

int cmp_json_signatures(const char* filename1, const char* filename2) {
    /* Run service if not already running */
    if (pid == -1)
        start_json_sign_service();

    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE, "%s\n", filename1);
    write(pipe_in[1], buffer, strlen(buffer));

    ssize_t bytes_read = read(pipe_out[0], buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        perror("read");
        return 0;
    }
    buffer[bytes_read] = '\0'; /* Null-terminate the string */
    char signature1[BUFFER_SIZE];
    strcpy(signature1, buffer);

    snprintf(buffer, BUFFER_SIZE, "%s\n", filename2);
    write(pipe_in[1], buffer, strlen(buffer));

    bytes_read = read(pipe_out[0], buffer, BUFFER_SIZE - 1);

    /* Verify that the signature is of the expected length (SHA256) */
    if (bytes_read != 65) {
        printf("strlen(buffer)=%ld %s\n", strlen(buffer), buffer);
        perror("read");
        return 0;
    }
    buffer[bytes_read] = '\0'; /* Null-terminate the string */
    char signature2[BUFFER_SIZE];
    strcpy(signature2, buffer);

    /* Compare signatures */
    if (strcmp(signature1, signature2) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void cleanup_json_sign_service(void) {
    if (pid != -1) {
        close(pipe_in[1]);
        close(pipe_out[0]);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        pid = -1;
    }
}

void assert_json_equal(const char* filename1, const char* filename2, int ignoreListOrder) {
    UNUSED(ignoreListOrder);

    ASSERT_TRUE(access(filename1, F_OK) != -1, "Failed to open file: %s", filename1);
    ASSERT_TRUE(access(filename2, F_OK) != -1, "Failed to open file: %s", filename2);

    if (cmp_json_signatures(filename1, filename2))
        return;

    printf("---- %s ----\n", filename1);
    char *f1 = readFile(filename1, NULL, NULL);
    printf ("%s", f1);
    free(f1);

    printf("\n---- %s ----\n", filename2);
    char *f2 = readFile(filename2, NULL, NULL);
    printf ("%s", f2);
    free(f2);
    printf("\n------------\n");

    assert_true(0);
}

/* printHexDump() Generates a formatted hexadecimal and ASCII representation of binary
 * data. Given a memory address and its length, it produces a human-readable obuf,
 * displaying byte offsets in hexadecimal and replacing non-printable characters with
 * dots ('.').
 *
 * Returns how many bytes written to obuf buffer. -1 Otherwise.
 *
 * Output example for input: "A123456789B123456789C123456789D123456789"
 *    000000  41 31 32 33 34 35 36 37    38 39 42 31 32 33 34 35  A1234567  89B12345
 *    000010  36 37 38 39 43 31 32 33    34 35 36 37 38 39 44 31  6789C123  456789D1
 *    000020  32 33 34 35 36 37 38 39                             23456789
 */
int printHexDump(const char *input, size_t len, char *obuf, int obuflen) {
    size_t i;
    int iout=0, j, llen = 16; /* line len */
    unsigned char *buff = (unsigned char *)malloc(llen + 10);

    if (input == NULL || len <= 0 || obuf == NULL || obuflen < 200 || obuflen > 0xFFFFFF) {
        free(buff);
        return -1;
    }

    for (i = 0, j = 0; (i < len) && (iout + 100 < obuflen) ; i++) {
        if ((i % llen) == 0) {
            if (i > 0) {
                buff[j] = '\0';
                iout += snprintf(obuf + iout, obuflen - iout, "  %s\n", buff);
            }
            iout += snprintf(obuf + iout, obuflen - iout, "%06zx ", i);
            j = 0;
        }

        if (((int)i % llen) == (llen / 2)) { /* middle of the line */
            iout += snprintf(obuf + iout, obuflen - iout, "   ");
            buff[j++] = ' ';
            buff[j++] = ' ';
        }

        iout += snprintf(obuf + iout, obuflen - iout, " %02x", (unsigned char)input[i]);
        buff[j++] = (isprint(input[i])) ? input[i] : '.';
    }

    /* pad the last line */
    for (; (i % llen) != 0; i++) {
        iout += snprintf(obuf + iout, obuflen - iout, "   ");
        if (( (int)i % llen) == (llen / 2)) {
            iout += snprintf(obuf + iout, obuflen - iout, "   ");
        }
    }

    buff[j] = '\0';
    iout += snprintf(obuf + iout, obuflen - iout, "  %s\n", buff);
    if (i < len)
        iout += snprintf(obuf + iout, obuflen - iout, "...");
    free(buff);
    return iout;
}
