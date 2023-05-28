#include "test_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* server port to allocate for tests against live Redis */
int redisPort;

void runSystemCmd(const char *cmdFormat, ...) {
    char cmd[256];
    va_list args;
    va_start(args, cmdFormat);
    vsnprintf(cmd, sizeof(cmd)-1, cmdFormat, args);
    va_end(args);

    if (system(cmd)) {
        printf("\nFailed to run command: %s\n", cmd);
        exit(1);
    }
}

void runSystemCmdRetry(int seconds, const char *cmdFormat, ...) {
    char cmd[256];
    va_list args;
    va_start(args, cmdFormat);
    vsnprintf(cmd, sizeof(cmd)-1, cmdFormat, args);
    va_end(args);
    time_t startTime = time(NULL);
    do {
        if (system(cmd) == 0) return;
        usleep(10000);
    } while (difftime(time(NULL), startTime) < seconds);

    printf("\nFailed to run command: %s\n", cmd);
    exit(1);
}

static char* sanitizeData(char* str, char* charsToSkip) {
    int i, j;
    int len = strlen(str);
    char* output = str;

    if (!charsToSkip) charsToSkip = "";

    for (i = 0, j = 0; i < len; i++) {
        int skipChar = 0;

        for (int k = 0; charsToSkip[k] != '\0'; k++) {
            if (str[i] == charsToSkip[k])
                skipChar = 1;
        }
        if (!skipChar)
            output[j++] = str[i];
    }

    output[j] = '\0';
    return output;
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

void assert_payload_file(const char *filename, char *expPayload, char *charsToSkip) {
    char *filedata = readFile(filename, NULL);
    assert_string_equal( sanitizeData(expPayload, charsToSkip),
                         sanitizeData(filedata, charsToSkip));
    free(filedata);
}

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

/* sanitize, sort, and compare */
#define MAX_LINE_LENGTH  4096
void assert_json_equal(const char* filename1, const char* filename2) {
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

    for (int i = 0; i < lineCount1; i++)
        if (strcmp(lines1[i], lines2[i]) != 0) {
            printf ("strcmp fail: [%s] [%s]\n", lines1[i], lines2[i]);
            goto end_cmp;
        }

    res = 0;

end_cmp:
    for (int i = 0; i < lineCount1; i++)
        free(lines1[i]);
    for (int i = 0; i < lineCount2; i++)
        free(lines2[i]);

    fclose(file1);
    fclose(file2);

    if (!res) return;

    printf("Json files not equal.\n");
    printf("---- %s ----\n", filename1);
    char *f1 = readFile(filename1, NULL);
    printf ("%s", f1);
    printf("\n---- %s ----\n", filename2);
    char *f2 = readFile(filename2, NULL);
    printf ("%s", f2);
    printf("\n------------\n");
    free(f1);
    free(f2);
    assert_true(0);
}
