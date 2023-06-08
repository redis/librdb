#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Rely only on API (and not internal parser headers) */
#include "../../api/librdb-api.h"
#include "../../api/librdb-ext-api.h"

#define UNUSED(x) (void)(x)

FILE* logfile;
char* logfilePath = "./rdb-convert.log";

static int getOptArg(int argc, char* argv[], int *at,  char *abbrvOpt, char *opt, char *token, int *flag, char **arg) {
    if ((strcmp(token, abbrvOpt) == 0) || (strcmp(token, opt) == 0)) {
        if (arg) {
            if ((*at) + 1 == argc) {
                fprintf(stderr, "%s (%s) requires one argument.", opt, abbrvOpt);
                exit(RDB_ERR_GENERAL);
            }
            *arg = argv[++(*at)];
        }
        if (flag) *flag = 1;
        return 1;
    } else {
        return 0;
    }
}

static void logger(RdbLogLevel l, const char *msg) {
    static char *logLevelStr[] = {
            [RDB_LOG_ERROR]    = ":: ERROR ::",
            [RDB_LOG_WARNNING] = ":: WARN  ::",
            [RDB_LOG_INFO]     = ":: INFO  ::",
            [RDB_LOG_DBG]      = ":: DEBUG ::",
    };
    fprintf(logfile, "%s %s\n", logLevelStr[l], msg);
}

static void printUsage() {
    printf("Usage: rdb-convert /path/to/dump.rdb [COMMON_OPT] <json|resp> [SPECIFIC_OPT] \n");
    printf("Common Options:\n");
    printf("\t-l|--log-file <PATH>         Path to log-file (Default: './rdb-convert.log'\n\n");

    printf("Options specific to 'json':\n");
    printf("\t-o|--output <FILE>           Output to file. Or stdout, if not specified\n");
    printf("\t-w|--with-aux-values         Add auxiliary values\n\n");

    printf("Options specific to 'resp':\n");
    printf("\t-o|--output <FILE>           Output to File. Or to stdout if {-o, -h, -p} not specified\n");
    printf("\t-h|--hostname <HOSTNAME>     Server hostname (default: 127.0.0.1)\n");
    printf("\t-p|--port <PORT>             Server port\n");
    printf("\t-r|--support-restore         use RESTORE command when possible\n");
    printf("\t-t|--target-redis-ver <VER>  Target Redis version\n");
    printf("\t-x|--target-rdb-ver <VER>    Target RDB version\n");
}

static RdbRes convertJson(RdbParser *parser, char *input, int argc, char **argv) {
    RdbStatus status;
    char *output = NULL;/*default:stdout*/
    int withAuxValues = 0; /*without*/

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", opt, NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-w", "--with-aux-values", opt, &withAuxValues, NULL)) continue;

        fprintf(stderr, "Invalid specific JSON argument: %s\n", opt);
        printUsage();
        return RDB_ERR_GENERAL;
    }

    RdbxToJsonConf conf = {
            .level = RDB_LEVEL_DATA,
            .encoding = RDBX_CONV_JSON_ENC_PLAIN,
            .skipAuxField = !(withAuxValues),
            .flatten = 1,
    };

    if (RDBX_createReaderFile(parser, input) == NULL)
        return RDB_ERR_GENERAL;

    if (RDBX_createHandlersToJson(parser, output, &conf) == NULL)
        return RDB_ERR_GENERAL;

    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);

    return (status != RDB_STATUS_OK) ? RDB_ERR_GENERAL : RDB_OK;
}

static RdbRes convertResp(RdbParser *parser, char *input, int argc, char **argv) {
    RdbStatus status;
    RdbxToResp *rdbToResp;
    char *hostname = "127.0.0.1";
    char *portStr=NULL, *dstRdbVersion=NULL;
    char *output = NULL;/*default:stdout*/

    RdbxToRespConf conf = { 0 };

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", opt, NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-h", "--hostname", opt, NULL, &hostname)) continue;
        if (getOptArg(argc, argv, &at, "-p", "--port", opt, NULL, &portStr)) continue;
        if (getOptArg(argc, argv, &at, "-r", "--support-restore", opt, &(conf.supportRestore), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-t", "--target-redis-ver", opt, NULL, &(conf.restore.dstRedisVersion))) continue;
        if (getOptArg(argc, argv, &at, "-x", "--target-rdb-ver", opt, NULL, &dstRdbVersion)) continue;

        fprintf(stderr, "Invalid specific RESP argument: %s\n", opt);
        printUsage();
        return RDB_ERR_GENERAL;
    }

    if (RDBX_createReaderFile(parser, input) == NULL)
        return RDB_ERR_GENERAL;

    if ((rdbToResp = RDBX_createHandlersToResp(parser, &conf)) == NULL)
        return RDB_ERR_GENERAL;

    if ((dstRdbVersion) && ((conf.restore.dstRdbVersion = atoi(dstRdbVersion)) == 0))
        return RDB_ERR_GENERAL;

    if (portStr != NULL) {
        int port = atoi(portStr);
        if (port == 0) {
            printf("Invalid port: %s\n", portStr);
            return RDB_ERR_GENERAL;
        }
        if (RDBX_createRespToTcpLoader(parser, rdbToResp, hostname, port) == NULL)
            return RDB_ERR_GENERAL;
    } else {
        if (RDBX_createRespFileWriter(parser, rdbToResp, output) == NULL)
            return RDB_ERR_GENERAL;
    }

    while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);

    return (status != RDB_STATUS_OK) ? RDB_ERR_GENERAL : RDB_OK;
}

int main(int argc, char **argv)
{
    int at;
    RdbRes res;
    RdbRes (*convertCmd)(RdbParser *p, char *input, int argc, char **argv) = convertJson;

    if (argc < 3) {
        printf("Invalid input.\n");
        printUsage();
        return 1;
    }

    /* first argument is input file */
    char *input = argv[1];

    /* common options (until json/resp command found)*/
    for (at = 2; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-l", "--log-file", opt, NULL, &logfilePath))
            continue;
        if (strcmp(opt, "json") == 0) {
            convertCmd = convertJson; /* subcommand */
            break;
        } else if (strcmp(opt, "resp") == 0) {
            convertCmd = convertResp; /* subcommand */
            break;
        }

        fprintf(stderr, "Invalid common command argument: %s\n", opt);
        printUsage();
        return RDB_ERR_GENERAL;
    }

    if (at == argc) { /* didn't find any subcommand (json / resp) */
        printUsage();
        return RDB_ERR_GENERAL;
    }

    if ((logfile = fopen(logfilePath, "w")) == NULL) {
        printf("Error opening log file for writing: %s \n", logfilePath);
        return RDB_ERR_GENERAL;
    }

    /* create the parser and attach it a file reader */
    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_INFO);
    RDB_setLogger(parser, logger);

    res = convertCmd(parser, input, argc - at, argv + at);

    if (RDB_OK != RDB_getErrorCode(parser))
        res = RDB_getErrorCode(parser);

    RDB_deleteParser(parser);
    fclose(logfile);
    return res;
}
