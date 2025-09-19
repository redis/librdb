#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

/* Rely only on API (and not internal parser headers) */
#include "../../api/librdb-api.h"
#include "../../api/librdb-ext-api.h"

#define UNUSED(x) (void)(x)

FILE* logfile = NULL;
#define LOG_FILE_PATH_DEF "./rdb-cli.log"

/* common options to all FORMATTERS */
typedef struct Options {
    const char *logfilePath;
    int ignoreChecksum;
    int progressMb;  /* print progress every <progressMb> MB. Set to 0 if disabled */
    RdbRes (*formatFunc)(RdbParser *p, int argc, char **argv);
} Options;

void loggerWrap(RdbLogLevel l, const char *msg, ...);

/* This function checks if the current argument matches the given option or its
 * abbreviation. If a match is found and an argument is expected, it retrieves the
 * argument and stores it. It also sets a `flag` or read `extraArg` if provided.
 */
static int getOptArg(int argc, char* argv[], int *at, char *abbrvOpt, char *opt,
                     int *flag, const char **extraArg) {
    if ((strcmp(argv[*at], abbrvOpt) == 0) || (strcmp(argv[*at], opt) == 0)) {
        if (extraArg) {
            if ((*at) + 1 == argc) {
                fprintf(stderr, "%s (%s) requires one argument.", opt, abbrvOpt);
                exit(1);
            }
            *extraArg = argv[++(*at)];
        }
        if (flag) *flag = 1;
        return 1;
    } else {
        return 0;
    }
}

/* This function checks if the current argument matches the given option or its
 * abbreviation. If a match is found, it retrieves the argument, converts it to
 * an integer, and verifies that it is within the specified boundaries. It also
 * sets a `flag` if provided.
 */
static int getOptArgVal(int argc, char* argv[], int *at, char *abbrvOpt, char *opt,
                        int *flag, int *val, int min, int max) {
    const char *valStr;
    if (getOptArg(argc, argv, at,  abbrvOpt, opt, flag, &valStr)) {

        *val = atoi(valStr);

        /* check boundaries. Condition support also the limits INT_MAX and INT_MIN. */
        if (!((*val>=min) && (*val <=max))) {
            loggerWrap(RDB_LOG_ERR, "Value of %s (%s) must be a integer between %d and %d",
                       opt, abbrvOpt, min, max);
            exit(1);
        }
        return 1;
    }
    return 0;
}

static void logger(RdbLogLevel l, const char *msg) {
    static char *logLevelStr[] = {
            [RDB_LOG_ERR]  = "ERROR :",
            [RDB_LOG_WRN]  = "WARN  :",
            [RDB_LOG_INF]  = "INFO  :",
            [RDB_LOG_DBG]  = "DEBUG :",
    };

    if (logfile != NULL) {
        fprintf(logfile, "%s %s\n", logLevelStr[l], msg);
        fflush(logfile);
    }

    if (l == RDB_LOG_ERR)
        printf("%s %s\n", logLevelStr[l], msg);
}

void loggerWrap(RdbLogLevel l, const char *msg, ...) {
    char tmp[1024];
    va_list args;
    va_start(args, msg);
    vsnprintf(tmp, sizeof(tmp), msg, args);
    va_end(args);
    logger(l, tmp);
}

static void printUsage(int shortUsage) {
    if (shortUsage) {
        printf("Usage: rdb-cli /path/to/dump.rdb [OPTIONS] {json|resp|redis} [FORMAT_OPTIONS]\n");
        printf("For detailed usage, run command without arguments\n");
        return;
    }
    printf("[v%s] ", RDB_getLibVersion(NULL,NULL,NULL));
    printf("Usage: rdb-cli /path/to/dump.rdb [OPTIONS] {print|json|resp|redis} [FORMAT_OPTIONS]\n");
    printf("OPTIONS:\n");
    printf("\t-l, --log-file <PATH>         Path to the log file or stdout (Default: './rdb-cli.log')\n");
    printf("\t-i, --ignore-checksum         Ignore RDB file checksum verification\n");
    printf("\t-s, --show-progress <MBytes>  Show progress to STDOUT after every <MBytes> processed\n");
    printf("\t-k, --key <REGEX>             Include only keys that match REGEX\n");
    printf("\t-K  --no-key <REGEX>          Exclude all keys that match REGEX\n");
    printf("\t-t, --type <TYPE>             Include only selected TYPE {str|list|set|zset|hash|module|func}\n");
    printf("\t-T, --no-type <TYPE>          Exclude TYPE {str|list|set|zset|hash|module|func}\n");
    printf("\t-d, --dbnum <DBNUM>           Include only selected db number\n");
    printf("\t-D, --no-dbnum <DBNUM>        Exclude DB number\n");
    printf("\t-e, --expired                 Include only expired keys\n");
    printf("\t-E, --no-expired              Exclude expired keys\n\n");

    printf("FORMAT_OPTIONS ('print'):\n");
    printf("\t-a, --aux-val <FMT>           %%f=Auxiliary-Field, %%v=Auxiliary-Value (Default: \"\") \n");
    printf("\t-k, --key <FMT>               %%d=Db %%k=Key %%v=Value %%t=Type %%e=Expiry %%r=LRU %%f=LFU %%i=Items\n");
    printf("\t                              (Default: \"%%d,%%k,%%v,%%t,%%e,%%i\")\n");
    printf("\t-o, --output <FILE>           Specify the output file. If not specified, output to stdout\n\n");

    printf("FORMAT_OPTIONS ('json'):\n");
    printf("\t-i, --include <EXTRAS>        To include: {aux-val|func|stream-meta|db-info}\n");
    printf("\t-m, --meta-prefix <PREFIX>    To distinct EXTRAS from actual data, Prefix it (Default:\"__\")\n");
    printf("\t-f, --flatten                 Print flatten json, without DBs Parenthesis\n");
    printf("\t-o, --output <FILE>           Specify the output file. If not specified, output to stdout\n\n");

    printf("FORMAT_OPTIONS ('redis'):\n");
    printf("\t-h, --hostname <HOSTNAME>     Specify the server hostname (default: 127.0.0.1)\n");
    printf("\t-p, --port <PORT>             Specify the server port (default: 6379)\n");
    printf("\t-l, --pipeline-depth <VALUE>  Number of pending commands before blocking for responses\n");
    printf("\t-u, --user <USER>             Redis username for authentication\n");
    printf("\t-P, --password <PWD>          Redis password for authentication\n");
    printf("\t-a, --auth N [ARG1 ... ARGN]  An alternative authentication command. Given as vector of arguments\n\n");

    printf("FORMAT_OPTIONS ('redis'|'resp'):\n");
    printf("\t-r, --support-restore         Use the RESTORE command when possible\n");
    printf("\t-d, --del-before-write        Delete each key before writing. Relevant for non-empty db\n");
    printf("\t-f, --func-replace-if-exist   Replace function-library if already exists in the same name rather than aborting\n");
    printf("\t-t, --target-redis-ver <VER>  Specify the target Redis version. Helps determine which commands can\n");
    printf("\t                              be applied. Particularly crucial if support-restore being used \n");
    printf("\t                              as RESTORE is closely tied to specific RDB versions. If versions not\n");
    printf("\t                              aligned the parser will generate higher-level commands instead.\n");
    printf("\t-o, --output <FILE>           Specify the output file (For 'resp' only: if not specified, output to stdout)\n");
    printf("\t-1, --single-db               Avoid SELECT command. DBs in RDB will be stored to db 0. Watchout for conflicts\n");
    printf("\t-s, --start-cmd-num <NUM>     Start writing redis from command number\n");
    printf("\t-e, --enum-commands           Command enumeration and tracing by preceding each generated RESP command\n");
    printf("\t                              with debug command of type: `SET _RDB_CLI_CMD_ID_ <CMD-ID>`\n");

}

static RdbRes formatJson(RdbParser *parser, int argc, char **argv) {
    extern const char *jsonMetaPrefix;
    const char *includeArg;
    const char *output = NULL;/*default:stdout*/
    int includeDbInfo=0, includeStreamMeta=0, includeFunc=0, includeAuxField=0,
        flatten=0;

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-f", "--flatten", &flatten, NULL)) continue;
        if (getOptArg(argc, argv, &at, "-m", "--meta-prefix", NULL, &jsonMetaPrefix)) continue;

        if (getOptArg(argc, argv, &at, "-i", "--include", NULL, &includeArg)) {
            if (strcmp(includeArg, "aux-val") == 0) { includeAuxField = 1; continue; }
            if (strcmp(includeArg, "func") == 0) { includeFunc = 1; continue; }
            if (strcmp(includeArg, "stream-meta") == 0) { includeStreamMeta = 1; continue; }
            if (strcmp(includeArg, "db-info") == 0) { includeDbInfo = 1; continue; }
            loggerWrap(RDB_LOG_ERR, "Invalid argument for '--include': %s\n", includeArg);
            return RDB_ERR_GENERAL;
        }

        loggerWrap(RDB_LOG_ERR, "Invalid 'json' [FORMAT_OPTIONS] argument: %s\n", opt);
        printUsage(1);
        return RDB_ERR_GENERAL;
    }

    RdbxToJsonConf conf = {
            .level = RDB_LEVEL_DATA,
            .encoding = RDBX_CONV_JSON_ENC_PLAIN,
            .flatten = flatten,
            .includeAuxField = includeAuxField,
            .includeFunc = includeFunc,
            .includeStreamMeta = includeStreamMeta,
            .includeDbInfo = includeDbInfo,
    };

    if (RDBX_createHandlersToJson(parser, output, &conf) == NULL)
        return RDB_ERR_GENERAL;

    return RDB_OK;
}

static RdbRes formatPrint(RdbParser *parser, int argc, char **argv) {
    const char *auxFmt = NULL, *keyFmt = "%d,%k,%v,%t,%e,%i";
    const char *output = NULL;/*default:stdout*/

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-a", "--aux-val", NULL, &auxFmt)) continue;
        if (getOptArg(argc, argv, &at, "-k", "--key", NULL, &keyFmt)) continue;
        loggerWrap(RDB_LOG_ERR, "Invalid 'print' [FORMAT_OPTIONS] argument: %s\n", opt);
        printUsage(1);
        return RDB_ERR_GENERAL;
    }

    if (RDBX_createHandlersToPrint(parser, auxFmt, keyFmt, output) == NULL)
        return RDB_ERR_GENERAL;

    return RDB_OK;
}

static RdbRes formatRedis(RdbParser *parser, int argc, char **argv) {
    const char *output = NULL;
    RdbxRedisAuth auth = {0};
    RdbxToRespConf conf = { 0 };
    int commandEnum=0, startCmdNum=0, pipeDepthVal=0, port = 6379;
    RdbxRespToRedisLoader *respToRedis;
    RdbxToResp *rdbToResp, *rdbToResp2;
    const char *hostname = "127.0.0.1";

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-h", "--hostname", NULL, &hostname)) continue;
        if (getOptArgVal(argc, argv, &at, "-p", "--port", NULL, &port, 1, 65535)) continue;
        if (getOptArg(argc, argv, &at, "-r", "--support-restore", &(conf.supportRestore), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-d", "--del-before-write", &(conf.delKeyBeforeWrite), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-f", "--func-replace-if-exist", &(conf.funcLibReplaceIfExist), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-1", "--single-db", &(conf.singleDb), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-t", "--target-redis-ver", NULL, &(conf.dstRedisVersion))) continue;
        if (getOptArgVal(argc, argv, &at, "-l", "--pipeline-depth", NULL, &pipeDepthVal, 1, 1000)) continue;
        if (getOptArgVal(argc, argv, &at, "-s", "--start-cmd-num", NULL, &startCmdNum, 1, INT_MAX)) continue;
        if (getOptArg(argc, argv, &at, "-u", "--user", NULL, &auth.user)) continue;
        if (getOptArg(argc, argv, &at, "-P", "--password", NULL, &auth.pwd)) continue;
        if (getOptArg(argc, argv, &at, "-e", "--enum-commands", &commandEnum, NULL)) continue;
        if (getOptArgVal(argc, argv, &at, "-a", "--auth", NULL, &(auth.cmd.argc), 1, INT_MAX)) {
            auth.cmd.argv = argv + at + 1;
            if ((1 + at + auth.cmd.argc) >= argc) {
                loggerWrap(RDB_LOG_ERR, "Insufficient number of arguments to option --auth\n");
                printUsage(1);
                return RDB_ERR_GENERAL;
            }
            at += auth.cmd.argc;
            continue;
        }

        loggerWrap(RDB_LOG_ERR, "Invalid 'redis' [FORMAT_OPTIONS] argument: %s\n", opt);
        printUsage(1);
        return RDB_ERR_GENERAL;
    }

    if (((auth.user) || (auth.pwd)) && (auth.cmd.argc > 0)) {
        loggerWrap(RDB_LOG_ERR, "Invalid AUTH arguments. --auth(-a) is mutually exclusive with --password(-P) and --user(-u)\n");
        return RDB_ERR_GENERAL;
    }

    if ((rdbToResp = RDBX_createHandlersToResp(parser, &conf)) == NULL)
        return RDB_ERR_GENERAL;

    if (startCmdNum)
        RDBX_writeFromCmdNumber(rdbToResp, startCmdNum);

    if (commandEnum)
        RDBX_enumerateCmds(rdbToResp);

    if ((respToRedis = RDBX_createRespToRedisTcp(parser, rdbToResp, &auth, hostname, port)) == NULL)
        return RDB_ERR_GENERAL;

    /* if in addition requested to generate a dump to a file (of RESP protocol) */
    if (output) {
        if ((rdbToResp2 = RDBX_createHandlersToResp(parser, &conf)) == NULL)
            return RDB_ERR_GENERAL;

        if (startCmdNum)
            RDBX_writeFromCmdNumber(rdbToResp2, startCmdNum);

        if (commandEnum)
            RDBX_enumerateCmds(rdbToResp2);

        if (RDBX_createRespToFileWriter(parser, rdbToResp2, output) == NULL)
            return RDB_ERR_GENERAL;
    }

    if (pipeDepthVal)
        RDBX_setPipelineDepth(respToRedis, pipeDepthVal);

    return RDB_OK;
}

static RdbRes formatResp(RdbParser *parser, int argc, char **argv) {
    RdbxToResp *rdbToResp;
    const char *output = NULL;/*default:stdout*/
    int commandEnum = 0,  startCmdNum=0;

    RdbxToRespConf conf = { 0 };

    /* parse specific command options */
    for (int at = 1; at < argc; ++at) {
        char *opt = argv[at];
        if (getOptArg(argc, argv, &at, "-o", "--output", NULL, &output)) continue;
        if (getOptArg(argc, argv, &at, "-r", "--support-restore", &(conf.supportRestore), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-d", "--del-before-write", &(conf.delKeyBeforeWrite), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-f", "--func-replace-if-exist", &(conf.funcLibReplaceIfExist), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-1", "--single-db", &(conf.singleDb), NULL)) continue;
        if (getOptArg(argc, argv, &at, "-t", "--target-redis-ver", NULL, &(conf.dstRedisVersion))) continue;
        if (getOptArg(argc, argv, &at, "-e", "--enum-commands", &commandEnum, NULL)) continue;
        if (getOptArgVal(argc, argv, &at, "-s", "--start-cmd-num", NULL, &startCmdNum, 1, INT_MAX)) continue;

        loggerWrap(RDB_LOG_ERR, "Invalid 'resp' [FORMAT_OPTIONS] argument: %s\n", opt);
        printUsage(1);
        return RDB_ERR_GENERAL;
    }

    if ((rdbToResp = RDBX_createHandlersToResp(parser, &conf)) == NULL)
        return RDB_ERR_GENERAL;

    if (startCmdNum)
        RDBX_writeFromCmdNumber(rdbToResp, startCmdNum);

    if (RDBX_createRespToFileWriter(parser, rdbToResp, output) == NULL)
        return RDB_ERR_GENERAL;

    if (commandEnum)
        RDBX_enumerateCmds(rdbToResp);

    return RDB_OK;
}

int matchRdbDataType(const char *dataTypeStr) {
    if (!strcmp(dataTypeStr, "str")) return RDB_DATA_TYPE_STRING;
    if (!strcmp(dataTypeStr, "list")) return RDB_DATA_TYPE_LIST;
    if (!strcmp(dataTypeStr, "set")) return RDB_DATA_TYPE_SET;
    if (!strcmp(dataTypeStr, "zset")) return RDB_DATA_TYPE_ZSET;
    if (!strcmp(dataTypeStr, "hash")) return RDB_DATA_TYPE_HASH;
    if (!strcmp(dataTypeStr, "module")) return RDB_DATA_TYPE_MODULE;
    if (!strcmp(dataTypeStr, "stream")) return RDB_DATA_TYPE_STREAM;
    if (!strcmp(dataTypeStr, "func")) return RDB_DATA_TYPE_FUNCTION;

    loggerWrap(RDB_LOG_ERR,
        "Invalid TYPE argument (%s). Valid values: str, list, set, zset, hash, module, stream, func",
        dataTypeStr);
    exit(1);
}

int readCommonOptions(RdbParser *p, int argc, char* argv[], Options *options, int applyFilters) {
    const char *typeFilter, *keyFilter;
    int dbNumFilter;
    int at;

    /* default */
    options->progressMb = 0;
    options->logfilePath = LOG_FILE_PATH_DEF;
    options->ignoreChecksum = 0;
    options->formatFunc = formatJson;

    /* parse common options until FORMAT (json/resp/redis) specified */
    for (at = 2; at < argc; ++at) {
        char *opt = argv[at];

        if (getOptArg(argc, argv, &at, "-l", "--log-file", NULL, &(options->logfilePath)))
            continue;
        
        if (getOptArg(argc, argv, &at, "-i", "--ignore-checksum", &(options->ignoreChecksum), NULL))
            continue;

        if (getOptArgVal(argc, argv, &at, "-s", "--show-progress", NULL, &options->progressMb, 0, INT_MAX))
            continue;

        if (getOptArg(argc, argv, &at, "-k", "--key", NULL, &keyFilter)) {
            if (applyFilters && (!RDBX_createHandlersFilterKey(p, keyFilter, 0)))
                exit(1);
            continue;
        }

        if (getOptArg(argc, argv, &at, "-K", "--no-key", NULL, &keyFilter)) {
            if (applyFilters && (!RDBX_createHandlersFilterKey(p, keyFilter, 1)))
                exit(1);
            continue;
        }

        if (getOptArg(argc, argv, &at, "-t", "--type", NULL, &typeFilter)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterType(p, matchRdbDataType(typeFilter), 0)))
                exit(1);
            continue;
        }

        if (getOptArg(argc, argv, &at, "-T", "--no-type", NULL, &typeFilter)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterType(p, matchRdbDataType(typeFilter), 1)))
                exit(1);
            continue;
        }

        if (getOptArgVal(argc, argv, &at, "-d", "--dbnum", NULL, &dbNumFilter, 0, INT_MAX)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterDbNum(p, dbNumFilter, 0)))
                exit(1);
            continue;
        }

        if (getOptArgVal(argc, argv, &at, "-D", "--no-dbnum", NULL, &dbNumFilter, 0, INT_MAX)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterDbNum(p, dbNumFilter, 1)))
                exit(1);
            continue;
        }

        if (getOptArg(argc, argv, &at, "-e", "--expired", NULL, NULL)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterExpired(p, 0)))
                exit(1);
            continue;
        }

        if (getOptArg(argc, argv, &at, "-E", "--no-expired", NULL, NULL)) {
            if ((applyFilters) && (!RDBX_createHandlersFilterExpired(p, 1)))
                exit(1);
            continue;
        }

        if (strcmp(opt, "json") == 0) { options->formatFunc = formatJson; break; }
        else if (strcmp(opt, "resp") == 0) { options->formatFunc = formatResp; break; }
        else if (strcmp(opt, "redis") == 0) { options->formatFunc = formatRedis; break; }
        else if (strcmp(opt, "print") == 0) { options->formatFunc = formatPrint; break; }

        loggerWrap(RDB_LOG_ERR, "At argv[%d], unexpected OPTIONS argument: %s\n", at, opt);
        printUsage(1);
        exit(1);
    }
    return at;
}

void closeLogFileOnExit(void) {
    if (logfile != NULL)
        fclose(logfile);
}

int main(int argc, char **argv)
{
    size_t fileSize = 0;
    Options options;
    RdbStatus status;
    int at;
    RdbRes res;

    if (argc < 2) {
        printUsage(0);
        return 1;
    }

    /* first argument is expected to be input file */
    char *input = argv[1];

    /* Initially, read common options that are applicable to all formatters. To
     * make it effective, apply filters later (applyFilters), ensuring that they
     * are registered only after the FORMATTER registers its own handlers. */
    at = readCommonOptions(NULL, argc, argv, &options, 0);

    if (at == argc) {
        logger(RDB_LOG_ERR, "Missing <FORMAT> value.");
        printUsage(1);
        return RDB_ERR_GENERAL;
    }

    if ((logfile = fopen(options.logfilePath, "w")) == NULL) {
        printf("Error opening log file for writing `%s`: %s\n",
               options.logfilePath, strerror(errno));
        return RDB_ERR_GENERAL;
    }

    atexit(closeLogFileOnExit);

    /* create the parser and attach it a file reader */
    RdbParser *parser = RDB_createParserRdb(NULL);
    RDB_setLogLevel(parser, RDB_LOG_INF);
    RDB_setLogger(parser, logger);
    
    if (options.ignoreChecksum) 
        RDB_IgnoreChecksum(parser);

    if (strcmp(input, "-") == 0) {
        if (RDBX_createReaderFileDesc(parser, 0 /*stdin*/, 0) == NULL)
            return RDB_ERR_GENERAL;
    } else {
        if (RDBX_createReaderFile(parser, input /*file*/) == NULL)
            return RDB_ERR_GENERAL;

        /* If input is a file, then get its size */
        struct stat st;
        if (stat(input, &st) == 0) {
            fileSize = st.st_size;
        } else {
            printf("Error getting file size: %s\n", strerror(errno));
            return RDB_ERR_GENERAL;
        }
    }

    if (RDB_OK != (res = options.formatFunc(parser, argc - at, argv + at)))
        return res;

    if (RDB_OK != RDB_getErrorCode(parser))
        return RDB_getErrorCode(parser);

    /* now that the formatter got registered, attach filters */
    readCommonOptions(parser, argc, argv, &options, 1);

    /* If requested to print progress */
    if (options.progressMb) {
        RDB_setPauseInterval(parser, options.progressMb * 1024 * 1024);
        while (1) {
            status = RDB_parse(parser);
            if (status == RDB_STATUS_WAIT_MORE_DATA)
                continue;
            else if (status == RDB_STATUS_PAUSED) {
                size_t bytes = RDB_getBytesProcessed(parser);
                /* If file size is known, print percentage */
                if (fileSize != 0)
                    printf("... Processed %zuMBytes (%.2f%%) ...\n",
                           bytes / (1024 * 1024), (bytes * 100.0) / fileSize);
                else
                    printf("... Processed %zuMBytes ...\n", bytes / (1024 * 1024));
                continue;
            }

            break; /* RDB_STATUS_ERROR */
        }
    } else {
        while ((status = RDB_parse(parser)) == RDB_STATUS_WAIT_MORE_DATA);
    }

    if (status != RDB_STATUS_OK)
        return RDB_getErrorCode(parser);

    RDB_deleteParser(parser);

    return 0;
}
