/* The following C file serves as an illustration of how to use the librdb
 * library for transforming Redis RDB files into JSON format. If you wish to see
 * the various parsing components being invoked in the background, simply set
 * the environment variable ENV_VAR_DEBUG_DATA to 1.
 *
 *     $ export LIBRDB_DEBUG_DATA=1
 *     $ make example
 *
 */
#include <stdio.h>
#include <assert.h>
#include "../api/librdb-api.h"  /* RDB library header */
#include "../api/librdb-ext-api.h" /* RDB library extension header */


void logger(RdbLogLevel l, const char *msg) {
    static char *logLevelStr[] = {
            [RDB_LOG_ERR]  = "| ERROR |",
            [RDB_LOG_WRN]  = "| WARN  |",
            [RDB_LOG_INF]  = "| INFO  |",
            [RDB_LOG_DBG]  = "| DEBUG |",
    };
    printf("%s %s\n", logLevelStr[l], msg);
}

/*******************************************************************
 * Example of RDB to Json file conversion. It also shows the usage
 * of two FilterKey.
 *******************************************************************/
int main() {
    RdbParser *parser;
    RdbxReaderFile *reader;
    RdbxToJson *rdbToJson;
    RdbxFilterKey *filterKey;
    RdbRes err=RDB_OK;

    const char *infile = "./dumps/multiple_lists_strings.rdb";
    const char *outfile = "./dumps/multiple_lists_strings.json";

    parser = RDB_createParserRdb(NULL);
    if (!parser) {
        logger(RDB_LOG_ERR, "Failed to create parser");
        return RDB_ERR_FAILED_CREATE_PARSER;
    }

    RDB_setLogger(parser, logger);

    reader = RDBX_createReaderFile(parser, infile);
    if (!reader) goto PARSER_ERROR;

    /* Create RDB to JSON built-in Handlers */
    rdbToJson = RDBX_createHandlersToJson(parser, outfile, NULL);
    if (!rdbToJson) goto PARSER_ERROR;

    /* Filter keys that starts with the word `mylist` */
    filterKey = RDBX_createHandlersFilterKey(parser, "mylist.*", 0 /*flags*/);
    if (!filterKey) goto PARSER_ERROR;

    /* Run the parser */
    RdbStatus status = RDB_parse(parser);
    if (status != RDB_STATUS_OK) goto PARSER_ERROR;
    printf ("Parsed successfully RDB to JSON file: %s\n", outfile);

    goto PARSER_END;

PARSER_ERROR:
    err = RDB_getErrorCode(parser);
    assert(err != RDB_OK);
    logger(RDB_LOG_ERR, RDB_getErrorMessage(parser));

PARSER_END:
    RDB_deleteParser(parser);
    return err;
}