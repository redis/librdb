# librdb

This is C library for parsing RDB files.

The Parser is implemented in the spirit of SAX parser. It fires off a series of events as
it reads the RDB file from beginning to end, and callbacks to handlers registered on
selected types of data.


The primary objective of this project is to offer an efficient and robust C library for
parsing Redis RDB files. It also provides an extension library for parsing to JSON and RESP
protocols.

## Getting Started
If you just wish to get a basic understanding of the library's functionality:

    % make example

To see cool internal state printouts of the parser, set env-var `LIBRDB_DEBUG_DATA` beforehand:

    % LIBRDB_DEBUG_DATA=1 make example

To build and run tests, you need to have cmocka unit testing and python3 installed:

    % make test

To install into /usr/local/:

    % make install

To run CLI extension of this library and let it parse RDB file to json:

    % rdb-cli mixed_data_types.rdb json
    [{
      "my_key":"Hello, Redis!",
      "my_set":["member1","member2"],
      "my_zset":{"Bob":"5","Alice":"10","Charlie":"15"},
      "my_hash":{"field1":"value1","field2":"field2"},
      "my_list":["item1","item2", "item3"],
      "my_stream":{
        "entries":[
          { "id":"1695649068107-0", "values":{"message":"Message1"} },
          { "id":"1695649068110-0", "values":{"message":"Message2"} },
          { "id":"1695893015933-0", "values":{"field1":"value1", "field2":"value2", "field3":"value3"} }
      ]}
    }]


To generate RESP commands:

    % rdb-cli multiple_lists_strings.rdb resp
    *2
    $6
    SELECT
    $1
    ...

To run against live Redis server and upload RDB file, assuming Redis is installed as well:

    % redis-server --port 6379 & 
    % rdb-cli multiple_lists_strings.rdb redis -h 127.0.0.1 -p 6379
    % redis-cli keys "*"
    1) "string2"
    2) "mylist3"
    3) "mylist2"
    4) "mylist1"
    5) "string1"
    6) "lzf_compressed"

## Motivation behind this project
There is a genuine need by the Redis community for a versatile RDB file parser that can
export data, perform data analysis, or merely extract raw data from RDB and RESTORE it
against a live Redis server. However, available parsers have shortcomings in some aspects
such as lack of long-term support, lagging far behind the latest Redis release, and
usually not being optimized for memory, performance, or high-traffic streaming for
production environments. Additionally, most of them are not written in C, which limits the
reuse of Redis components and potential to contribute back to Redis repo. To address these
issues, it is worthwhile to develop a new parser with a modern architecture, that maybe
can also challenge the current integrated RDB parser of Redis and even replace it in the
future.

## Main building blocks
The RDB library parser composed of 3 main building blocks:

       +--------+     +--------+     +----------+
       | READER | --> | PARSER | --> | HANDLERS |
       +--------+     +--------+     +----------+

### Reader
The **Reader** gives interface to the parser to access the RDB source. It can be either
reading from a file, a socket or user defined reader. Possible extensions might be reading 
from S3, gz file, or a live redis instance.

This block is optional. As an alternative, the parser can be fed with prefetched chunks of 
data.

### Parser
The **Parser** is the core engine. It will parse RDB file and trigger registered handlers.

The parser supports 3 sets of handlers to register, at 3 different levels of the
parsed data:

#### Level0 - Registration on raw data
For example, if a user wants to restore from RDB source, then he doesn't care much about
the different data-types, neither the internal RDB data structure, only to get raw data of
whatever serialized and replay it against a live Redis server with RESTORE command.
In that case registration on Level0 will do the magic.

#### Level1 - Registration on RDB data-structures
If required to analyze memory consumption, for example, then there is no escape but to
inspect "low-level" data structures of RDB file. The best way to achieve it, is
registration at level1 and pouring the logic to analyze each of the RDB data-structures
into corresponding callbacks.

#### Level2 - Registration on Redis data-types
If we only care about DB logical data-types, for example in order to export data to
another framework, then we better register our callbacks at level2.

### Handlers
The **Handlers** represent a set of builtin or user-defined functions that will 
be called on the parsed data. Currently, librdb supports 2 built-in Handlers that 
converts to JSON and RESSP and one extension to RESP handlers that in addition 
can play it against live server.

It is possible to attach to parser more than one set of handlers at the same level.
That is, for a given data at a given level, the parser will call each of the handlers that
registered at that level. One reason to do so can be because usually retrieving RDB file
is the most time-consuming task of the parser, and it can save time by making a single
parse yet invoke multiple sets of handlers.

More common reason is that a handlers can be used also as a Filter to decide whether to
propagate data to the next set of handlers in-line. Such built-in filters can be
found at extension library of this project. Note that for any given level, order of
calls to handlers will be the opposite to order of their registration to that level.

Furthermore, it is also possible to attach multiple handlers at different levels, which is
described in the [Advanced](#Advanced) section.

## Usage
Following examples avoid error check to keep it concise. Full example can be found in
`examples` directory. Note that there are different prefixes for parser functions in the
core library vs. extension library ("RDB" vs "RDBX").

- Converting RDB file to JSON file:

      RdbParser *parser = RDB_createParserRdb(NULL);
      RDBX_createReaderFile(parser, "dump.rdb");
      RDBX_createHandlersToJson(parser, "db.json", NULL);
      RDB_parse(parser); 
      RDB_deleteParser(parser);

- Parsing RDB file to RESP protocol:

      RdbParser *parser = RDB_createParserRdb(NULL);
      RDBX_createReaderFile(parser, rdbfile);
      RdbxToResp *rdbToResp = RDBX_createHandlersToResp(parser, NULL);
      RDBX_createRespToFileWriter(parser, rdbToResp, "./rdbDump.resp");
      RDB_parse(parser);
      RDB_deleteParser(parser);

- Parsing RDB file with user callbacks:

      RdbRes myHandleNewKey(RdbParser *parser, void *userData,  RdbBulk key, RdbKeyInfo *info) { 
          printf("KEY=%s\n", key);
          return RDB_OK;
      } 

      RdbParser *parser = RDB_createParserRdb(NULL);
      RDBX_createReaderFile(parser, "dump.rdb");
      RdbHandlersRawCallbacks callbacks = { .handleNewKey = myHandleNewKey };
      RDB_createHandlersRaw(parser, &callbacks, myUserData, NULL);
      RDB_parse(parser);
      RDB_deleteParser(parser);

- Use builtin Handlers (filters) to propagate only specific keys

      RdbParser *parser = RDB_createParserRdb(NULL);
      RDBX_createReaderFile(parser, "dump.rdb");
      RDBX_createHandlersToJson(parser, "redis.json", NULL);
      RDBX_createHandlersFilterKey(parser, "id_*", 0 /*exclude*/);
      RDB_parse(parser);
      RDB_deleteParser(parser);

- Parsing in memory data (without reader)

      unsigned char rdbContent[] =  {'R', 'E', 'D', 'I', 'S', .... };
      RdbParser *parser = RDB_createParserRdb(NULL);
      RDBX_createHandlersToJson(parser, "redis.json", NULL);
      RDB_parseBuff(parser, rdbContent, sizeof(rdbContent), 1 /*EOF*/);
      RDB_deleteParser(parser);


Whether it is Reader or Handlers, once a new block is created, it is being attached to the
parser and the parse will take ownership and will release the blocks either during its own
destruction, or when newer block replacing old one.

### rdb-cli usage

    Usage: rdb-cli /path/to/dump.rdb [OPTIONS] {json|resp|redis} [FORMAT_OPTIONS]
    OPTIONS:
            -l, --log-file <PATH>         Path to the log file or stdout (Default: './rdb-cli.log')
    
            Multiple filters combination of keys/types/dbs can be specified:
            -k, --key <REGEX>             Include only keys that match REGEX
            -K  --no-key <REGEX>          Exclude all keys that match REGEX
            -t, --type <TYPE>             Include only selected TYPE {str|list|set|zset|hash|module|func}
            -T, --no-type <TYPE>          Exclude TYPE {str|list|set|zset|hash|module|func}
            -d, --dbnum <DBNUM>           Include only selected db number
            -D, --no-dbnum <DBNUM>        Exclude DB number
    
    FORMAT_OPTIONS ('json'):
            -i, --include <EXTRAS>        To include: {aux-val|func|stream-meta}
            -f, --flatten                 Print flatten json, without DBs Parenthesis
            -o, --output <FILE>           Specify the output file. If not specified, output to stdout
    
    FORMAT_OPTIONS ('redis'):
            -h, --hostname <HOSTNAME>     Specify the server hostname (default: 127.0.0.1)
            -p, --port <PORT>             Specify the server port (default: 6379)
            -l, --pipeline-depth <VALUE>  Number of pending commands before blocking for responses
            -u, --user <USER>             Redis username for authentication
            -P, --password <PWD>          Redis password for authentication
            -a, --auth N [ARG1 ... ARGN]  An alternative authentication command. Given as vector of arguments
    
    FORMAT_OPTIONS ('redis'|'resp'):
            -r, --support-restore         Use the RESTORE command when possible
            -d, --del-before-write        Delete each key before writing. Relevant for non-empty db
            -t, --target-redis-ver <VER>  Specify the target Redis version. Helps determine which commands can
                                          be applied. Particularly crucial if support-restore being used
                                          as RESTORE is closely tied to specific RDB versions. If versions not
                                          aligned the parser will generate higher-level commands instead.
            -o, --output <FILE>           Specify the output file (For 'resp' only: if not specified, output to stdout)
            -1, --single-db               Avoid SELECT command. DBs in RDB will be stored to db 0. Watchout for conflicts
            -s, --start-cmd-num <NUM>     Start writing redis from command number
            -e, --enum-commands           Command enumeration and tracing by preceding each generated RESP command
                                          with debug command of type: `SET _RDB_CLI_CMD_ID_ <CMD-ID>`


<a name="Advanced"></a>
## Advanced
### Customized Reader
The built-in readers should be sufficient for most purposes. However, if they do not meet
your specific needs, you can use the `RDB_createReaderRdb()` helper function to create a
custom reader with its own reader function. The built-in reader file
([readerFile.c](src/ext/readerFile.c)) can serve as a code reference for this purpose.

### Asynchronous parser
The parser has been designed to handle asynchronous situation where it may temporarily
not have data to read from the RDB-reader, or not feed yet with more input buffers.

Building on what was discussed previously, a reader can be implemented to support
asynchronous reads by returning `RDB_STATUS_WAIT_MORE_DATA` for read requests. In such a
case, it's necessary to provide a mechanism for indicating to the application when the
asynchronous operation is complete, so the application can call `RDB_parse()` again. The
async indication for read completion from the customized reader to the application is
beyond the scope of this library. A conceptual invocation of such flow can be:

      myAsyncReader = RDB_createReaderRdb(parser, myAsyncRdFunc, myAsyncRdData, myAsyncRdDeleteFunc);
      while(RDB_parse(parser) == RDB_STATUS_WAIT_MORE_DATA) {
         my_reader_completed_await(myAsyncReader); 
      }

Another way to work asynchronously with the parser is just feeding the parser with chunks
of streamed buffers by using the `RDB_parseBuff()` function:

      int parseRdbToJson(int file_descriptor, const char *fnameOut)
      {
        RdbStatus status;
        const int BUFF_SIZE = 200000;
        RdbParser *parser = RDB_createParserRdb(NULL);
        RDBX_createHandlersToJson(parser, fnameOut, NULL);
        void *buf = malloc(BUFF_SIZE);
        do {                        
            int bytes_read = read(file_descriptor, buf, BUFF_SIZE);
            if (bytes_read < 0)  break; /* error */
            status = RDB_parseBuff(parser, buf, bytes_read, bytes_read == 0);
        } while (status == RDB_STATUS_WAIT_MORE_DATA);
        RDB_deleteParser(parser);
        free(buf);
      } 

### Cancel parser execution
To cancel parsing in the middle of execution, the trigger should come from the registered
handlers, Simply by returning `RDB_ERR_CANCEL_PARSING`. If the parser is using builtin
handlers for parsing, and yet, you want that the parser will stop when some condition is
met, then it is required to write a dedicated customized handlers, user-defined callbacks,
to give this indication and register it as well.

### Pause parser and resume
At times, the application may need to execute additional tasks during parsing intervals,
such as updating a progress bar or verifying that used memory remains within limit. To 
facilitate this, the parser can be configured with a pause interval that specifies the 
number of bytes to be read from RDB source before pausing. This means that each time the 
parser is invoked, it will continue parsing until it has read a number of bytes equal to 
or greater than the configured interval, at which point it will automatically pause and 
return 'RDB_STATUS_PAUSED' in order to allow the application to perform other tasks. Example:

      size_t intervalBytes = 1048576;  
      RdbParser *parser = RDB_createParserRdb(memAlloc);
      RDBX_createReaderFile(parser, "dump.rdb");
      RDBX_createHandlersToJson(parser, "db.json", NULL);
      RDB_setPauseInterval(parser, intervalBytes);
      while (RDB_parse(parser) == RDB_STATUS_PAUSED) {
          /* do something else in between */
      } 
      RDB_deleteParser(parser);

Note, if pause interval has elapsed and at the same time the parser need to return
indication to wait for more data, then the parser will suppress pause indication and
return `RDB_STATUS_WAIT_MORE_DATA` instead.

However, there may be cases where it is more appropriate for the callback handlers to
determine when to suspend the parser. In such cases, the callback should call
`RDB_pauseParser()` to pause the parser. Note that, the parser may still call one or a few
more callbacks before actual pausing.

Special cautious should be given when using this feature along with `RDB_parseBuff()`.
Since the parser doesn't owns the buffer it reads from, when the application intends to
call again to `RDB_parseBuff()` to resume parsing after pause, it must call with the same
buffer that it supplied before the pause and only partially processed. The function
`RDB_parseBuff()` will verify that the buffer reference is identical as before and continue
with the same offset it reached. This also implies that the buffer must remain persistent
in such a scenario. Whereas it might seem redundant API to pass again the same values on
resume, yet it highlights the required persistence of the reused buffer.

### Memory optimization
The optimization of memory usage is a major focus for the parser, which is also evident in
its API. The application can optionally choose not only to customize the malloc function
used internally by the parser, but also the method for allocating data passed to the
callbacks. This includes the options:
1. Using parser internal stack
2. Using parser internal heap allocation (with refcount support for zero-copy).
3. Using external allocation
4. Using external allocation unless data is already prefetched in memory.

The external allocation options give the opportunity to allocate the data by the parser in
specific layout, as the application expects. For more information, lookup for
`RdbBulkAllocType` at [librdb-api.h](api/librdb-api.h).

### Multiple handlers at different levels
Some of the more advanced usages might require parsing different data types at different
levels of the parser. As each level has its own way to handle the data with distinct set
of callbacks, it is the duty of the application to configure for each RDB object type at
what level it is needed to get handled by calling `RDB_handleByLevel()`. Otherwise, the
parser will resolve it by parsing and calling handlers that are registered at lowest level.

As for the common callbacks to all levels, such as `handleStartRdb` or `handleNewDb`,
if registered at different levels then all of them will be called, one by one, starting 
from handlers that are registered at the lowest level.

## Implementation notes
The Redis RDB file format consists of a series of opcodes followed by the actual data that
is being persisted. Each opcode represents a specific operation that needs to be performed
when encoding or decoding data. The parsing process has been organized into separate
**parsing-elements** which primarily align with RDB opcodes. Each parsing-element that
correspond to RDB opcode usually carries out the following steps:

1. Reads from RDB file required amount of data to process current state of parsing-element.
2. If required, calls app's callbacks or store the parsed data for later use.
3. Updates the state of the next parsing-element to be called.

### Async support
As mentioned above, instead of blocking the parser on read command, the reader (and in
turn the parser) can return to the caller `RDB_STATUS_WAIT_MORE_DATA` and will be ready to
be called again to continue parsing once more data become available.

In such scenario, any incomplete parsing-element will preserve its current state. As for
any data that has already been read from the RDB reader - it cannot be read again from the
reader. To address this issue, a unique **bulk-pool** data structure is used to route all
data being read from the RDB reader. It stores a reference to the allocations in a queue,
and enable to **rollback** and replay later once more data becomes available, in an
attempt to complete the parsing-element state. The **rollback** command basically rewinds
the queue of allocation and allows the exact same sequence of allocation requests to be
provided to the caller, however, instead of creating new allocations, the allocator
returns the next item in the queue. Otherwise, if the parser managed to reach a new
parsing-element state, then all cached data in the pool will be **flushed**.

The bulk-pool is also known as parsing-element's **cache**. To learn more about it,
refer to the comment at the start of the file [bulkAlloc.h](src/lib/bulkAlloc.h).

### Parsing-Element states
Having gained understanding of the importance of bulk-pool rollback and replay for
async parsing, it is necessary to address two crucial questions:

1. If we are parsing, say a large list, is it necessary for the parser to rollback all
   the way to the beginning of current parsing-element?
2. If the parser has already called app callbacks, will it call them again on rollback?

#### 1. Parsing-element internal states
It is essential to break down complex parsing elements with multiple items into internal
iterative states. This ensures that any asynchronous event will cause the parser to
rollback to its last valid iterative state, rather than all the way back to the beginning
of the parsing element. For instance, in the case of a list opcode, the corresponding
parsing element (See function `elementList`) will comprise an entry state that parses
the number of elements in the list from the RDB file and an iterative state that parses
each subsequent node in the list. In case of rollback only the last node will be parsed
again rather than parsing the entire list from start.

The parsing-element cache gets flushed on each parsing-element state transition. This
prevents the parser from reading outdated buffers from the cache that belong to the
previous state in case of a rollback scenario, ensuring that consecutive states are
clearly differentiated.

#### 2. Defining Safe-state
Regarding the second question, before making a callback to the application, the parsing
element must first ensure that its state reached a **safe state**. That is, there should
be no new attempts to read the RDB file until the end of current state that may result in
rollbacks. Otherwise, on rollback, the parser may end up calling the same application
callback more than once.

### Caching and garbage-collector
As mentioned above the parsing-element cache will be flushed whenever next parsing-element
is set or when the parsing-element state is updated. This way we also gain along the way
a cache with garbage collector capabilities at hand that can also serve parsing-element
for its own internal allocations, for example, after reading compressed data from RDB
file, the parser can allocate a new buffer from cache for decompression operation without
the worry to release it at the end or in case of an error.

### State machine parser
The parsing-elements in the implementation are partially designed using a state machine
approach. Each parsing-element calls indirectly the next one, and the main parsing loop
triggers the next parsing element through the `parserMainLoop` function. This
approach not only adds an extra layer of control to the parser along execution steps, but
also enables parsing of customized RDB files or even specific parts of the file. This
functionality can be further enhanced as needed.
