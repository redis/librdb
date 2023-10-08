# deps
The purpose of this folder is to provide the necessary dependencies for the librdb parser. 

# librdb dependencies

## redis
The redis subfolder contains a modified subset of files from the Redis repository. These 
files have been slightly adapted and used by librdb parser. In the future, there is a 
possibility that the librdb library will be integrated into the Redis repository. If this 
integration occurs, the contents of this deps folder will reflect part of the required 
dependencies and changes needed for the integration.

To upgrade, use as base reference specified version in version.h file, though it shouldn't
update so often (Otherwise, consider in the future having better methodology to consume 
and upgrade redis code).

## hiredis
This directory contains the 'hiredis' project as a submodule. It is exclusively utilized 
by the tests to manipulate the Redis server.