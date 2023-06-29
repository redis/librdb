# deps
The purpose of this folder is to provide the necessary dependencies for the librdb parser. 
Currently, it includes only redis subfolder, which contains a subset of files from the Redis 
repository that have been slightly adapted for reuse by librdb.

As the librdb library evolves, it might require additional dependencies apart from the redis
subfolder. In such cases, new subfolders may be added under the deps directory to
accommodate these dependencies.

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

