#include <stddef.h>
#include <assert.h>

#include "version.h"

#define STATIC_ASSERT(COND,MSG) typedef char static_assertion[(COND)?1:-1]

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define LIBRDB_COMPOSED_VERSION_STRING TOSTRING(LIBRDB_MAJOR_VERSION) "." \
                                       TOSTRING(LIBRDB_MINOR_VERSION) "." \
                                       TOSTRING(LIBRDB_PATCH_VERSION)

/* Verify that the composed version string matches the individual version components */
STATIC_ASSERT(
        (sizeof(LIBRDB_VERSION_STRING) == sizeof(LIBRDB_COMPOSED_VERSION_STRING)) &&
        (__builtin_strcmp(LIBRDB_VERSION_STRING, LIBRDB_COMPOSED_VERSION_STRING) == 0),
        "LIBRDB_VERSION_STRING does not match the individual version components"
);
