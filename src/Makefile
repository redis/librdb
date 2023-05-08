default: all

LIB_NAME              = rdb
LIB_DIR               = ../lib

# Artifacts:
TARGET_LIB            = $(LIB_DIR)/lib$(LIB_NAME).so
TARGET_LIB_STATIC     = $(LIB_DIR)/lib$(LIB_NAME).a

# Source files in the working directory
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))

# Source files in deps/redis directory
DEPS_SOURCES = $(notdir $(basename $(wildcard deps/redis/*.c)))
DEPS_OBJECTS = $(patsubst %,deps/redis/%.o,$(DEPS_SOURCES))

EXTERN_RP_CONFIG=
CC       = gcc
STD      = -std=gnu99
STACK    = -fstack-protector-all -Wstack-protector
WARNS    = -Wall -Wextra -pedantic -Werror
CFLAGS   = -fPIC -O3 $(STD) $(STACK) $(WARNS) $(EXTERN_RP_CONFIG)
DEBUG    = -g3 -DDEBUG=1
LIBS     =

######################################### RULES #######################################
all: $(TARGET_LIB) $(TARGET_LIB_STATIC)
	@echo "Done.";

$(TARGET_LIB): $(OBJECTS) $(DEPS_OBJECTS)
	$(CC) -o $@ -shared ${LDFLAGS} $^

$(TARGET_LIB_STATIC): $(OBJECTS) $(DEPS_OBJECTS)
	ar rcs $@ $^

# Include object file dependencies
-include $(OBJECTS:.o=.d) $(DEPS_OBJECTS:.o=.d)

# Compile source files in the working directory to object files
%.o: %.c
	$(CC) -fPIC $(CFLAGS) -c $*.c -o $*.o $(DEBUG) $(LIBS)
	$(CC) -MM $(CFLAGS) $*.c > $*.d

# Compile source files in deps/redis directory to object files
deps/redis/%.o: deps/redis/%.c
	@mkdir -p deps/redis
	$(CC) $(CFLAGS) -c $< -o $@ $(DEBUG) $(LIBS)
	$(CC) -MM $(CFLAGS) $< > $(@:.o=.d)

clean:
	@rm -rvf $(TARGET_LIB) $(TARGET_LIB_STATIC) ./*.o ./*.d deps/redis/*.o deps/redis/*.d;

.PHONY: all clean
