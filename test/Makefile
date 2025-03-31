default: all

LIB_DIR               = ../lib
LIB_NAME              = rdb
LIB_NAME_EXT          = $(LIB_NAME)-ext
LIBHIREDIS            = ../deps/hiredis/libhiredis.a

# Artifacts:
TARGET_TEST           = test_lib
TARGET_TEST_STATIC    = test_static_lib

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))

STD         = -std=c99
STACK       = -fstack-protector-all -Wstack-protector
WARNS       = -Wall -Wextra -pedantic -Werror -Wno-unused-function

OPTIMIZATION ?= -O0

CFLAGS      = -D_DEFAULT_SOURCE -fPIC $(OPTIMIZATION) $(STD) $(STACK) $(WARNS)
DEBUG       = -g3 -DDEBUG=1
LIBS        = -l cmocka -L $(LIB_DIR) -l $(LIB_NAME) -l $(LIB_NAME_EXT) $(LIBHIREDIS)
LIBS_STATIC = -l cmocka -L $(LIB_DIR) $(LIB_DIR)/lib$(LIB_NAME).a $(LIB_DIR)/lib$(LIB_NAME_EXT).a $(LIBHIREDIS)

ifeq ($(BUILD_TLS),yes)
	CFLAGS += -DUSE_OPENSSL=1
	LIBS += -lssl -lcrypto
endif

# Platform-specific overrides
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

ifeq ($(uname_S),Darwin)
	CFLAGS += -I$(shell brew --prefix)/include
	LIBS += -L$(shell brew --prefix)/lib
	LIBS_STATIC += -L$(shell brew --prefix)/lib
endif

######################################### RULES #######################################
all: $(TARGET_TEST) $(TARGET_TEST_STATIC)
	@echo "Done.";

$(TARGET_TEST): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(DEBUG) $(CFLAGS) $(LIBS)

$(TARGET_TEST_STATIC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(DEBUG) $(CFLAGS) $(LIBS_STATIC)

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) -c $*.c -o $*.o $(DEBUG) $(CFLAGS)
	$(CC) -MM $(CFLAGS) $*.c > $*.d

clean:
	@rm -rvf $(TARGET_TEST) $(TARGET_TEST_STATIC) ./tmp/*.* ./*.o ./*.d ./log/*.log;

.PHONY: all clean