default: all

LIB_DIR               = ../../lib
LIB_NAME              = rdb
LIB_FILENAME          = librdb.a
LIB_NAME_EXT          = rdb-ext
LIB_FILENAME_EXT      = librdb-ext.a

# Artifacts:
TARGET_APP           = rdb-cli

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))
TARGETS  = $(basename $(SOURCES))

OPTIMIZATION ?= -O3

STD         = -std=c99
STACK       = -fstack-protector-all -Wstack-protector
WARNS       = -Wall -Wextra -pedantic -Werror
CFLAGS      = -fPIC $(OPTIMIZATION) $(STD) $(STACK) $(WARNS)
DEBUG       = -g3 -DDEBUG=1
LDFLAGS     =

ifeq ($(shell uname -s),Darwin)
    LIBS = -L $(LIB_DIR) -l $(LIB_NAME_EXT) -l $(LIB_NAME)
else
    LIBS = -L $(LIB_DIR) -l:$(LIB_FILENAME) -l:$(LIB_FILENAME_EXT)
endif

ifeq ($(BUILD_TLS),yes)
	CFLAGS += -DUSE_OPENSSL=1
	LIBS += -lssl -lcrypto

	# On macOS, OpenSSL from Homebrew is in a non-standard location
	ifeq ($(shell uname -s),Darwin)
		ifndef OPENSSL_PREFIX
			# Try common Homebrew OpenSSL locations (Apple Silicon and Intel)
			SEARCH_PATH1=/opt/homebrew/opt/openssl
			SEARCH_PATH2=/usr/local/opt/openssl

			ifneq ($(wildcard $(SEARCH_PATH1)),)
				OPENSSL_PREFIX=$(SEARCH_PATH1)
			else ifneq ($(wildcard $(SEARCH_PATH2)),)
				OPENSSL_PREFIX=$(SEARCH_PATH2)
			endif
		endif

		ifdef OPENSSL_PREFIX
			CFLAGS += -I$(OPENSSL_PREFIX)/include
			LDFLAGS += -L$(OPENSSL_PREFIX)/lib
		endif
	endif
endif

######################################### RULES #######################################
all: $(TARGET_APP)
	rm -f ../../bin/$(TARGET_APP)
	cp $(TARGET_APP) ../../bin/
	@echo "Done.";

$(TARGET_APP): %: %.c lib_dependency
	$(CC) $(CFLAGS) -o $@ $<  $(DEBUG) $(LDFLAGS) $(LIBS)

lib_dependency: $(LIB_DIR)/$(LIB_FILENAME_EXT)

clean:
	@rm -rvf $(TARGETS) ./*.o ../../bin/$(TARGET_APP)

.PHONY: all clean lib_dependency