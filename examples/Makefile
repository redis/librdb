default: all

LIB_NAME              = rdb
LIB_DIR               = ../lib
LIB_NAME_EXT          = $(LIB_NAME)-ext

# Artifacts:
TARGET_TEST           = example1

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))
TARGETS  = $(basename $(SOURCES))

OPTIMIZATION?=-O3

STD         = -std=c99
STACK       = -fstack-protector-all -Wstack-protector
WARNS       = -Wall -Wextra -pedantic -Werror
CFLAGS      = -fPIC $(OPTIMIZATION) $(STD) $(STACK) $(WARNS)
DEBUG       = -g3 -DDEBUG=1
LDFLAGS     =
LIBS        = -L /usr/lib -L $(LIB_DIR) -l $(LIB_NAME) -l $(LIB_NAME_EXT)

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
all: $(TARGET_TEST)
	@echo "Done.";

$(TARGET_TEST): %: %.c
	$(CC) $(CFLAGS) -o $@ $<  $(DEBUG) $(LDFLAGS) $(LIBS)

clean:
	@rm -rvf $(TARGETS) ./*.o;

.PHONY: all clean