default: all

LIB_NAME              = rdb
LIB_DIR               = ../../lib
LIB_NAME_EXT          = $(LIB_NAME)-ext

# Artifacts:
TARGET_APP           = rdb-convert

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))
TARGETS  = $(basename $(SOURCES))

CC          = gcc
STD         = -std=gnu99
STACK       = -fstack-protector-all -Wstack-protector
WARNS       = -Wall -Wextra -pedantic -Werror
CFLAGS      = -fPIC -O3 $(STD) $(STACK) $(WARNS)
DEBUG       = -g3 -DDEBUG=1
LIBS        = -L /usr/lib -L $(LIB_DIR) -l $(LIB_NAME) -l $(LIB_NAME_EXT)

ifeq ($(BUILD_TLS),yes)
CFLAGS+=-DUSE_OPENSSL=1
LIBS+=-lssl -lcrypto
endif

######################################### RULES #######################################
all: $(TARGET_APP)
	mv $(TARGET_APP) ../../bin
	@echo "Done.";

$(TARGET_APP): %: %.c
	$(CC) $(CFLAGS) -o $@ $<  $(DEBUG) $(LIBS)

clean:
	@rm -rvf $(TARGETS) ./*.o;

.PHONY: all clean