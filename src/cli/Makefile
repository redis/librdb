default: all

LIB_DIR               = ../../lib
LIB_NAME              = librdb.a
LIB_NAME_EXT          = librdb-ext.a

# Artifacts:
TARGET_APP           = rdb-cli

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
LIBS        = -L /usr/lib -L $(LIB_DIR) -l:$(LIB_NAME_EXT)  -l:$(LIB_NAME)

ifeq ($(BUILD_TLS),yes)
CFLAGS+=-DUSE_OPENSSL=1
LIBS+=-lssl -lcrypto
endif

######################################### RULES #######################################
all: $(TARGET_APP)
	rm -f ../../bin/$(TARGET_APP)
	cp $(TARGET_APP) ../../bin/
	@echo "Done.";

$(TARGET_APP): %: %.c  lib_dependency
	$(CC) $(CFLAGS) -o $@ $<  $(DEBUG) $(LIBS)

lib_dependency: $(LIB_DIR)/$(LIB_NAME_EXT)

clean:
	@rm -rvf $(TARGETS) ./*.o ../../bin/$(TARGET_APP)

.PHONY: all clean lib_dependency