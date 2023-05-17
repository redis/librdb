default: all

LIB_NAME              = rdb
LIB_DIR               = ../lib
LIB_NAME_EXT          = $(LIB_NAME)-ext

# Artifacts:
TARGET_TEST           = test_lib
TARGET_TEST_STATIC    = test_static_lib

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))

CC          = gcc
STD         = -std=gnu99
STACK       = -fstack-protector-all -Wstack-protector
WARNS       = -Wall -Wextra -pedantic -Werror -Wno-unused-function

CFLAGS      = -fPIC -O3 $(STD) $(STACK) $(WARNS)
DEBUG       = -g3 -DDEBUG=1
LIBS        = -l cmocka -L /usr/lib -L $(LIB_DIR) -l $(LIB_NAME) -l $(LIB_NAME_EXT)
LIBS_STATIC = -l cmocka -L /usr/lib -L $(LIB_DIR) -l:lib$(LIB_NAME_EXT).a

######################################### RULES #######################################
all: $(TARGET_TEST) $(TARGET_TEST_STATIC)
	@echo "Done.";

$(TARGET_TEST): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(DEBUG) $(CFLAGS) $(LIBS)

$(TARGET_TEST_STATIC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(DEBUG) $(CFLAGS) $(LIBS) $(LIBS_STATIC)

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) -c $*.c -o $*.o $(DEBUG) $(CFLAGS)
	$(CC) -MM $(CFLAGS) $*.c > $*.d

clean:
	@rm -rvf $(TARGET_TEST) $(TARGET_TEST_STATIC) ./tmp/*.* ./*.o ./*.d ./log/*.log;

.PHONY: all clean