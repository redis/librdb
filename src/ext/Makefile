default: all

LIB_NAME              = rdb
LIB_NAME_EXT          = $(LIB_NAME)-ext
LIB_DIR               = ../../lib

TARGET_LIB_STATIC     = $(LIB_DIR)/lib$(LIB_NAME).a
# Artifacts:
TARGET_LIB_EXT        = $(LIB_DIR)/lib$(LIB_NAME_EXT).so
TARGET_LIB_STATIC_EXT = $(LIB_DIR)/lib$(LIB_NAME_EXT).a

#########################################################################################
SOURCES  = $(notdir $(basename $(wildcard *.c)))
OBJECTS  = $(patsubst %,%.o,$(SOURCES))

CC       = gcc
STD      = -std=gnu99
STACK    = -fstack-protector-all -Wstack-protector
WARNS    = -Wall -Wextra -pedantic -Werror
CFLAGS   = -fPIC -O3 $(STD) $(STACK) $(WARNS) $(EXTERN_RP_CONFIG)
DEBUG    = -g3 -DDEBUG=1
LIBS     = -L $(LIB_DIR) -l $(LIB_NAME)

######################################### RULES #######################################
all: $(TARGET_LIB_EXT) $(TARGET_LIB_STATIC_EXT)
	@echo "Done.";

$(TARGET_LIB_EXT): $(OBJECTS)
	$(CC) -o $@ -shared ${LDFLAGS} $^  $(LIBS)

$(TARGET_LIB_STATIC_EXT): $(OBJECTS)
	ar rcs $@ $^

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c -o $*.o $(DEBUG)
	$(CC) -MM $(CFLAGS) $*.c > $*.d

clean:
	@rm -rvf $(TARGET_LIB_EXT) $(TARGET_LIB_STATIC_EXT) ./*.o ./*.d;
