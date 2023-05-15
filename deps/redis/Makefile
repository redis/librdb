SOURCES = $(notdir $(basename $(wildcard *.c)))
OBJECTS = $(patsubst %,%.o,$(SOURCES))

CC             = gcc
STD            = -std=gnu99
WARNS          = -Wall -Wextra -pedantic -Werror
CFLAGS         = -fPIC -O3 $(STD) $(WARNS)
DEBUG          = -g3 -DDEBUG=1
LIBS           =

all: $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(DEBUG) $(LIBS)
	$(CC) -MM $(CFLAGS) $< > $*.d

# Include object file dependencies
-include $(OBJECTS:.o=.d)

clean:
	@rm -rvf ./*.o ./*.d

.PHONY: all clean
