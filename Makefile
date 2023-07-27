ifeq ($(BUILD_TLS),yes)
export BUILD_TLS
endif

# DESTDIR Specifies library installation folder
DESTDIR?=/usr/local/lib

all:
	$(MAKE) -C deps -f Makefile all
	$(MAKE) -C src/lib -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C src/cli -f Makefile all
	$(MAKE) -C examples -f Makefile all
	$(MAKE) -C test -f Makefile all
	./runtests -v

lib:
	$(MAKE) -C deps -f Makefile all
	$(MAKE) -C src/lib -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C examples -f Makefile all

clean:
	$(MAKE) -C deps -f Makefile clean
	$(MAKE) -C src/lib -f Makefile clean
	$(MAKE) -C src/ext -f Makefile clean
	$(MAKE) -C src/cli -f Makefile clean
	$(MAKE) -C examples -f Makefile clean
	$(MAKE) -C test -f Makefile clean

distclean:
	$(MAKE) -C deps -f Makefile clean
	$(MAKE) -C src/lib -f Makefile clean
	$(MAKE) -C src/ext -f Makefile clean
	$(MAKE) -C src/cli -f Makefile clean
	$(MAKE) -C examples -f Makefile clean
	$(MAKE) -C test -f Makefile clean

example:
	cd examples && export LD_LIBRARY_PATH=../lib && ./example1

test:
	./runtests

valgrind:
	./runtests -v

install: lib
	cp lib/librdb.so $(DESTDIR)
	cp lib/librdb-ext.so $(DESTDIR)

help:
	@echo "Target rules:"
	@echo "    all        - Build parser libraries, tests, and run tests."
	@echo "    lib        - Build parser libraries."
	@echo "    test       - Run tests with shared lib."
	@echo "    valgrind   - Run tests with static lib and valgrind."
	@echo "    example    - Run the example."
	@echo "    clean      - Clean without deps folders"
	@echo "    distclean  - Clean including deps folders"
	@echo "    install    - Build parser libraries and copy to DESTDIR."
	@echo "    help       - Prints this message."


.PHONY: all clean test help valgrind lib