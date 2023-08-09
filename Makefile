ifeq ($(BUILD_TLS),yes)
export BUILD_TLS
endif

# DESTDIR Specifies library installation folder
LDCONFIG=ldconfig
PREFIX?=/usr/local
DESTDIR?=/usr/local/lib
INSTALL_BIN=$(PREFIX)/bin

all:
	$(MAKE) -C deps -f Makefile all
	$(MAKE) -C src/lib -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C src/cli -f Makefile all
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
	$(MAKE) -C test -f Makefile all
	./runtests

valgrind:
	$(MAKE) -C test -f Makefile all
	./runtests -v

install: all
	cp lib/librdb.so $(DESTDIR)
	cp lib/librdb-ext.so $(DESTDIR)
	cp bin/rdb-cli $(INSTALL_BIN)
	($(LDCONFIG) || true)  >/dev/null 2>&1;

uninstall:
	rm -f $(DESTDIR)/lib/librdb.so
	rm -f $(DESTDIR)/lib/librdb-ext.so
	rm -f $(INSTALL_BIN)/rdb-cli

help:
	@echo "Target rules:"
	@echo "    all        - Build parser libraries, tests, and run tests."
	@echo "    test       - Run tests with shared lib."
	@echo "    valgrind   - Run tests with static lib and valgrind."
	@echo "    example    - Run the example."
	@echo "    clean      - Clean without deps folders"
	@echo "    distclean  - Clean including deps folders"
	@echo "    install    - Build parser libraries and copy to DESTDIR (?=/usr/local/lib)"
	@echo "    uninstall  - Remove libraries from DESTDIR."
	@echo "    help       - Prints this message."


.PHONY: all clean test help valgrind install uninstall