
PREFIX?=/usr/local

DESTDIR?=
INSTALL = /usr/bin/install -c
BINDIR=$(DESTDIR)$(PREFIX)/bin
LIBDIR=$(DESTDIR)$(PREFIX)/lib
INCDIR=$(DESTDIR)$(PREFIX)/include/librdb/

VERSION = $(shell grep -oP '(?<=LIBRDB_VERSION_STRING ")[0-9]+\.[0-9]+\.[0-9]+' ./src/lib/version.h)

# ------------------------- ALL --------------------------------------

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

distclean: clean

example: all
	cd examples && export LD_LIBRARY_PATH=../lib && ./example1

# ------------------------- DEBUG -------------------------------------

debug:
	OPTIMIZATION="-O0" LIBRDB_DEBUG=1 $(MAKE)

# ------------------------- TEST --------------------------------------

build_test: all
	$(MAKE) -C test -f Makefile all

test: build_test
	./runtests

valgrind: build_test
	./runtests -v

# ------------------------- INSTALL --------------------------------------
install: all
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) -m 755 bin/rdb-cli $(BINDIR)/rdb-cli-$(VERSION)
	ln -fsr $(BINDIR)/rdb-cli-$(VERSION) $(BINDIR)/rdb-cli
	$(INSTALL) -d $(LIBDIR)
	$(INSTALL) -m 755 lib/librdb.so $(LIBDIR)/librdb.so.$(VERSION)
	ln -fsr $(LIBDIR)/librdb.so.$(VERSION) $(LIBDIR)/librdb.so
	$(INSTALL) -m 755 lib/librdb-ext.so $(LIBDIR)/librdb-ext.so.$(VERSION)
	ln -fsr $(LIBDIR)/librdb-ext.so.$(VERSION) $(LIBDIR)/librdb-ext.so
	$(INSTALL) -m 755 lib/librdb.a $(LIBDIR)/librdb.a.$(VERSION)
	ln -fsr $(LIBDIR)/librdb.a.$(VERSION) $(LIBDIR)/librdb.a
	$(INSTALL) -m 755 lib/librdb-ext.a $(LIBDIR)/librdb-ext.a.$(VERSION)
	ln -fsr $(LIBDIR)/librdb-ext.a.$(VERSION) $(LIBDIR)/librdb-ext.a
	$(INSTALL) -d $(INCDIR)
	$(INSTALL) -m 644 api/librdb-api.h $(INCDIR)
	$(INSTALL) -m 644 api/librdb-ext-api.h $(INCDIR)

uninstall:
	rm -f $(BINDIR)/rdb-cli || true
	rm -f $(BINDIR)/rdb-cli-$(VERSION)
	rm -f $(LIBDIR)/librdb.so
	rm -f $(LIBDIR)/librdb.so.$(VERSION)
	rm -f $(LIBDIR)/librdb-ext.so
	rm -f $(LIBDIR)/librdb-ext.so.$(VERSION)
	rm -f $(LIBDIR)/librdb.a
	rm -f $(LIBDIR)/librdb.a.$(VERSION)
	rm -f $(LIBDIR)/librdb-ext.a
	rm -f $(LIBDIR)/librdb-ext.a.$(VERSION)
	rm -f $(INCDIR)/librdb-api.h
	rm -f $(INCDIR)/librdb-ext-api.h

# ------------------------- HELP --------------------------------------

help:
	@echo "librdb (v$(VERSION)) target rules:"
	@echo "    all        - Build parser libraries, tests, and run tests"
	@echo "    debug      - Build without compiler optimization and with assert() enabled"
	@echo "    test       - Run tests with shared lib"
	@echo "    valgrind   - Run tests with static lib and valgrind"
	@echo "    example    - Run the example"
	@echo "    clean      - Clean without deps folders"
	@echo "    distclean  - Clean including deps folders"
	@echo "    install    - install to (DESTDIR)/(PREFIX)/bin and (DESTDIR)/(PREFIX)/lib"
	@echo "                 By default PREFIX=/usr/local"
	@echo "    uninstall  - Remove from (DESTDIR)\(PREFIX)/bin and (DESTDIR)/(PREFIX)/lib"
	@echo "    help       - Prints this message"


.PHONY: all debug test valgrind example clean distclean install uninstall build_test help