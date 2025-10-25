
PREFIX ?= /usr/local

DESTDIR ?=
INSTALL = /usr/bin/install -c
BINDIR = $(DESTDIR)$(PREFIX)/bin
LIBDIR = $(DESTDIR)$(PREFIX)/lib
INCDIR = $(DESTDIR)$(PREFIX)/include/librdb/
LIBRDB_INSTALL_SHARED := yes
LIBRDB_INSTALL_STATIC := yes

UNAME := $(shell uname)

# Set ln flags based on OS (macOS doesn't support -r flag)
ifeq ($(UNAME),Darwin)
	LN_FLAGS = -fs
else
	LN_FLAGS = -fsr
endif

ifneq (,$(filter $(UNAME),OpenBSD FreeBSD NetBSD))
	PKGCONFIGDIR = $(DESTDIR)$(PREFIX)/libdata/pkgconfig
else
	PKGCONFIGDIR = $(LIBDIR)/pkgconfig
endif

LIBRDB_VERSION = $(shell sed -n 's|^\#define LIBRDB_VERSION_STRING "\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\)"|\1|p' ./src/version.h)
export LIBRDB_VERSION

# ------------------------- ALL --------------------------------------

all: ./deps/hiredis/hiredis.h
	$(MAKE) -C deps all
	$(MAKE) -C src/lib all
	$(MAKE) -C src/ext all
	$(MAKE) -C src/cli all
	$(MAKE) -C examples all

clean:
	$(MAKE) -C deps clean
	$(MAKE) -C src/lib clean
	$(MAKE) -C src/ext clean
	$(MAKE) -C src/cli clean
	$(MAKE) -C examples clean
	$(MAKE) -C test clean
	rm -f librdb.pc
	rm -f librdb-ext.pc

example: all
	cd examples && export LD_LIBRARY_PATH=../lib && ./example1

./deps/hiredis/hiredis.h:
	git submodule update --init deps/hiredis

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

librdb.pc: librdb.pc.in Makefile
	sed -e 's|@PREFIX@|$(PREFIX)|' \
        -e 's|@VERSION@|$(LIBRDB_VERSION)|' \
         $< >$@

librdb-ext.pc: librdb-ext.pc.in Makefile
	sed -e 's|@PREFIX@|$(PREFIX)|' \
        -e 's|@VERSION@|$(LIBRDB_VERSION)|' \
         $< >$@

install: all librdb.pc librdb-ext.pc
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) -m 755 bin/rdb-cli $(BINDIR)/rdb-cli-$(LIBRDB_VERSION)
	ln $(LN_FLAGS) $(BINDIR)/rdb-cli-$(LIBRDB_VERSION) $(BINDIR)/rdb-cli
	$(INSTALL) -d $(LIBDIR)

ifeq ($(LIBRDB_INSTALL_SHARED),yes)
	$(INSTALL) -m 755 lib/librdb.so.$(LIBRDB_VERSION) $(LIBDIR)/librdb.so.$(LIBRDB_VERSION)
	ln $(LN_FLAGS) $(LIBDIR)/librdb.so.$(LIBRDB_VERSION) $(LIBDIR)/librdb.so
	$(INSTALL) -m 755 lib/librdb-ext.so.$(LIBRDB_VERSION) $(LIBDIR)/librdb-ext.so.$(LIBRDB_VERSION)
	ln $(LN_FLAGS) $(LIBDIR)/librdb-ext.so.$(LIBRDB_VERSION) $(LIBDIR)/librdb-ext.so
	$(INSTALL) -d $(PKGCONFIGDIR)
	$(INSTALL) -m 644 librdb.pc $(PKGCONFIGDIR)
	$(INSTALL) -m 644 librdb-ext.pc $(PKGCONFIGDIR)
endif

ifeq ($(LIBRDB_INSTALL_STATIC),yes)
	$(INSTALL) -m 755 lib/librdb.a $(LIBDIR)/librdb.a.$(LIBRDB_VERSION)
	ln $(LN_FLAGS) $(LIBDIR)/librdb.a.$(LIBRDB_VERSION) $(LIBDIR)/librdb.a
	$(INSTALL) -m 755 lib/librdb-ext.a $(LIBDIR)/librdb-ext.a.$(LIBRDB_VERSION)
	ln $(LN_FLAGS) $(LIBDIR)/librdb-ext.a.$(LIBRDB_VERSION) $(LIBDIR)/librdb-ext.a
endif

	$(INSTALL) -d $(INCDIR)
	$(INSTALL) -m 644 api/librdb-api.h $(INCDIR)
	$(INSTALL) -m 644 api/librdb-ext-api.h $(INCDIR)

uninstall:
	rm -f $(BINDIR)/rdb-cli || true
	rm -f $(BINDIR)/rdb-cli-$(LIBRDB_VERSION)
	rm -f $(LIBDIR)/librdb.so
	rm -f $(LIBDIR)/librdb.so.$(LIBRDB_VERSION)
	rm -f $(LIBDIR)/librdb-ext.so
	rm -f $(LIBDIR)/librdb-ext.so.$(LIBRDB_VERSION)
	rm -f $(LIBDIR)/librdb.a
	rm -f $(LIBDIR)/librdb.a.$(LIBRDB_VERSION)
	rm -f $(LIBDIR)/librdb-ext.a
	rm -f $(LIBDIR)/librdb-ext.a.$(LIBRDB_VERSION)
	rm -f $(INCDIR)/librdb-api.h
	rm -f $(INCDIR)/librdb-ext-api.h
	rm -f $(PKGCONFIGDIR)/librdb.pc
	rm -f $(PKGCONFIGDIR)/librdb-ext.pc

# ------------------------- HELP --------------------------------------

help:
	@echo "librdb (v$(LIBRDB_VERSION)) target rules:"
	@echo "    all        - Build parser libraries, tests, and run tests"
	@echo "    debug      - Build without compiler optimization and with assert() enabled"
	@echo "    test       - Run tests with shared lib"
	@echo "    valgrind   - Run tests with static lib and valgrind"
	@echo "    example    - Run the example"
	@echo "    clean      - Clean without deps folders"
	@echo "    install    - install to (DESTDIR)/(PREFIX)/bin and (DESTDIR)/(PREFIX)/lib"
	@echo "                 By default PREFIX=/usr/local"
	@echo "    uninstall  - Remove from (DESTDIR)\(PREFIX)/bin and (DESTDIR)/(PREFIX)/lib"
	@echo "    help       - Prints this message"


.PHONY: all debug test valgrind example clean install uninstall build_test help
