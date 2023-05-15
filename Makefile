all:
	$(MAKE) -C deps -f Makefile all
	$(MAKE) -C src -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C examples -f Makefile all
	$(MAKE) -C test -f Makefile all
	./runtests -v

lib:
	$(MAKE) -C deps -f Makefile all
	$(MAKE) -C src -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C examples -f Makefile all

clean:
	$(MAKE) -C src -f Makefile clean
	$(MAKE) -C src/ext -f Makefile clean
	$(MAKE) -C examples -f Makefile clean
	$(MAKE) -C test -f Makefile clean

cleanall:
	$(MAKE) -C deps -f Makefile clean
	$(MAKE) -C src -f Makefile clean
	$(MAKE) -C src/ext -f Makefile clean
	$(MAKE) -C examples -f Makefile clean
	$(MAKE) -C test -f Makefile clean

example:
	cd examples && export LD_LIBRARY_PATH=../lib && ./example1

test:
	./runtests

valgrind:
	./runtests -v

help:
	@echo "Target rules:"
	@echo "    all        - Build parser libraries, tests, and run tests."
	@echo "    lib        - Build parser libraries."
	@echo "    test       - Run tests with shared lib."
	@echo "    valgrind   - Run tests with static lib and valgrind."
	@echo "    example    - Run the example."
	@echo "    clean      - Clean without deps folders"
	@echo "    cleanall   - Clean including deps folders"
	@echo "    help       - Prints this message."


.PHONY: all clean test help valgrind lib