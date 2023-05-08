all:
	$(MAKE) -C src -f Makefile $@
	$(MAKE) -C src/ext -f Makefile $@
	$(MAKE) -C examples -f Makefile $@
	$(MAKE) -C test -f Makefile $@
	./runtests -v

lib:
	$(MAKE) -C src -f Makefile all
	$(MAKE) -C src/ext -f Makefile all
	$(MAKE) -C examples -f Makefile all

clean:
	$(MAKE) -C src -f Makefile $@
	$(MAKE) -C src/ext -f Makefile $@
	$(MAKE) -C examples -f Makefile $@
	$(MAKE) -C test -f Makefile $@

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
	@echo "    clean      - "
	@echo "    help       - Prints this message."


.PHONY: all clean test help valgrind lib