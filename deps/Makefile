all:
	$(MAKE) -C redis -f Makefile all
	$(MAKE) -C hiredis -f Makefile all

clean:
	$(MAKE) -C redis -f Makefile clean
	$(MAKE) -C hiredis -f Makefile clean


.PHONY: all clean