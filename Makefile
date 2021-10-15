CC=gcc

DEPS = core.h librdp/rdp.h liblist/list.h
BUILD = release
CFLAGS_release = 
CFLAGS_debug = -g -O0
CFLAGS = ${CFLAGS_${BUILD}}

# EXAMPLE: 
#   $ make clean && make BUILD=debug

all: procurator-local procurator-server

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

librdp/librdp.a: librdp/rdp.h librdp/rdp.c
	cd librdp && make BUILD=$(BUILD)

ctest.o: ctest.c
	$(CC) -c -o $@ $<

procurator-local: local.o core.o crypto.o librdp/librdp.a liblist/list.o
	$(CC) -o $@ $^ -lcrypto

procurator-server: server.o core.o crypto.o librdp/librdp.a liblist/list.o
	$(CC) -o $@ $^ -lcrypto

ctest: ctest.o
	$(CC) -o $@ $^

.PHONY: test
test: clean ctest procurator-local procurator-server
	./ctest

.PHONY: pretty
pretty:
	clang-format -i *.c *.h

.PHONY: anyway
anyway: clean all

.PHONY: install
install:
	mkdir -p /bin
	install -m 755 -T procurator-local /bin/procurator-local
	install -m 755 -T procurator-server /bin/procurator-server

.PHONY: clean
clean:
	rm -f *.o **/*.o procurator-local procurator-server ctest
	cd librdp/ && make clean
