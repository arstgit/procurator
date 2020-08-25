CC=gcc

DEPS = core.h
BUILD = release
CFLAGS_release = 
CFLAGS_debug = -g -O0
CFLAGS = ${CFLAGS_${BUILD}}

# EXAMPLE: 
#   $ make clean && make BUILD=debug

all: procurator-local procurator-server

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

curltest.o: curltest.c
	$(CC) -c -o $@ $<

procurator-local: local.o core.o crypto.o
	$(CC) -o $@ $^ -lcrypto -lrdp

procurator-server: server.o core.o crypto.o
	$(CC) -o $@ $^ -lcrypto -lrdp

curltest: curltest.o
	$(CC) -o $@ $^

.PHONY: test
test: clean curltest procurator-local procurator-server
	./curltest

.PHONY: pretty
pretty:
	clang-format -i *.c *.h

.PHONY: anyway
anyway: clean all

.PHONY: install
install:
	cp procurator-local /usr/local/bin/procurator-local
	cp procurator-server /usr/local/bin/procurator-server

.PHONY: clean
clean:
	rm -f *.o procurator-local procurator-server curltest
