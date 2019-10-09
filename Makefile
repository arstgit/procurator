CC=gcc

DEPS = core.h
BUILD = release
CFLAGS_release = 
CFLAGS_debug = -g
CFLAGS = ${CFLAGS_${BUILD}}

REMOTE_HOST="\"127.0.0.1\"" 
REMOTE_PORT="\"8838\"" 
LOCAL_PORT="\"8080\""

# EXAMPLE: 
#   $ make clean && make REMOTE_HOST='"\"127.0.0.1\""' REMOTE_PORT='"\"8838\""' LOCAL_PORT='"\"8080\""' BUILD=debug

all: local server

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< -DREMOTE_HOST=$(REMOTE_HOST) -DREMOTE_PORT=$(REMOTE_PORT) -DLOCAL_PORT=$(LOCAL_PORT)

curltest.o: curltest.c
	$(CC) -c -o $@ $<

local: local.o core.o crypto.o
	$(CC) -o $@ $^ -lcrypto

server: server.o core.o crypto.o
	$(CC) -o $@ $^ -lcrypto

curltest: curltest.o
	$(CC) -o $@ $^

test: curltest local server
	./curltest

pretty:
	clang-format -i *.c *.h

install:
	cp local /usr/local/bin/procurator-local
	cp server /usr/local/bin/procurator-server

clean:
	rm -f *.o local server curltest

.PHONY: clean test pretty install

