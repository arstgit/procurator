CC=gcc

DEPS = core.h

REMOTE_HOST="\"127.0.0.1\"" 
REMOTE_PORT="\"8838\"" 
LOCAL_PORT="\"8080\""

# EXAMPLE: 
#   $ make clean && make REMOTE_HOST='"\"127.0.0.1\""' REMOTE_PORT='"\"8838\""' LOCAL_PORT='"\"8080\""'

all: local server

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< -DREMOTE_HOST=$(REMOTE_HOST) -DREMOTE_PORT=$(REMOTE_PORT) -DLOCAL_PORT=$(LOCAL_PORT)

curltest.o: curltest.c
	$(CC) -c -o $@ $<

local: local.o core.o
	$(CC) -o $@ $^

server: server.o core.o
	$(CC) -o $@ $^

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

