# procurator

[![Build Status](https://travis-ci.org/derekchuank/procurator.svg?branch=master)](https://travis-ci.org/derekchuank/procurator)

## Super simple to use

Socks5 proxy client and server.

## Compile & Install

Don't forget to make your own `host` and `port` substitution.
```
  $ make REMOTE_HOST='"\"127.0.0.1\""' REMOTE_PORT='"\"8838\""' LOCAL_PORT='"\"8080\""'
  $ make install
```

## Usage

In local machine, run command:
```
  $ procurator-local
```

In remote machine, run command:
```
  $ procurator-server
```

## Test
```
  $ make clean && make test
```
