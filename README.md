# procurator

[![Test Status](https://github.com/derekchuank/procurator/workflows/Test/badge.svg)](https://github.com/derekchuank/procurator/actions)

## Super simple to use

Socks5 proxy client and server.

## Design

[www.tiaoxingyubolang.com](https://www.tiaoxingyubolang.com/article/2020-03-22_procurator1)

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
