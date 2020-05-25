# procurator

[![Test Status](https://github.com/derekchuank/procurator/workflows/Test/badge.svg)](https://github.com/derekchuank/procurator/actions)

## Super simple to use

Socks5 proxy client and server.

## Design

[www.tiaoxingyubolang.com](https://www.tiaoxingyubolang.com/article/2020-03-22_procurator1)

## Compile & Install

Don't forget to make your own `host` and `port` substitution.
```
  $ make
  $ make install
```

## Usage

In local machine, run command:
```
  $ procurator-local --remote-host 127.0.0.1 --remote-port 8080 --local-port 1080
```

In remote machine, run command:
```
  $ procurator-server --remote-port 8080
```

## Test
```
  $ make clean && make test
```
