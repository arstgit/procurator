# procurator

[![Test Status](https://github.com/derekchuank/procurator/workflows/Test/badge.svg)](https://github.com/derekchuank/procurator/actions)

## Super simple to use

Socks5 proxy client and server. UDP relay support. More aggressive packet sending strategy, using `librdp`.

## Design

[www.tiaoxingyubolang.com](https://www.tiaoxingyubolang.com/article/2020-03-22_procurator1)

## Prerequisites
Environment: 
  - Linux.

Libraries: 
  - libssl-dev.
  - librdp. https://github.com/derekchuank/librdp. Needed only after version v1.0.0. In fact, after that, the connections between procurator-local and procurator-server switched from TCP to UDP.

## Compile & Install

```
  $ make
  $ make install
```

## Usage

On your local machine, run:
```
  $ procurator-local --remote-host 127.0.0.1 \
      --remote-port 8080 \
      --remote-udp-port 8081 \
      --local-port 1080 \
      --local-udp-port 1081 \
      --password foobar \
      --udp-target-host 8.8.8.8 \
      --udp-target-port 53
```

- `--udp-target-host` and `--udp-target-port` aren't required, if you are not planning to establish a direct(no socks5 involved) udp port relay, usually for DNS forwarding.

On remote machine, run:
```
  $ procurator-server --remote-port 8080 --remote-udp-port 8081 --password foobar
```

## Test
```
  $ make clean && make test
```
