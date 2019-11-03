#ifndef _CORE_H_
#define _CORE_H_

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"

#ifndef REMOTE_HOST
#define REMOTE_HOST "127.0.0.1"
#endif

#ifndef REMOTE_PORT
#define REMOTE_PORT "8838"
#endif

#ifndef LOCAL_PORT
#define LOCAL_PORT "8080"
#endif

#define TCPKEEPALIVE 1;
#define TCPKEEPIDLE 2;
#define TCPKEEPINTVL 2;
#define TCPKEEPCNT 5;

#define BUF_SIZE (212992 * 16)
#define TMP_BUF_SIZE BUF_SIZE
#define MAX_EVENTS 20
#define BUF_FACTOR1 1
#define BUF_FACTOR2 16
#define CONNECT_POOL_SIZE 8

enum evtype { LISTEN, IN, OUT };

struct evinfo {
  enum evtype type;
  int fd;
  int stage;
  int outconnected;
  void *encryptCtx;
  void *decryptCtx;
  int bufStartIndex;
  int bufEndIndex;
  int bufLen;
  char *buf;
  struct evinfo *ptr;
};

struct connectPool {
  int fds[CONNECT_POOL_SIZE];
  int next;
} connPool;

int efd;
unsigned char buf[BUF_SIZE];
unsigned char tmpBuf[TMP_BUF_SIZE];
int serverflag;
int connectPool[CONNECT_POOL_SIZE];

enum elevel { LOWEST_LEVEL, INFO_LEVEL, ERR_LEVEL, HIGHEST_LEVEL };

void eprint(int, unsigned char *, int, int);

void clean(struct evinfo *einfo);

int sendOrStore(int fd, void *buf, size_t len, int flags, struct evinfo *einfo,
                int storeSelf);

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events);
int connOut(struct evinfo *, char *, char *);

void eloop(char *port,
           int (*handleIn)(struct evinfo *, unsigned char *, ssize_t));

int inetConnect(const char *host, const char *service, int type);

int inetListen(const char *service, int backlog, socklen_t *addrlen);

#endif
