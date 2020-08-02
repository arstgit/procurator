#ifndef _CORE_H_
#define _CORE_H_

#define _BSD_SOURCE

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
// A connection is allowed idle MAX_IDLE_TIME seconds at most.
#define MAX_IDLE_TIME 10 * 60
// milliseconds
#define EPOLL_TIMEOUT (30 * 1000)

extern char *remoteHost;
extern char *remotePort;
extern char *localPort;
extern char *password;

enum evtype { LISTEN, IN, OUT };

struct evinfo {
  enum evtype type;
  int fd;
  char stage;
  char outconnected;
  struct encryptor encryptor;
  int bufStartIndex;
  int bufEndIndex;
  int bufLen;
  char *buf;
  struct evinfo *ptr;
  time_t last_active;
  struct evinfo *prev, *next;
};

struct connectPool {
  int fds[CONNECT_POOL_SIZE];
  int next;
};

enum elevel { LOWEST_LEVEL, INFO_LEVEL, ERR_LEVEL, HIGHEST_LEVEL };

void eprint(unsigned char *, int, ...);

void eprintf(const char *, ...);

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
