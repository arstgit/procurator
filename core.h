#ifndef _CORE_H_
#define _CORE_H_

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"

#include "liblist/list.h"
#include "librdp/rdp.h"

// Log levels.
#define LL_DEBUG 0
#define LL_VERBOSE 1
#define LL_NOTICE 2
#define LL_WARNING 3
// Only used by config options, rdpSocket.verbosity specifically.
#define LL_SILIENT 9
// Modifier to log without timestamp.
#define LL_RAW (1 << 10)
// Default maximum length of log messages.
#define LOG_MAX_LEN 1024

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

#define CHECK_TIMEOUT_INTERVAL 5 * 1000

// A connection is allowed idle MAX_IDLE_TIME seconds at most.
#define MAX_IDLE_TIME 10 * 60 * 1000

extern char *remoteHost;
extern char *remotePort;
extern char *localPort;
extern char *password;

enum evtype { LISTEN, IN, OUT, RDP_IN, RDP_OUT, RDP_LISTEN };
enum evstate { ES_IDLE, ES_DESTROY };

struct evinfo {
  listNode *node;
  enum evstate state;
  enum evtype type;
  int fd;
  rdpConn *c;
  char stage;
  char outconnected;
  struct encryptor encryptor;
  int bufStartIndex;
  int bufEndIndex;
  int bufLen;
  char *buf;
  struct evinfo *ptr;
  uint64_t last_active;
};

struct connectPool {
  int fds[CONNECT_POOL_SIZE];
  int next;
};

void tlog(int level, const char *fmt, ...);

void clean(struct evinfo *einfo);

int sendOrStore(int self, void *buf, size_t len, int flags,
                struct evinfo *einfo);

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events, rdpConn *c);
int connOut(struct evinfo *, char *, char *);

void eloop(char *port,
           int (*handleIn)(struct evinfo *, unsigned char *, ssize_t));

int inetConnect(const char *host, const char *service, int type);

int inetListen(const char *service, int backlog, socklen_t *addrlen);

#endif
