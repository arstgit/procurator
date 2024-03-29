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
#include "librdp/libdict/dict.h"
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

#define BUF_SIZE (16 * 1024 * 1024)
#define TMP_BUF_SIZE BUF_SIZE
#define MAX_EVENTS 20
#define BUF_FACTOR1 1
#define BUF_FACTOR2 16
#define CONNECT_POOL_SIZE 2

#define CHECK_IDLE_INTERVAL (10 * 1000)
#define CHECK_DESTROY_INTERVAL (200)

// A connection is allowed idle MAX_IDLE_TIME seconds at most.
#define MAX_IDLE_TIME (30 * 1000)

// UDP relay entry registration timeout.
#define MAX_UDP_IDLE_TIME (30 * 1000)

// Function return value.
#define RETEOF (1)

extern char *version;
extern char *remoteHost;
extern char *remotePort;
// todo duplicated?
extern char *remoteUdpPort;
extern char *localPort;
extern char *localUdpPort;
extern char *password;

enum evtype {
  UDP_LISTEN_IN,
  UDP_LISTEN_OUT,
  PROCURATOR_TCP_LISTEN,
  IN,
  OUT,
  RDP_IN,
  RDP_OUT,
  RDP_LISTEN
};

enum evstate { ES_HALF_OPENED, ES_CONNECTING, ES_OPENED, ES_CLOSED, ES_HALF_CLOSED };

struct evinfo {
  listNode *node;
  enum evstate state;
  enum evtype type;
  int fd;
  rdpConn *c;
  char stage; // Sockets stage.
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
  struct evinfo *einfos[CONNECT_POOL_SIZE];
  int next;
};

void tlog(int level, const char *fmt, ...);

void clean(struct evinfo *einfo);

int sendOrStore(int self, void *buf, size_t len, int flags,
                struct evinfo *einfo);

ssize_t sendUdpIn(struct evinfo *einfo, unsigned char *buf, size_t buflen,
                  struct sockaddr_storage *addr, socklen_t addrlen);

ssize_t sendUdpOut(struct evinfo *einfo, unsigned char *buf, size_t buflen,
                   char *host, char *port);

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events, rdpConn *c);
int connOut(struct evinfo *, char *, char *);

void eloop(char *port, char *udpPort,
           int (*handleInData)(struct evinfo *, unsigned char *, ssize_t),
           int (*handleUdpIn)(struct evinfo *, unsigned char *, ssize_t,
                              struct sockaddr *, socklen_t),
           int (*handleUdpOut)(struct evinfo *, unsigned char *, ssize_t,
                               struct sockaddr *, socklen_t));

int getaddrinfoWithoutHints(const char *host, const char *service,
                            struct addrinfo **result);

int inetConnect(const char *host, const char *service, int type);

int inetListen(const char *service, int backlog, socklen_t *addrlen);

int udpRelayDictAddOrUpdate(void *key, struct sockaddr_storage *addr,
                            socklen_t addrlen);

int udpRelayDictGetBySockaddr(struct sockaddr *src_addr, socklen_t addrlen,
                              unsigned char *keybuf,
                              struct sockaddr_storage **dst_addr,
                              socklen_t *dst_addrlen);

int udpRelayDictGetByKey(void *key, struct sockaddr_storage **dst_addr,
                         socklen_t *dst_addrlen);

#endif
