#ifndef _CORE_H_
#define _CORE_H_

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef REMOTE_HOST
#define REMOTE_HOST "127.0.0.1"
#endif

#ifndef REMOTE_PORT
#define REMOTE_PORT "8838"
#endif

#ifndef LOCAL_PORT
#define LOCAL_PORT "8080"
#endif

#define BUF_SIZE 16384
#define MAX_EVENTS 20

enum evtype { LISTEN, IN, OUT };

struct evinfo {
  enum evtype type;
  int fd;
  int stage;
  struct evinfo *ptr;
};

int efd;
char buf[BUF_SIZE];

void clean(struct evinfo *einfo);

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events);

int connOut(struct evinfo *einfo, char *outhost, char *outport);

int connOutCpl(struct evinfo *einfo);

int handleOut(struct evinfo *einfo);

void eloop(char *port, int (*handleIn)(struct evinfo *));

int inetConnect(const char *host, const char *service, int type);

int inetListen(const char *service, int backlog, socklen_t *addrlen);

#endif
