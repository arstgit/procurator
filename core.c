#include "core.h"

unsigned char key[32];
unsigned char iv[16];

int globalElevel = INFO_LEVEL;

// User input config.
char *remoteHost;
char *remotePort;
char *localPort;
char *password;

struct evinfo *dumbevhead, *listenevinfo;
struct connectPool connPool;

int efd;
unsigned char buf[BUF_SIZE];
unsigned char tmpBuf[TMP_BUF_SIZE];
int serverflag;
int connectPool[CONNECT_POOL_SIZE];

void eprint(unsigned char *str, int num, ...) {
  va_list valist;
  int fd;
  int elevel;
  int perrorflag;
  time_t now;

  if (num > 3) {
    exit(EXIT_FAILURE);
  }

  va_start(valist, num);

  fd = STDOUT_FILENO;
  elevel = INFO_LEVEL;
  perrorflag = 0;
  for (int i = 0; i < num; i++) {
    switch (i) {
    case 0:
      fd = va_arg(valist, int);
      break;
    case 1:
      elevel = va_arg(valist, int);
      break;
    case 2:
      perrorflag = va_arg(valist, int);
      break;
    }
  }

  if (elevel < globalElevel)
    return;

  now = time(NULL);
  if (now == -1) {
    perror("time, eprint");
    exit(EXIT_FAILURE);
  }

  if (write(fd, ctime(&now), strlen(ctime(&now)) - 1) == -1) {
    perror("write, eprint, time");
    exit(EXIT_FAILURE);
  }
  if (write(fd, " ", 1) == -1) {
    perror("write, eprint, space");
    exit(EXIT_FAILURE);
  }

  if (perrorflag == 1) {
    perror(str);
    return;
  }

  if (elevel == INFO_LEVEL) {
    if (write(fd, str, strlen(str)) == -1) {
      perror("write, eprint");
      exit(EXIT_FAILURE);
    }
  }
  if (elevel == ERR_LEVEL) {
    if (write(fd, str, strlen(str)) == -1) {
      perror("write, eprint");
      exit(EXIT_FAILURE);
    }
  }

  va_end(valist);
  return;
}

static int setnonblocking(int fd) {
  int flags;

  flags = fcntl(fd, F_GETFL);
  if (flags == -1) {
    perror("fcntl: setnonblocking, F_GETFL");
    return -1;
  }
  flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) < 0) {
    perror("fcntl: setnonblocking, F_SETFL");
    return -1;
  }
}

void eprintf(const char *fmt, ...) {
  int size = 0;
  char *p = NULL;
  va_list ap;

  va_start(ap, fmt);
  size = vsnprintf(p, size, fmt, ap);
  va_end(ap);

  if (size < 0)
    return;

  size++; /* For '\0' */
  p = malloc(size);
  if (p == NULL)
    return;

  va_start(ap, fmt);
  size = vsnprintf(p, size, fmt, ap);
  va_end(ap);

  if (size < 0) {
    free(p);
    return;
  }

  eprint(p, 0);

  free(p);
  return;
}

static int populateKeyIv() {
  unsigned char feed[128];

  memcpy(feed, password, strlen(password));
  MD5(feed, strlen(password), key);

  memcpy(feed, key, 16);
  memcpy(feed + 16, password, strlen(password));
  MD5(feed, strlen(password) + 16, key + 16);

  memcpy(feed, key + 16, 16);
  memcpy(feed + 16, password, strlen(password));
  MD5(feed, strlen(password) + 16, iv);

  return 0;
}

int inetConnect(const char *host, const char *service, int type) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s, flags, conn, optval;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = type;

  s = getaddrinfo(host, service, &hints, &result);
  if (s != 0) {
    errno = ENOSYS;
    return -1;
  }
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    optval = 1;
    if (setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) ==
        -1) {
      close(sfd);
      sfd = -1;
      continue;
    }
    if (setnonblocking(sfd) == -1) {
      close(sfd);
      sfd = -1;
      continue;
    }

    conn = connect(sfd, rp->ai_addr, rp->ai_addrlen);
    if (conn < 0 && errno != EINPROGRESS) {
      close(sfd);
      sfd = -1;
      continue;
    }

    break;
  }

  freeaddrinfo(result);

  return (rp == NULL) ? -1 : sfd;
}

int inetPassiveSocket(const char *service, int type, socklen_t *addrlen,
                      int doListen, int backlog) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, optval, s, flags;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  hints.ai_socktype = type;
  hints.ai_family = AF_UNSPEC; /* Allows IPv4 or IPv6 */
  hints.ai_flags = AI_PASSIVE; /* Use wildcard IP address */

  s = getaddrinfo(NULL, service, &hints, &result);
  if (s != 0)
    return -1;

  optval = 1;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (doListen) {
      if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) ==
          -1) {
        close(sfd);
        freeaddrinfo(result);
        return -1;
      }

      optval = 1;
      if (setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) ==
          -1) {
        close(sfd);
        freeaddrinfo(result);
        return -1;
      }

      if (setnonblocking(sfd) == -1) {
        close(sfd);
        freeaddrinfo(result);
        return -1;
      }
    }

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sfd);
  }

  if (rp != NULL && doListen) {
    if (listen(sfd, backlog) == -1) {
      freeaddrinfo(result);
      return -1;
    }
  }

  if (rp != NULL && addrlen != NULL)
    *addrlen = rp->ai_addrlen;

  freeaddrinfo(result);

  return (rp == NULL) ? -1 : sfd;
}

int inetListen(const char *service, int backlog, socklen_t *addrlen) {
  return inetPassiveSocket(service, SOCK_STREAM, addrlen, 1, backlog);
}

void cleanOne(struct evinfo *einfo) {
  if (einfo->bufEndIndex - einfo->bufStartIndex > 0) {
    printf("clean with Num: %d\n", einfo->bufEndIndex - einfo->bufStartIndex);
    fflush(stdout);
  }
  if (close(einfo->fd) == -1) {
    perror("clean: close");
    exit(EXIT_FAILURE);
  }

  if (einfo->bufLen > 0) {
    free(einfo->buf);
  }
  freeCipher(&einfo->encryptor);

  if (einfo->type == IN) {
    einfo->prev->next = einfo->next;
    einfo->next->prev = einfo->prev;
  }

  free(einfo);
}

void clean(struct evinfo *einfo) {
  if (einfo->ptr != NULL) {
    cleanOne(einfo->ptr);
  }
  cleanOne(einfo);
}

static int trySend(struct evinfo *einfo) {
  ssize_t numSend;
  size_t len;
  unsigned char *buf;

  len = einfo->bufEndIndex - einfo->bufStartIndex;
  buf = einfo->buf + einfo->bufStartIndex;
  for (; len > 0;) {
    numSend = send(einfo->fd, buf, len, 0);
    if (numSend == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else {
        perror("send: trysend");
        return -1;
      }
    } else {
      len -= numSend;
      buf = buf + numSend;
    }
  }
  if (len == 0)
    einfo->bufEndIndex = 0;
  einfo->bufStartIndex = einfo->bufEndIndex - len;
  return 0;
}

int sendOrStore(int fd, void *buf, size_t len, int flags, struct evinfo *einfo,
                int storeSelf) {
  ssize_t numSend;

  einfo = storeSelf == 1 ? einfo : einfo->ptr;

  if ((serverflag == 1 && einfo->type == IN) ||
      (serverflag == 0 && einfo->type == OUT)) {
    int tmpLen;

    if (encrypt(&einfo->encryptor, tmpBuf, &tmpLen, buf, len, key, iv) == -1) {
      perror("encrypt, 1");
      return -1;
    }
    buf = tmpBuf;
    len = tmpLen;
  }

  if (einfo->bufEndIndex > 0) {
    // Expand buf size.
    if (einfo->bufEndIndex + len > einfo->bufLen) {
      einfo->buf =
          realloc(einfo->buf, BUF_FACTOR2 * (einfo->bufEndIndex + len));
      if (einfo->buf == NULL) {
        eprintf("realloc step1\n");
        return -1;
      }
      einfo->bufLen = BUF_FACTOR2 * (einfo->bufEndIndex + len);
    }

    memcpy(einfo->buf + einfo->bufEndIndex, buf, len);
    einfo->bufEndIndex = einfo->bufEndIndex + len;

    len = einfo->bufEndIndex - einfo->bufStartIndex;
    buf = einfo->buf + einfo->bufStartIndex;
  }

  for (; len > 0;) {
    numSend = send(fd, buf, len, flags);
    if (numSend == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // to do
        if (einfo->bufEndIndex == 0) {
          if (len > einfo->bufLen) {
            einfo->buf = realloc(einfo->buf, BUF_FACTOR1 * len);

            if (einfo->buf == NULL) {
              eprintf("realloc step2\n");
              return -1;
            }
            einfo->bufLen = BUF_FACTOR1 * len;
          }

          memcpy(einfo->buf, buf, len);
          einfo->bufEndIndex = einfo->bufStartIndex + len;
        }
        break;
      } else {
        perror("send: sendOrStore");
        return -1;
      }
    } else {
      len -= numSend;
      buf = buf + numSend;
    }
  }
  if (len == 0)
    einfo->bufEndIndex = 0;
  einfo->bufStartIndex = einfo->bufEndIndex - len;

  return 0;
}

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events) {
  struct evinfo *einfo;
  struct epoll_event ev;
  time_t now;

  now = time(NULL);
  if (now == -1) {
    perror("time, evinfo");
    exit(EXIT_FAILURE);
  }

  if (events & EPOLLET) {
    if (setnonblocking(fd) == -1) {
      perror("eadd setnonblocking");
      exit(EXIT_FAILURE);
    }
  }

  einfo = malloc(sizeof(struct evinfo));
  if (einfo == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  einfo->type = type;
  einfo->fd = fd;
  einfo->stage = stage;
  einfo->outconnected = 0;
  einfo->bufStartIndex = 0;
  einfo->bufEndIndex = 0;
  einfo->bufLen = 0;
  einfo->buf = NULL;
  einfo->ptr = ptr;
  einfo->last_active = now;

  einfo->encryptor.encryptCtx = NULL;
  einfo->encryptor.decryptCtx = NULL;
  einfo->encryptor.sentIv = 0;
  einfo->encryptor.receivedIv = 0;

  if (einfo->type == IN) {
    dumbevhead->prev->next = einfo;
    einfo->prev = dumbevhead->prev;
    dumbevhead->prev = einfo;
    einfo->next = dumbevhead;
  } else {
    einfo->prev = NULL;
    einfo->next = NULL;
  }

  ev.data.ptr = einfo;
  ev.events = events;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_ctl: connfd");
    exit(EXIT_FAILURE);
  }
  return einfo;
}

static int checkConnected(int fd) {
  int result;

  socklen_t result_len = sizeof(result);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
    // error, fail somehow, close socket
    perror("getsockopt");
    return -1;
  }
  if (result != 0) {
    // eprint(STDERR_FILENO, "checkConnected reasult not 0.\n", INFO_LEVEL, 1);
    return -1;
  }

  return 0;
}

static int connOutConnected(struct evinfo *einfo) {
  return checkConnected(einfo->fd);
}

int setkeepalive(int fd) {
  int optval;

  optval = TCPKEEPALIVE;
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == -1) {
    return -1;
  }
  optval = TCPKEEPIDLE;
  if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) == -1) {
    return -1;
  }
  optval = TCPKEEPINTVL;
  if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) == -1) {
    return -1;
  }
  optval = TCPKEEPCNT;
  if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) == -1) {
    return -1;
  }

  return 0;
}

int connOut(struct evinfo *einfo, char *outhost, char *outport) {
  int outfd, tmpfd;
  ssize_t numRead;

  if (serverflag == 0) {
    outfd = connPool.fds[connPool.next];
    numRead = recv(outfd, buf, BUF_SIZE, MSG_PEEK);
    // if (numRead == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    if (checkConnected(outfd) == 0 && numRead == -1 &&
        (errno == EAGAIN || errno == EWOULDBLOCK)) {
    } else {
      if (numRead == -1) {
        perror("recv, connOut");
      }
      if (numRead > 0) {
        eprintf("recv, connOut, numRead > 0.");
      }

      if (close(outfd) == -1) {
        perror("close, connOut");
        return -1;
      }
      outfd = inetConnect(outhost, outport, SOCK_STREAM);
      if (outfd == -1) {
        perror("inetConnect, connOut local1");
        return -1;
      }
      if (setkeepalive(outfd) == -1) {
        if (close(outfd) == -1) {
          perror("close, connOut, setkeepalive");
        }
        return -1;
      }
    }

    tmpfd = inetConnect(outhost, outport, SOCK_STREAM);
    if (tmpfd == -1) {
      perror("inetConnect, connOut local2");
      return -1;
    }
    if (setkeepalive(tmpfd) == -1) {
      if (close(tmpfd) == -1) {
        perror("close, connOut, setkeepalive");
      }
      return -1;
    }
    connPool.fds[connPool.next] = tmpfd;
    if (connPool.next++ == CONNECT_POOL_SIZE - 1)
      connPool.next = 0;
  } else {
    outfd = inetConnect(outhost, outport, SOCK_STREAM);
    if (outfd == -1) {
      perror("inetConnect, connOut server");
      return -1;
    }
  }

  einfo->ptr = eadd(OUT, outfd, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET);

  return 0;
}

static int handleOutData(struct evinfo *einfo, unsigned char *buf,
                         ssize_t numRead) {
  int infd = einfo->ptr->fd;

  if (sendOrStore(infd, buf, numRead, 0, einfo, 0) == -1) {
    perror("sendOrStore: handleOut");
    return -1;
  }
  return 0;
}

static int handleIn(struct evinfo *einfo,
                    int (*handleInData)(struct evinfo *, unsigned char *,
                                        ssize_t)) {
  int infd = einfo->fd;
  ssize_t numRead;
  unsigned char *bufp;
  bufp = buf;

  for (;;) {
    numRead = recv(infd, buf, BUF_SIZE, 0);
    if (numRead == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else {
        perror("handleIn recv");
        return -1;
      }
    }
    if (numRead == 0) {
      return -1;
    }
    if (numRead > 0) {
      if ((serverflag == 1 && einfo->type == IN) ||
          (serverflag == 0 && einfo->type == OUT)) {
        int tmpLen;
        if (decrypt(&einfo->encryptor, tmpBuf, &tmpLen, buf, numRead, key,
                    iv) == -1) {
          eprintf("encrypt, handleIn");
          return -1;
        }
        if (tmpLen > TMP_BUF_SIZE) {
          eprintf("recv, handleIn, tmpLen > TMP_BUF_SIZE");
          exit(EXIT_FAILURE);
        }
        bufp = tmpBuf;
        numRead = tmpLen;
      }
      if (numRead == BUF_SIZE) {
        eprintf("numRead === BUF_SIZE\n");
      }

      if (handleInData(einfo, bufp, numRead) == -1) {
        eprintf("handleIn: handleInData\n");
        return -1;
      }
    }
  }

  return 0;
}

void onquit(int signum) {
  struct evinfo *tmpeinfo, *nexteinfo;

  tmpeinfo = dumbevhead->next;
  for (;;) {
    if (tmpeinfo == dumbevhead)
      break;

    nexteinfo = tmpeinfo->next;
    clean(tmpeinfo);
    tmpeinfo = nexteinfo;
  }
}

void onexit(int signum) {
  struct evinfo *tmpeinfo, *nexteinfo;

  tmpeinfo = dumbevhead->next;
  for (;;) {
    if (tmpeinfo == dumbevhead)
      break;

    nexteinfo = tmpeinfo->next;
    clean(tmpeinfo);
    tmpeinfo = nexteinfo;
  }

  free(listenevinfo);
  free(dumbevhead);

  exit(EXIT_SUCCESS);
}

void eloop(char *port,
           int (*handleInData)(struct evinfo *, unsigned char *, ssize_t)) {
  dumbevhead = malloc(sizeof(struct evinfo));
  dumbevhead->prev = dumbevhead->next = dumbevhead;

  struct sigaction sa;
  ssize_t numRead;
  int nfds, listenfd, infd;
  struct evinfo *einfo, *tmpeinfo, *nexteinfo;
  enum evtype etype;
  struct epoll_event ev, evlist[MAX_EVENTS];
  time_t now;

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGPIPE, &sa, NULL) == -1) {
    perror("failed to ignore SIGPIPE; sigaction");
    exit(EXIT_FAILURE);
  }
  sa.sa_handler = onexit;
  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("failed to ignore SIGINT; sigaction");
    exit(EXIT_FAILURE);
  }
  sa.sa_handler = onquit;
  if (sigaction(SIGQUIT, &sa, NULL) == -1) {
    perror("failed to ignore SIGQUIT; sigaction");
    exit(EXIT_FAILURE);
  }

  populateKeyIv();

  listenfd = inetListen(port, 80, NULL);
  if (listenfd == -1) {
    perror("inetListen");
    exit(EXIT_FAILURE);
  }

  efd = epoll_create1(0);
  if (efd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
  }

  listenevinfo = eadd(LISTEN, listenfd, -1, NULL, EPOLLIN);

  if (serverflag == 0) {
    int i, fd;

    connPool.next = 0;
    for (i = 0; i < CONNECT_POOL_SIZE; i++) {
      fd = inetConnect(remoteHost, remotePort, SOCK_STREAM);
      if (fd == -1) {
        perror("inetConnect, eloop");
        exit(EXIT_FAILURE);
      }
      if (setkeepalive(fd) == -1) {
        if (close(fd) == -1) {
          perror("close, eloop, setkeepalive");
        }
        exit(EXIT_FAILURE);
      }
      connPool.fds[i] = fd;
    }
  }

  eprintf("started!\n\n");

  for (;;) {
    nfds = epoll_wait(efd, evlist, 1, EPOLL_TIMEOUT);
    // nfds = epoll_wait(efd, evlist, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      if (errno == EINTR)
        continue;
      exit(EXIT_FAILURE);
    }

    if (nfds == 0) {
      now = time(NULL);
      if (now == -1) {
        perror("time, eloop");
        exit(EXIT_FAILURE);
      }

      tmpeinfo = dumbevhead->next;
      int activecnt = 0;
      for (;;) {
        if (tmpeinfo == dumbevhead)
          break;

        if ((now - tmpeinfo->last_active) < MAX_IDLE_TIME) {
          activecnt++;
          printf("now: %ld, tmpeinfo->last_active: %ld, (now - "
                 "tmpeinfo->last_active): %ld, max: %ld\n",
                 now, tmpeinfo->last_active, (now - tmpeinfo->last_active),
                 MAX_IDLE_TIME);

          tmpeinfo = tmpeinfo->next;
          continue;
        } else {
          eprintf("Timeout clean 1.\n");
          nexteinfo = tmpeinfo->next;
          clean(tmpeinfo);
          tmpeinfo = nexteinfo;
          continue;
        }
      }
      eprintf("activecnt: %d\n", activecnt);
    }

    for (int n = 0; n < nfds; ++n) {
      einfo = (struct evinfo *)evlist[n].data.ptr;
      etype = einfo->type;

      if (evlist[n].events & EPOLLERR) {
        eprintf("EPOLLERR\n");
        printf("EPOLLERR type: %d, buf: %d, %d, %d\n", etype, einfo->bufStartIndex,
               einfo->bufEndIndex, einfo->bufLen);
        fflush(stdout);
        clean(einfo);
        continue;
      }
      if (evlist[n].events & EPOLLHUP) {
        eprintf("EPOLLHUP\n");
        printf("EPOLLHUP type: %d, buf: %d, %d, %d\n", etype, einfo->bufStartIndex,
               einfo->bufEndIndex, einfo->bufLen);
        fflush(stdout);
        clean(einfo);
        continue;
      }

      if (evlist[n].events & EPOLLOUT) {
        if (etype == OUT) {
          if (einfo->outconnected == 0) {
            if (connOutConnected(einfo) == -1) {
              clean(einfo);
              continue;
            } else {
              einfo->outconnected = 1;
            }
          }

          if (trySend(einfo) == -1) {
            eprintf("trySend: eloop\n");
            clean(einfo);
            continue;
          }
        } else if (etype == IN) {
          if (trySend(einfo) == -1) {
            eprintf("trySend: eloop\n");
            clean(einfo);
            continue;
          }
        } else {
          eprintf("wrong etype in EPOLLOUT\n");
          exit(EXIT_FAILURE);
        }
      }

      if (evlist[n].events & EPOLLIN) {
        if (etype == LISTEN) {
          for (;;) {
            infd = accept(einfo->fd, NULL, NULL);
            if (infd == -1) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
              } else {
                perror("accept");
                exit(EXIT_FAILURE);
              }
            }
            eadd(IN, infd, 0, NULL, EPOLLOUT | EPOLLIN | EPOLLET);
          }
          continue;
        } else if (etype == IN) {
          if (handleIn(einfo, handleInData) == -1) {
            clean(einfo);
            continue;
          }
        } else if (etype == OUT) {
          if (handleIn(einfo, handleOutData) == -1) {
            clean(einfo);
            continue;
          }
        } else {
          eprintf("wrong etype in EPOLLIN\n");
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}
