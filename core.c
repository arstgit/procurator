#include "core.h"

unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
unsigned char *iv = (unsigned char *)"0123456789012345";
int globalElevel = INFO_LEVEL;

void eprint(int fd, unsigned char *str, int elevel, int perrorflag) {
  if (elevel < globalElevel)
    return;

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
  freeCipher(einfo->encryptCtx);
  freeCipher(einfo->decryptCtx);
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
    if (encrypt(einfo->encryptCtx, tmpBuf, &tmpLen, buf, len, 1) == -1) {
      perror("encrypt, 1");
      return -1;
    }
    buf = tmpBuf;
    len = tmpLen;
  }

  if (einfo->bufEndIndex > 0) {
    if (einfo->bufEndIndex + len > einfo->bufLen) {
      einfo->buf = realloc(einfo->buf, BUF_FACTOR * (einfo->bufEndIndex + len));
      if (einfo->buf == NULL) {
        perror("realloc");
        exit(EXIT_FAILURE);
      }
      einfo->bufLen = BUF_FACTOR * (einfo->bufEndIndex + len);
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
        if (einfo->bufEndIndex == 0) {
          if (len > einfo->bufLen) {
            einfo->buf = realloc(einfo->buf, BUF_FACTOR * len);
            if (einfo->buf == NULL) {
              perror("realloc");
              exit(EXIT_FAILURE);
            }
            einfo->bufLen = BUF_FACTOR * len;
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
  einfo->bufStartIndex = einfo->bufEndIndex - len;

  return 0;
}

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events) {
  struct evinfo *einfo;
  struct epoll_event ev;

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
  einfo->encryptCtx = NULL;
  einfo->decryptCtx = NULL;
  einfo->bufStartIndex = 0;
  einfo->bufEndIndex = 0;
  einfo->bufLen = 0;
  einfo->buf = NULL;
  einfo->ptr = ptr;

  if ((serverflag == 1 && einfo->type == IN) ||
      (serverflag == 0 && einfo->type == OUT)) {
    if (initCipher((void **)&einfo->encryptCtx, key, iv, 1) == -1) {
      perror("initCipher, encrypt");
      exit(EXIT_FAILURE);
    }
    if (initCipher((void **)&einfo->decryptCtx, key, iv, 0) == -1) {
      perror("initCipher, decrypt");
      exit(EXIT_FAILURE);
    }
  }

  ev.data.ptr = einfo;
  ev.events = events;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_ctl: connfd");
    exit(EXIT_FAILURE);
  }
  return einfo;
}

int connOut(struct evinfo *einfo, char *outhost, char *outport) {
  int outfd;

  outfd = inetConnect(outhost, outport, SOCK_STREAM);
  if (outfd == -1) {
    perror("inetConnect");
    return -1;
  }

  einfo->ptr = eadd(OUT, outfd, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET);

  return 0;
}

static int connOutConnected(struct evinfo *einfo) {
  int flags, result;
  struct epoll_event ev;

  socklen_t result_len = sizeof(result);
  if (getsockopt(einfo->fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
    // error, fail somehow, close socket
    perror("getsockopt");
    return -1;
  }
  if (result != 0) {
    eprint(STDERR_FILENO, "connOutConnected, not connected ", INFO_LEVEL, 1);
    return -1;
  }

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
        if (encrypt(einfo->decryptCtx, tmpBuf, &tmpLen, buf, numRead, 0) ==
            -1) {
          perror("encrypt, 0");
          exit(EXIT_FAILURE);
        }
        if (tmpLen > BUF_SIZE + 512) {
          perror("tmpLen exceeded, handleIn");
          exit(EXIT_FAILURE);
        }
        bufp = tmpBuf;
        numRead = tmpLen;
      }

      if (handleInData(einfo, bufp, numRead) == -1) {
        perror("handleIn: handleInData");
        return -1;
      }
    }
  }
  return 0;
}

void eloop(char *port,
           int (*handleInData)(struct evinfo *, unsigned char *, ssize_t)) {
  struct sigaction sa;
  ssize_t numRead;
  int nfds, listenfd, infd;
  struct evinfo *einfo;
  enum evtype etype;
  struct epoll_event ev, evlist[MAX_EVENTS];

  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigaction(SIGPIPE, &sa, 0);
  if (sigaction(SIGPIPE, &sa, NULL) == -1) {
    perror("failed to ignore SIGPIPE; sigaction");
    exit(EXIT_FAILURE);
  }
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

  eadd(LISTEN, listenfd, -1, NULL, EPOLLIN);

  eprint(STDOUT_FILENO, "started!\n\n", INFO_LEVEL, 0);

  for (;;) {
    nfds = epoll_wait(efd, evlist, 1, -1);
    // nfds = epoll_wait(efd, evlist, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      if (errno == EINTR)
        continue;
      exit(EXIT_FAILURE);
    }

    for (int n = 0; n < nfds; ++n) {
      einfo = (struct evinfo *)evlist[n].data.ptr;
      etype = einfo->type;

      if (evlist[n].events & EPOLLERR) {
        eprint(STDOUT_FILENO, "EPOLLERR\n", INFO_LEVEL, 0);
        clean(einfo);
        continue;
      }
      if (evlist[n].events & EPOLLHUP) {
        eprint(STDOUT_FILENO, "EPOLLHUP\n", INFO_LEVEL, 0);
        clean(einfo);
        continue;
      }

      if (evlist[n].events & EPOLLIN) {
        if (etype == LISTEN) {
          infd = accept(einfo->fd, NULL, NULL);
          if (infd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              continue;
            } else {
              perror("accept");
              exit(EXIT_FAILURE);
            }
          }
          if (setnonblocking(infd) == -1) {
            perror("setnonblocking");
            exit(EXIT_FAILURE);
          }

          eadd(IN, infd, 0, NULL, EPOLLOUT | EPOLLIN | EPOLLET);
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
          eprint(STDOUT_FILENO, "wrong etype in EPOLLIN\n", INFO_LEVEL, 0);
          exit(EXIT_FAILURE);
        }
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
            perror("trySend: eloop");
            clean(einfo);
            continue;
          }
        } else if (etype == IN) {
          if (trySend(einfo) == -1) {
            perror("trySend: eloop");
            clean(einfo);
            continue;
          }
        } else {
          eprint(STDOUT_FILENO, "wrong etype in EPOLLOUT\n", INFO_LEVEL, 0);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}
