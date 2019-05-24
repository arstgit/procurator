#include "core.h"

int inetConnect(const char *host, const char *service, int type) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s, flags, conn;

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

    flags = fcntl(sfd, F_GETFL);
    if (flags == -1) {
      close(sfd);
      sfd = -1;
      continue;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sfd, F_SETFL, flags) == -1) {
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
  int sfd, optval, s;

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

void clean(struct evinfo *einfo) {
  if (einfo->ptr != NULL) {
    if (close(einfo->ptr->fd) == -1) {
      perror("clean: close1");
      exit(EXIT_FAILURE);
    }
    free(einfo->ptr);
  }
  if (close(einfo->fd) == -1) {
    perror("clean: close1");
    exit(EXIT_FAILURE);
  }
  free(einfo);
}

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events) {
  struct evinfo *einfo;
  struct epoll_event ev;

  einfo = malloc(sizeof(struct evinfo));
  if (einfo == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  einfo->type = type;
  einfo->fd = fd;
  einfo->stage = stage;
  einfo->ptr = ptr;

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

  einfo->ptr = eadd(OUT, outfd, -1, einfo, EPOLLOUT);

  if (epoll_ctl(efd, EPOLL_CTL_DEL, einfo->fd, NULL) == -1) {
    perror("epoll_ctl: DEL connOut");
    exit(EXIT_FAILURE);
  }

  return 0;
}

int connOutCpl(struct evinfo *einfo) {
  int flags, result;
  struct epoll_event ev;

  socklen_t result_len = sizeof(result);
  if (getsockopt(einfo->fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
    // error, fail somehow, close socket
    perror("getsockopt");
    return -1;
  }
  if (result != 0) {
    write(STDERR_FILENO, strerror(result), strlen(strerror(result)));
    write(STDERR_FILENO, "\n", 1);
    return -1;
  }

  flags = fcntl(einfo->fd, F_GETFL);
  if (flags == -1) {
    perror("connDst F_GETFL");
    return -1;
  }
  flags &= (~O_NONBLOCK);
  if (fcntl(einfo->fd, F_SETFL, flags) < 0) {
    perror("connDst F_SETFL");
    return -1;
  }

  ev.data.ptr = einfo;
  ev.events = EPOLLIN;
  if (epoll_ctl(efd, EPOLL_CTL_MOD, einfo->fd, &ev) == -1) {
    perror("epoll_ctl: connDst");
    exit(EXIT_FAILURE);
  }

  ev.data.ptr = einfo->ptr;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, einfo->ptr->fd, &ev) == -1) {
    perror("epoll_ctl: connDst");
    exit(EXIT_FAILURE);
  }

  return 0;
}

int handleOut(struct evinfo *einfo) {
  int outfd = einfo->fd;
  int infd = einfo->ptr->fd;
  ssize_t numRead;

  numRead = recv(outfd, buf, BUF_SIZE, 0);
  if (numRead == -1) {
    perror("recv: handleOut");
    return -1;
  }
  if (numRead == 0) {
    return -1;
  }

  if (send(infd, buf, numRead, 0) == -1) {
    perror("send: handleOut");
    return -1;
  }
  return 0;
}

void eloop(char *port, int (*handleIn)(struct evinfo *)) {
  ssize_t numRead;
  int nfds, listenfd, infd;
  struct evinfo *einfo;
  enum evtype etype;
  struct epoll_event ev, evlist[MAX_EVENTS];

  listenfd = inetListen(port, 50, NULL);
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

  write(STDOUT_FILENO, "started\n", 8);

  for (;;) {
    nfds = epoll_wait(efd, evlist, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      if (errno == EINTR)
        continue;
      exit(EXIT_FAILURE);
    }

    for (int n = 0; n < nfds; ++n) {
      einfo = (struct evinfo *)evlist[n].data.ptr;
      etype = einfo->type;

      if (evlist[n].events & EPOLLIN) {
        if (etype == LISTEN) {
          infd = accept(listenfd, NULL, NULL);
          if (infd == -1) {
            perror("accept");
            continue;
          }

          eadd(IN, infd, 0, NULL, EPOLLIN);
        } else if (etype == IN) {
          if (handleIn(einfo) == -1) {
            clean(einfo);
          }
        } else if (etype == OUT) {
          if (handleOut(einfo) == -1) {
            clean(einfo);
          }
        } else {
          write(STDERR_FILENO, "wrong etype in EPOLLIN\n", 25);
          exit(EXIT_FAILURE);
        }
      } else if (evlist[n].events & EPOLLOUT) {
        if (etype == OUT) {
          if (connOutCpl(einfo) == -1) {
            clean(einfo);
          }
        } else {
          write(STDERR_FILENO, "wrong etype in EPOLLOUT\n", 25);
          exit(EXIT_FAILURE);
        }
      } else if (evlist[n].events & (EPOLLHUP | EPOLLERR)) {
        write(STDERR_FILENO, "EPOLLHUP or EPOLLERR\n", 12);
        clean(einfo);
      } else {
        write(STDERR_FILENO, "wrong event\n", 12);
        exit(EXIT_FAILURE);
      }
    }
  }
}
