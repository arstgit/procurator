#include "core.h"

unsigned char key[32];
unsigned char iv[16];

int globalLogLevel;

// User input config.
char *remoteHost;
char *remotePort;
char *localPort;
char *password;

list *evinfolist;
listIterator *evinfolistIter;

struct evinfo *listenevinfo, *rdpListenevinfo;
struct connectPool connPool;

rdpSocket *rdpS;
int rdpfd;
int efd;
unsigned char buf[BUF_SIZE];
unsigned char tmpBuf[TMP_BUF_SIZE];
int serverflag;
int connectPool[CONNECT_POOL_SIZE];
uint64_t nowms, lastCheckms;

// Return the UNIX time in millisecond.
static inline uint64_t mstime(void) {
  struct timeval tv;
  uint64_t mst;

  gettimeofday(&tv, NULL);
  mst = ((uint64_t)tv.tv_sec) * 1000;
  mst += tv.tv_usec / 1000;
  return mst;
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

static int isLeapYear(time_t year) {
  if (year % 4)
    return 0; /* A year not divisible by 4 is not leap. */
  else if (year % 100)
    return 1; /* If div by 4 and not 100 is surely leap. */
  else if (year % 400)
    return 0; /* If div by 100 *and* not by 400 is not leap. */
  else
    return 1; /* If div by 100 and 400 is leap. */
}

static void nolocksLocaltime(struct tm *tmp, time_t t, time_t tz, int dst) {
  const time_t secs_min = 60;
  const time_t secs_hour = 3600;
  const time_t secs_day = 3600 * 24;

  t -= tz;                       /* Adjust for timezone. */
  t += 3600 * dst;               /* Adjust for daylight time. */
  time_t days = t / secs_day;    /* Days passed since epoch. */
  time_t seconds = t % secs_day; /* Remaining seconds. */

  tmp->tm_isdst = dst;
  tmp->tm_hour = seconds / secs_hour;
  tmp->tm_min = (seconds % secs_hour) / secs_min;
  tmp->tm_sec = (seconds % secs_hour) % secs_min;

  /* 1/1/1970 was a Thursday, that is, day 4 from the POV of the tm structure
   * where sunday = 0, so to calculate the day of the week we have to add 4
   * and take the modulo by 7. */
  tmp->tm_wday = (days + 4) % 7;

  /* Calculate the current year. */
  tmp->tm_year = 1970;
  while (1) {
    /* Leap years have one day more. */
    time_t days_this_year = 365 + isLeapYear(tmp->tm_year);
    if (days_this_year > days)
      break;
    days -= days_this_year;
    tmp->tm_year++;
  }
  tmp->tm_yday = days; /* Number of day of the current year. */

  /* We need to calculate in which month and day of the month we are. To do
   * so we need to skip days according to how many days there are in each
   * month, and adjust for the leap year that has one more day in February. */
  int mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  mdays[1] += isLeapYear(tmp->tm_year);

  tmp->tm_mon = 0;
  while (days >= mdays[tmp->tm_mon]) {
    days -= mdays[tmp->tm_mon];
    tmp->tm_mon++;
  }

  tmp->tm_mday = days + 1; /* Add 1 since our 'days' is zero-based. */
  tmp->tm_year -= 1900;    /* Surprisingly tm_year is year-1900. */
}

static void tlogRaw(int level, const char *msg) {
  const char *c = ".-*#";
  char buf[64];
  char outputMsg[LOG_MAX_LEN + 64];
  int n;
  int fd = STDOUT_FILENO;

  int rawmode = (level & LL_RAW);

  if ((level & 0xff) < globalLogLevel)
    return;

  if (rawmode) {
    n = snprintf(outputMsg, sizeof(outputMsg), "%s", msg);
    write(fd, outputMsg, n);
  } else {
    int off;
    struct timeval tv;
    time_t t;

    gettimeofday(&tv, NULL);
    struct tm tm;
    nolocksLocaltime(&tm, tv.tv_sec, 0, 0);
    off = strftime(buf, sizeof(buf), "%d %b %Y %H:%M:%S.", &tm);
    snprintf(buf + off, sizeof(buf) - off, "%03d", (int)tv.tv_usec / 1000);
    n = snprintf(outputMsg, sizeof(outputMsg), "[%s] %s %c %s\n",
                 serverflag ? "procurator-server" : "procurator-local", buf,
                 c[level], msg);
    write(fd, outputMsg, n);
  }
}

//  Printf-alike style log utility.
void tlog(int level, const char *fmt, ...) {
  va_list ap;
  char msg[LOG_MAX_LEN];

  if ((level & 0xff) < globalLogLevel)
    return;

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  tlogRaw(level, msg);
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
  assert(einfo->state != ES_DESTROY);
  einfo->state = ES_DESTROY;

  if (einfo->bufEndIndex - einfo->bufStartIndex > 0) {
    tlog(LL_VERBOSE, "cleaning dirty bytes: %d",
         einfo->bufEndIndex - einfo->bufStartIndex);
  }
  if (einfo->type == RDP_IN || einfo->type == RDP_OUT) {
    if (rdpConnSetUserData(einfo->c, NULL) == -1) {
      tlog(LL_DEBUG, "rdpConnSetUserData");
      exit(EXIT_FAILURE);
    }
    if (rdpConnClose(einfo->c) == -1) {
      tlog(LL_DEBUG, "rdpConnClose error");
      exit(EXIT_FAILURE);
    }
  } else if (einfo->type == IN || einfo->type == OUT) {
    if (close(einfo->fd) == -1) {
      perror("Clean: close");
      exit(EXIT_FAILURE);
    }
  } else {
    tlog(LL_DEBUG,
         "clean not valid type. einfo: type: %d, fd: %d, conn: %d, stage: %d",
         einfo->type, einfo->fd, einfo->c, einfo->stage);
    exit(EXIT_FAILURE);
  }

  if (einfo->bufLen > 0) {
    free(einfo->buf);
  }
  freeCipher(&einfo->encryptor);

  if (einfo->type == IN || einfo->type == RDP_IN) {
    assert(einfo->node);
    listNodeDestroy(evinfolist, einfo->node);
  }

  free(einfo);
}

void clean(struct evinfo *einfo) {
  if (einfo->ptr != NULL) {
    cleanOne(einfo->ptr);
  }
  cleanOne(einfo);
}

static int sendOrRdpWrite(struct evinfo *einfo, void *buf, size_t len,
                          int flags) {
  if (einfo->type == RDP_IN || einfo->type == RDP_OUT) {
    return rdpWrite(einfo->c, buf, len);
  } else if (einfo->type == IN || einfo->type == OUT) {
    return send(einfo->fd, buf, len, flags);
  } else {
    exit(1);
    assert(0);
  }
}

static int trySend(struct evinfo *einfo) {
  ssize_t numSend;
  size_t len;
  unsigned char *buf;

  len = einfo->bufEndIndex - einfo->bufStartIndex;
  buf = einfo->buf + einfo->bufStartIndex;
  for (; len > 0;) {
    numSend = sendOrRdpWrite(einfo, buf, len, 0);
    if (numSend == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else {
        perror("send: trysend");
        return -1;
      }
    } else {
      assert(numSend != 0);

      len -= numSend;
      buf = buf + numSend;
    }
  }
  if (len == 0)
    einfo->bufEndIndex = 0;
  einfo->bufStartIndex = einfo->bufEndIndex - len;
  return 0;
}

int sendOrStore(int self, void *buf, size_t len, int flags,
                struct evinfo *einfo) {
  ssize_t numSend;

  einfo = self == 1 ? einfo : einfo->ptr;

  if (einfo->type == RDP_IN || einfo->type == RDP_OUT) {
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
        tlog(LL_DEBUG, "realloc step1");
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
    numSend = sendOrRdpWrite(einfo, buf, len, flags);
    if (numSend == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // to do
        if (einfo->bufEndIndex == 0) {
          if (len > einfo->bufLen) {
            einfo->buf = realloc(einfo->buf, BUF_FACTOR1 * len);

            if (einfo->buf == NULL) {
              tlog(LL_DEBUG, "realloc step2");
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
      assert(numSend != 0);

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
                    uint32_t events, rdpConn *c) {
  struct evinfo *einfo;

  if ((events & EPOLLET) && (type == IN || type == OUT || type == LISTEN)) {
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
  if (type == RDP_IN || type == RDP_OUT) {
    assert(c);

    if (rdpConnSetUserData(c, einfo) == -1) {
      tlog(LL_DEBUG, "rdpConnSetUserData");
      exit(EXIT_FAILURE);
    }
    einfo->c = c;

  } else if (type == IN || type == OUT || type == RDP_LISTEN ||
             type == LISTEN) {
    assert(fd != -1);
    einfo->fd = fd;
  } else {
    assert(0);
  }

  einfo->node = NULL;
  einfo->state = ES_IDLE;
  einfo->stage = stage;
  einfo->outconnected = 0;
  einfo->bufStartIndex = 0;
  einfo->bufEndIndex = 0;
  einfo->bufLen = 0;
  einfo->buf = NULL;
  einfo->ptr = ptr;
  einfo->last_active = nowms;

  einfo->encryptor.encryptCtx = NULL;
  einfo->encryptor.decryptCtx = NULL;
  einfo->encryptor.sentIv = 0;
  einfo->encryptor.receivedIv = 0;

  if (einfo->type == IN || einfo->type == RDP_IN) {
    einfo->node = listNodeAddHead(evinfolist, einfo);
    if (einfo->node == NULL) {
      tlog(LL_DEBUG, "listNodeAddHead");
      exit(EXIT_FAILURE);
    }
  } else {
  }

  if (type != RDP_IN && type != RDP_OUT) {
    struct epoll_event ev;
    ev.data.ptr = einfo;
    ev.events = events;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
      perror("epoll_ctl: connfd");
      exit(EXIT_FAILURE);
    }
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
  rdpConn *c;

  // TO DO
  if (0 && serverflag == 0) {
    outfd = connPool.fds[connPool.next];
    numRead = recv(outfd, buf, BUF_SIZE, MSG_PEEK);
    // if (numRead == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    if (checkConnected(outfd) == 0 && numRead == -1 &&
        (errno == EAGAIN || errno == EWOULDBLOCK)) {
      // This fd is usable.
    } else {
      if (numRead == -1) {
        perror("recv, connOut");
      }
      if (numRead > 0) {
        tlog(LL_DEBUG, "recv, connOut, numRead > 0.");
      }

      if (close(outfd) == -1) {
        perror("close, connOut");
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

    if (serverflag == 0) {
      c = rdpNetConnect(rdpS, outhost, outport);
      if (c == NULL) {
        tlog(LL_DEBUG, "rdpNetConnect");
        return -1;
      }
    } else {
      outfd = inetConnect(outhost, outport, SOCK_STREAM);
      if (outfd == -1) {
        perror("inetConnect, connOut server");
        return -1;
      }
    }
  }
  if (serverflag == 0) {
    einfo->ptr = eadd(RDP_OUT, 0, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET, c);
  } else {
    einfo->ptr =
        eadd(OUT, outfd, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET, NULL);
  }

  return 0;
}

static int handleOutData(struct evinfo *einfo, unsigned char *buf,
                         ssize_t numRead) {

  if (sendOrStore(0, buf, numRead, 0, einfo) == -1) {
    perror("sendOrStore: handleOut");
    return -1;
  }
  return 0;
}

static int decryptIfNeed(struct evinfo *einfo, void **dst, int *dstLen,
                         void *src, int srcLen) {
  if (einfo->type == RDP_IN || einfo->type == RDP_OUT) {
    if (decrypt(&einfo->encryptor, *dst, dstLen, src, srcLen, key, iv) == -1) {
      tlog(LL_DEBUG, "encrypt, handleIn");
      return -1;
    }
    if (*dstLen > TMP_BUF_SIZE) {
      tlog(LL_DEBUG, "recv, handleIn, tmpLen > TMP_BUF_SIZE");
      exit(EXIT_FAILURE);
    }
  } else {
    *dst = src;
    *dstLen = srcLen;
  }

  return 0;
}

static int handleInBuf(struct evinfo *einfo,
                       int (*handleInData)(struct evinfo *, unsigned char *,
                                           ssize_t),
                       void *buf, int len) {
  int dstLen = BUF_SIZE;
  void *dst = tmpBuf;

  if (decryptIfNeed(einfo, &dst, &dstLen, buf, len) == -1) {
    tlog(LL_DEBUG, "decryptIfNeed");
    exit(EXIT_FAILURE);
  }
  if (len == BUF_SIZE) {
    tlog(LL_DEBUG, "numRead === BUF_SIZE");
  }

  if (handleInData(einfo, dst, dstLen) == -1) {
    tlog(LL_DEBUG, "handleInBuf: handleInData");
    return -1;
  }
  return 0;
}

static int handleIn(struct evinfo *einfo,
                    int (*handleInData)(struct evinfo *, unsigned char *,
                                        ssize_t)) {
  ssize_t n;

  for (;;) {
    n = recv(einfo->fd, buf, BUF_SIZE, 0);
    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else {
        perror("handleIn recv");
        return -1;
      }
    }
    if (n == 0) {
      return -1;
    }

    if (n > 0) {
      if (handleInBuf(einfo, handleInData, buf, n) == -1) {
        tlog(LL_DEBUG, "handleInBuf");
        return -1;
      }
    }
  }

  return 0;
}

int destroyAll() {
  listIteratorDestroy(evinfolistIter);
  listDestroy(evinfolist);

  close(listenevinfo->fd);
  free(listenevinfo);

  rdpSocketDestroy(rdpS);
  free(rdpListenevinfo);

  exit(EXIT_SUCCESS);
}

void onquit(int signum) { destroyAll(); }

void onexit(int signum) { destroyAll(); }

int afterSleep() {
  nowms = mstime();

  return 0;
}

int beforeSleep() {
  if (nowms - lastCheckms >= CHECK_TIMEOUT_INTERVAL) {
    listNode *node;
    int activecnt = 0;
    listIteratorRewind(evinfolist, evinfolistIter);
    while (node = listIteratorNext(evinfolistIter)) {
      struct evinfo *curinfo = node->value;

      if ((nowms - curinfo->last_active) < MAX_IDLE_TIME) {
        activecnt++;
        if (curinfo->bufEndIndex - curinfo->bufStartIndex > 0) {
          tlog(LL_DEBUG, "dirty bytes: %d",
               curinfo->bufEndIndex - curinfo->bufStartIndex);
        }
        continue;
      } else {
        tlog(LL_DEBUG, "cleaning. timeout.");

        clean(curinfo);
        continue;
      }
    }

    tlog(LL_DEBUG, "activecnt: %d", activecnt);

    lastCheckms = mstime();
  }

  int timeout;
  if ((timeout = rdpSocketIntervalAction(rdpS)) == -1) {
    tlog(LL_DEBUG, "rdpSocketIntervalAction");
    exit(EXIT_FAILURE);
  }
  return timeout;
}

void eloop(char *port,
           int (*handleInData)(struct evinfo *, unsigned char *, ssize_t)) {
  evinfolist = listCreate();
  evinfolistIter = listIteratorCreate(evinfolist, LIST_START_HEAD);

  struct sigaction sa;
  ssize_t numRead;
  int nfds, listenfd, infd;
  struct evinfo *einfo;
  enum evtype etype;
  struct epoll_event ev, evlist[MAX_EVENTS];

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

  rdpS = rdpSocketCreate(1, "0.0.0.0", port);
  if (rdpS == NULL) {
    tlog(LL_DEBUG, "rdpSocketCreate");
    exit(EXIT_FAILURE);
  }
  rdpfd = rdpSocketGetProp(rdpS, RDP_PROP_FD);
  if (rdpfd == -1) {
    tlog(LL_DEBUG, "rdpSocket get fd");
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

  rdpListenevinfo =
      eadd(RDP_LISTEN, rdpfd, -1, NULL, EPOLLIN | EPOLLOUT | EPOLLET, NULL);

  listenevinfo = eadd(LISTEN, listenfd, -1, NULL, EPOLLIN, NULL);

  if (0 && serverflag == 0) {
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

  tlog(LL_DEBUG, "started!");

  nowms = lastCheckms = mstime();

  for (;;) {
    int timeout;
    timeout = beforeSleep();
    assert(timeout > 0);
    nfds = epoll_wait(efd, evlist, 1, timeout);
    afterSleep();

    // nfds = epoll_wait(efd, evlist, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      if (errno == EINTR)
        continue;
      exit(EXIT_FAILURE);
    }

    for (int n = 0; n < nfds; n++) {
      einfo = (struct evinfo *)evlist[n].data.ptr;
      etype = einfo->type;

      einfo->last_active = nowms;

      if (evlist[n].events & EPOLLERR) {
        tlog(LL_DEBUG, "cleaning. EPOLLERR type: %d, buf: %d, %d, %d.", etype,
             einfo->bufStartIndex, einfo->bufEndIndex, einfo->bufLen);
        clean(einfo);
        continue;
      }
      if (evlist[n].events & EPOLLHUP) {
        tlog(LL_DEBUG, "cleaning. EPOLLHUP type: %d, buf: %d, %d, %d\n", etype,
             einfo->bufStartIndex, einfo->bufEndIndex, einfo->bufLen);
        clean(einfo);
        continue;
      }

      if (evlist[n].events & EPOLLOUT) {
        if (etype == OUT) {
          if (einfo->outconnected == 0) {
            if (connOutConnected(einfo) == -1) {
              tlog(LL_DEBUG, "cleaning, not connected.");
              clean(einfo);
              continue;
            } else {
              einfo->outconnected = 1;
            }
          }

          if (trySend(einfo) == -1) {
            tlog(LL_DEBUG, "cleaning. trySend: eloop");
            clean(einfo);
            continue;
          }
        } else if (etype == IN) {
          if (trySend(einfo) == -1) {
            tlog(LL_DEBUG, "cleaning. trySend: eloop");
            clean(einfo);
            continue;
          }
        } else if (etype == RDP_LISTEN) {
          // Resend is triggered by rdpReadPoll() return flag.
        } else {
          tlog(LL_DEBUG, "wrong etype in EPOLLOUT, etype: %d\n", etype);
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
            eadd(IN, infd, 0, NULL, EPOLLOUT | EPOLLIN | EPOLLET, NULL);
          }
          continue;
        } else if (etype == IN) {
          if (handleIn(einfo, handleInData) == -1) {
            tlog(LL_DEBUG, "cleaning, handlein, etype == IN.");
            clean(einfo);
            continue;
          }
        } else if (etype == OUT) {
          if (handleIn(einfo, handleOutData) == -1) {
            tlog(LL_DEBUG, "cleaning, handlein, etype == OUT.");
            clean(einfo);
            continue;
          }
        } else if (etype == RDP_LISTEN) {
          int flag;
          rdpConn *conn;
          for (;;) {
            ssize_t n = rdpReadPoll(rdpS, buf, BUF_SIZE, &conn, &flag);
            if (flag & RDP_ERROR) {
              tlog(LL_DEBUG, "rdpReadPoll error");
              break;
            }
            if (flag & RDP_AGAIN) {
              break;
            }
            if (flag & RDP_CONNECTED) {
              tlog(LL_DEBUG, "rdp connected");

              einfo = rdpConnGetUserData(conn);
              if (einfo == NULL) {
                tlog(LL_DEBUG, "rdpConnGetUserData");
                exit(EXIT_FAILURE);
              }

              assert(einfo->type == RDP_OUT);

              if (trySend(einfo) == -1) {
                tlog(LL_DEBUG, "cleaning. trySend: RDP_OUT connected");
                clean(einfo);
                continue;
              }
            }
            if (flag & RDP_ACCEPT) {
              tlog(LL_DEBUG, "rdp accept");
              // Only accept a connection on server end.
              if (serverflag == 1) {
                eadd(RDP_IN, 0, 0, NULL, EPOLLOUT | EPOLLIN | EPOLLET, conn);
              } else {
                rdpConnClose(conn);
              }
            }
            if (flag & RDP_DATA) {
              einfo = rdpConnGetUserData(conn);
              if (einfo == NULL) {
                // It means we have called clean(einfo) in other place.
                continue;
              }

              if (n == 0) {
                tlog(LL_DEBUG, "cleaning. rdp data EOF");
                // EOF
                clean(einfo);
              } else if (n > 0) {
                if (einfo->type == RDP_IN) {
                  assert(serverflag == 1);
                  if (handleInBuf(einfo, handleInData, buf, n) == -1) {
                    tlog(LL_DEBUG, "cleaning. handleInBuf RDP_IN");
                    clean(einfo);
                  }
                } else if (einfo->type == RDP_OUT) {
                  assert(serverflag == 0);
                  if (handleInBuf(einfo, handleOutData, buf, n) == -1) {
                    tlog(LL_DEBUG, "cleaning. handleInBuf RDP_OUT");
                    clean(einfo);
                  }
                } else {
                  tlog(LL_DEBUG, "einfo type not RDP_IN or RDP_OUT");
                  exit(EXIT_FAILURE);
                }
              } else {
                assert(0);
              }
            }

            if (flag & RDP_POLLOUT) {
              tlog(LL_DEBUG, "RDP_POLLOUT");

              einfo = rdpConnGetUserData(conn);
              if (einfo == NULL) {
                // It means we have called clean(einfo) in other place.
                continue;
              }
              if (trySend(einfo) == -1) {
                tlog(LL_DEBUG, "cleaning. trySend: eloop RDP_POLLOUT");
                clean(einfo);
              }
            }
            if (flag & RDP_CONTINUE) {
              continue;
            }
          }
        } else {
          tlog(LL_DEBUG, "wrong etype in EPOLLIN");
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}
