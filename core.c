#include "core.h"

char *version = "1.1.1";

unsigned char key[32];
unsigned char iv[16];

int globalLogLevel;

// User input config.
char *remoteHost;
char *remotePort;
char *remoteUdpPort;
char *localPort;
char *localUdpPort;
char *password;

// Global connection pairs.
list *evinfolist;
listIterator *evinfolistIter;

// UDP relay associations storage.
dict *udpRelayDict;
dictIterator *udpRelayDictIterator;

struct udpRelayEntry {
  struct sockaddr_storage addr;
  socklen_t addrlen;
  uint64_t lastVisited; // In milliseconds.
};

struct evinfo *tcpListenEvinfo, *udpListenEvinfo, *udpListenOutEvinfo,
    *rdpListenEvinfo;

rdpSocket *rdpS;
int rdpfd;
int efd;
unsigned char buf[BUF_SIZE];
unsigned char tmpBuf[TMP_BUF_SIZE];
int serverflag;
int connectPool[CONNECT_POOL_SIZE];
uint64_t nowms, lastCheckDestroy, lastCheckIdle;

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

  return 0;
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

// Remember to free addrinfo!
int getaddrinfoWithoutHints(const char *host, const char *service,
                            struct addrinfo **result) {
  struct addrinfo hints;
  int s;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  hints.ai_family = AF_UNSPEC;

  s = getaddrinfo(host, service, &hints, result);
  if (s != 0) {
    errno = ENOSYS;
    return -1;
  }

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

    if (doListen && setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval,
                               sizeof(optval)) == -1) {
      close(sfd);
      freeaddrinfo(result);
      return -1;
    }

    optval = 1;
    if (type == SOCK_STREAM && setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY,
                                          &optval, sizeof(optval)) == -1) {
      close(sfd);
      freeaddrinfo(result);
      return -1;
    }

    // todo can set using sock().
    if (setnonblocking(sfd) == -1) {
      close(sfd);
      freeaddrinfo(result);
      return -1;
    }

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sfd);
  }

  if (rp != NULL && doListen && type == SOCK_STREAM) {
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

int inetListenUDP(const char *service, int backlog, socklen_t *addrlen) {
  return inetPassiveSocket(service, SOCK_DGRAM, addrlen, 1, backlog);
}

int inetListenTCP(const char *service, int backlog, socklen_t *addrlen) {
  return inetPassiveSocket(service, SOCK_STREAM, addrlen, 1, backlog);
}

inline static int etypeIsRDP(struct evinfo *einfo) {
  return einfo->type == RDP_IN || einfo->type == RDP_OUT;
}

inline static int etypeIsTCP(struct evinfo *einfo) {
  return einfo->type == IN || einfo->type == OUT;
}

inline static int etypeIsIN(struct evinfo *einfo) {
  return einfo->type == IN || einfo->type == RDP_IN;
}

inline static int etypeIsOUT(struct evinfo *einfo) {
  return einfo->type == OUT || einfo->type == RDP_OUT;
}

inline static int evBufferRemain(struct evinfo *einfo) {
  assert(einfo->bufStartIndex <= einfo->bufEndIndex);
  return einfo->bufStartIndex != einfo->bufEndIndex;
}

inline static void __evstateTo(struct evinfo *einfo, enum evstate state) {
  einfo->state = state;
  einfo->ptr->state = state;
  return;
}

// ES_HALF_OPENED: Starting point. Accepted, but not received target host yet.
// ES_CONNECTING: Received target host, and started connect to it.
// ES_OPEN: Fully connected.
// ES_CLOSED: Mutually exclusive with ES_HALF_CLOSED.
// ES_HALF_CLOSED: Triggered under these conditions:
//  1. Initail state is ES_OPEN.
//  2. In server, not local.
//  3. Received EOF from OUT handle, not RDP_IN handle.
//  4. RDP_IN handle still have buffer to transmit.
inline static void evstateTo(struct evinfo *einfo, enum evstate state) {
  assert(etypeIsRDP(einfo) || etypeIsTCP(einfo));
  assert(etypeIsIN(einfo) || etypeIsOUT(einfo));
  assert(einfo->ptr != NULL);

  switch(einfo->state) {
    case ES_HALF_OPENED:
      switch(state) {
        case ES_CONNECTING:
        case ES_CLOSED:
          return __evstateTo(einfo, state);
        case ES_HALF_CLOSED:
        case ES_OPENED:
        case ES_HALF_OPENED:
        default:
          assert(0);
      }
      assert(0);
    case ES_CONNECTING:
      switch(state) {
        case ES_OPENED:
        case ES_CLOSED:
          return __evstateTo(einfo, state);
        case ES_HALF_CLOSED:
        case ES_HALF_OPENED:
        case ES_CONNECTING:
        default:
          assert(0);
      }
      assert(0);
    case ES_OPENED:
      switch(state) {
        case ES_HALF_CLOSED:
          assert(evBufferRemain(einfo));
          assert(serverflag);
          assert(einfo->type == OUT);
        case ES_CLOSED:
          return __evstateTo(einfo, state);
        case ES_CONNECTING:
        case ES_HALF_OPENED:
        case ES_OPENED:
        default:
          assert(0);
      }
      assert(0);
    case ES_CLOSED:
      switch(state) {
        case ES_HALF_OPENED:
        case ES_CONNECTING:
        case ES_OPENED:
        case ES_CLOSED:
        case ES_HALF_CLOSED:
        default:
          assert(0);
      }
      assert(0);
    case ES_HALF_CLOSED:
      switch(state) {
        case ES_CLOSED:
        case ES_HALF_OPENED:
          return __evstateTo(einfo, state);
        case ES_CONNECTING:
        case ES_OPENED:
        case ES_HALF_CLOSED:
        default:
          assert(0);
      }
      break;
    default:
      assert(0);
  }
}

void freeEvinfo(struct evinfo *einfo) {
  if (einfo->bufEndIndex - einfo->bufStartIndex > 0) {
    tlog(LL_VERBOSE, "free dirty bytes: %d",
         einfo->bufEndIndex - einfo->bufStartIndex);
  }

  if (etypeIsRDP(einfo)) {
    if (rdpConnSetUserData(einfo->c, NULL) == -1) {
      tlog(LL_DEBUG, "rdpConnSetUserData");
      exit(EXIT_FAILURE);
    }
    if (rdpConnClose(einfo->c) == -1) {
      tlog(LL_DEBUG, "rdpConnClose error");
      exit(EXIT_FAILURE);
    }
  } else if(etypeIsTCP(einfo)) {
    if (close(einfo->fd) == -1) {
      perror("freeEvinfo: close");
      exit(EXIT_FAILURE);
    }
  } else {
    assert(0);
  }

  if (einfo->bufLen > 0) {
    free(einfo->buf);
  }

  freeCipher(&einfo->encryptor);

  free(einfo);
}

// Key is atyp + ipv4 + port = 7 bytes.
uint64_t udpRelayDictHashFn(const void *key) {
  return dictHashFnDefault(key, 7);
}

int udpRelayDictKeyCmp(const void *key1, const void *key2) {
  return memcmp(key1, key2, 7) == 0;
}

void udpRelayDictKeyDestroy(void *key) { free(key); }

void udpRelayDictValDestroy(void *val) { free(val); }

int udpRelayDictAddOrUpdate(void *key, struct sockaddr_storage *addr,
                            socklen_t addrlen) {
  void *entryKey;
  struct udpRelayEntry *val;

  entryKey = malloc(7);
  if (entryKey == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  memcpy(entryKey, key, 7);

  val = malloc(sizeof(struct udpRelayEntry));
  if (val == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  val->addr = *(struct sockaddr_storage *)addr;
  val->addrlen = addrlen;
  val->lastVisited = nowms;

  int added = dictUpdateOrAdd(udpRelayDict, entryKey, val);
  if (!added) {
    // Already exists.
    free(entryKey);
  }

  return 0;
}

int udpRelayDictGetBySockaddr(struct sockaddr *src_addr, socklen_t addrlen,
                              unsigned char *keybuf,
                              struct sockaddr_storage **dst_addr,
                              socklen_t *dst_addrlen) {
  keybuf[0] = '\x01';
  memcpy(keybuf + 1, &(((struct sockaddr_in *)src_addr)->sin_addr), 4);
  memcpy(keybuf + 5, &((struct sockaddr_in *)src_addr)->sin_port, 2);

  dictEntry *entry = dictFind(udpRelayDict, keybuf);
  if (entry == NULL) {
    tlog(LL_DEBUG, "dictFind found nothing.");
    return -1;
  }

  *dst_addr = &((struct udpRelayEntry *)(entry->val))->addr;
  *dst_addrlen = ((struct udpRelayEntry *)(entry->val))->addrlen;
  return 0;
}

int udpRelayDictGetByKey(void *key, struct sockaddr_storage **dst_addr,
                         socklen_t *dst_addrlen) {
  dictEntry *entry = dictFind(udpRelayDict, key);
  if (entry == NULL) {
    tlog(LL_DEBUG, "dictFind found nothing.");
    return -1;
  }

  *dst_addr = &((struct udpRelayEntry *)(entry->val))->addr;
  *dst_addrlen = ((struct udpRelayEntry *)(entry->val))->addrlen;
  return 0;
}

inline static void udpRelayDictSweep() {
  dictIteratorRewind(udpRelayDictIterator);

  dictEntry *entry;
  unsigned char *key;
  struct udpRelayEntry *val;

  int swept = 0, remain = 0;

  while (entry = dictIteratorNext(udpRelayDictIterator)) {
    key = entry->key;
    val = (struct udpRelayEntry *)entry->val;

    if (nowms - val->lastVisited > MAX_UDP_IDLE_TIME) {
      dictEntryDelete(udpRelayDict, key, 0);
      swept++;
    } else {
      remain++;
    }
  }

  if (swept != 0 || remain != 0) {
    tlog(LL_DEBUG, "udpRelayDict entries, swept: %d, remain: %d", swept,
         remain);
  }
}

inline static void evDestroy() {
  listNode *node;

  listIteratorRewind(evinfolist, evinfolistIter);
  while ((node = listIteratorNext(evinfolistIter))) {
    struct evinfo *curinfo = node->value;

    if (curinfo->state == ES_CLOSED) {
      clean(curinfo);
    }
  }
}

inline static void connectionSweep() {
  listNode *node;
  int swept = 0, remain = 0;

  listIteratorRewind(evinfolist, evinfolistIter);
  while ((node = listIteratorNext(evinfolistIter))) {
    struct evinfo *curinfo = node->value;

    if (nowms - curinfo->last_active > MAX_IDLE_TIME && (curinfo->ptr == NULL || nowms - curinfo->ptr->last_active > MAX_IDLE_TIME)) {
      evstateTo(curinfo, ES_CLOSED);
      clean(curinfo);

      swept++;
    } else {
      remain++;
    }
  }

  if (swept != 0 || remain != 0) {
    tlog(LL_DEBUG, "connection, swept: %d, remain: %d", swept, remain);
  }
}

void evinfoPairFree(void *val) {
  struct evinfo *einfo = (struct evinfo *)val;
  if (einfo->ptr != NULL) {
    assert(etypeIsOUT(einfo->ptr));
    freeEvinfo(einfo->ptr);
  }

  assert(etypeIsIN(einfo));
  freeEvinfo(einfo);
}

void clean(struct evinfo *einfo) {
  if (etypeIsIN(einfo)) {
    assert(einfo->node);

    listNodeDestroy(evinfolist, einfo->node);
  } else if(etypeIsOUT(einfo)) {
    assert(einfo->ptr);
    assert(!einfo->node);
    assert(einfo->ptr->node);

    listNodeDestroy(evinfolist, einfo->ptr->node);
  } else {
    assert(0);
  }
}

inline static int sendOrRdpWrite(struct evinfo *einfo, void *buf, size_t len,
                          int flags) {
  if (etypeIsRDP(einfo)) {
    return rdpWrite(einfo->c, buf, len);
  } else if (etypeIsTCP(einfo)) {
    return send(einfo->fd, buf, len, flags);
  } else {
    assert(0);
  }
}

inline static int trySend(struct evinfo *einfo) {
  ssize_t numSend;
  size_t len;
  unsigned char *buf;

  einfo->last_active = nowms;

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
        perror("sendOrRdpWrite");
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

ssize_t sendUdpIn(struct evinfo *einfo, unsigned char *buf, size_t buflen,
                  struct sockaddr_storage *destaddr, socklen_t addrlen) {
  if (serverflag == 1) {
    int tmpLen;

    // Attach encryptor to the sending side.
    if (encryptOnce(&einfo->ptr->encryptor, tmpBuf, &tmpLen, buf, buflen, key,
                    iv) == -1) {
      perror("encryptOnce");
      return -1;
    }
    buf = tmpBuf;
    buflen = tmpLen;
  }

  return sendto(einfo->ptr->fd, buf, buflen, 0, (struct sockaddr *)destaddr,
                addrlen);
}

ssize_t sendUdpOut(struct evinfo *einfo, unsigned char *buf, size_t buflen,

                   char *destHost, char *destPort) {

  // Should only called within handleUdpIn.
  assert(einfo->ptr->type == UDP_LISTEN_OUT);

  struct addrinfo *ainfo;
  ssize_t numSend;

  if (getaddrinfoWithoutHints(destHost, destPort, &ainfo) == -1) {
    tlog(LL_DEBUG, "getaddrinfoWithoutHints");
    return -1;
  }

  if (serverflag == 0) {
    int tmpLen;

    if (encryptOnce(&einfo->ptr->encryptor, tmpBuf, &tmpLen, buf, buflen, key,
                    iv) == -1) {
      perror("encryptOnce");
      return -1;
    }
    buf = tmpBuf;
    buflen = tmpLen;
  }

  numSend =
      sendto(einfo->ptr->fd, buf, buflen, 0, ainfo->ai_addr, ainfo->ai_addrlen);

  freeaddrinfo(ainfo);

  return numSend;
}

struct evinfo *eadd(enum evtype type, int fd, int stage, struct evinfo *ptr,
                    uint32_t events, rdpConn *c) {
  struct evinfo *einfo;

  // todo, already nonblock?
  if ((events & EPOLLET) &&
      (type == IN || type == OUT || type == PROCURATOR_TCP_LISTEN ||
       type == UDP_LISTEN_IN || type == UDP_LISTEN_OUT)) {
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
  if (etypeIsRDP(einfo)) {
    assert(c);

    if (rdpConnSetUserData(c, einfo) == -1) {
      tlog(LL_DEBUG, "rdpConnSetUserData");
      exit(EXIT_FAILURE);
    }
    einfo->c = c;

  } else if (etypeIsTCP(einfo) || type == RDP_LISTEN ||
             type == PROCURATOR_TCP_LISTEN || type == UDP_LISTEN_IN ||
             type == UDP_LISTEN_OUT) {
    assert(fd != -1);
    einfo->fd = fd;
  } else {
    assert(0);
  }

  einfo->node = NULL;
  einfo->state = ES_HALF_OPENED;
  einfo->stage = stage;
  einfo->outconnected = 0;
  einfo->bufStartIndex = 0;
  einfo->bufEndIndex = 0;
  einfo->bufLen = 0;
  einfo->buf = NULL;
  einfo->ptr = ptr;
  einfo->last_active = nowms;

  // Initailize encryptor.
  einfo->encryptor.encryptCtx = NULL;
  einfo->encryptor.decryptCtx = NULL;
  einfo->encryptor.sentIv = 0;
  einfo->encryptor.receivedIv = 0;

  // Store all connection pairs in a list.
  if (etypeIsIN(einfo)) {
    einfo->node = listNodeAddHead(evinfolist, einfo);
    if (einfo->node == NULL) {
      tlog(LL_DEBUG, "listNodeAddHead");
      exit(EXIT_FAILURE);
    }
  } else {
  }

  // Every new TCP connection have a new fd to be monitored.
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
    // eprint(STDERR_FILENO, "checkConnected reasult not 0.\n", INFO_LEVEL,
    // 1);
    return -1;
  }

  return 0;
}

static int connOutConnected(struct evinfo *einfo) {
  return checkConnected(einfo->fd);
}

int connOut(struct evinfo *einfo, char *outhost, char *outport) {
  int outfd;
  rdpConn *newStoreConn;

  if (serverflag == 0) {
    // Local connect to Server.
    newStoreConn = rdpNetConnect(rdpS, outhost, outport);
    assert(newStoreConn != NULL);

    einfo->ptr =
        eadd(RDP_OUT, 0, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET, newStoreConn);
  } else {
    // Server connect outside.
    outfd = inetConnect(outhost, outport, SOCK_STREAM);
    if (outfd == -1) {
      perror("inetConnect, connOut server");
      return -1;
    }

    einfo->ptr =
        eadd(OUT, outfd, -1, einfo, EPOLLOUT | EPOLLIN | EPOLLET, NULL);
  }

  evstateTo(einfo, ES_CONNECTING);

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
    int tmplen;

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

  einfo->last_active = nowms;

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
      return RETEOF;
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

int processUdp(struct evinfo *einfo,
               int (*handleUdp)(struct evinfo *einfo, unsigned char *, ssize_t,
                                struct sockaddr *, socklen_t)) {
  ssize_t numRead;

  // todo performance.
  struct sockaddr_storage src_addr;
  socklen_t addrlen = sizeof(src_addr);

  numRead = recvfrom(einfo->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&src_addr,
                     &addrlen);
  if (numRead == -1) {
    tlog(LL_DEBUG, "udp recvfrom error");
    return -1;
  } else if (numRead == 0) {
    tlog(LL_DEBUG, "recvfrom read 0 bytes");
    // Just discard.
    return 0;
  }

  unsigned char *plainbuf = buf;
  size_t plainNumRead = numRead;

  if ((serverflag == 0 && einfo->type == UDP_LISTEN_OUT) ||
      (serverflag == 1 && einfo->type == UDP_LISTEN_IN)) {
    int tmplen;

    if (decryptOnce(&einfo->encryptor, tmpBuf, &tmplen, buf, numRead, key,
                    iv) == -1) {
      tlog(LL_DEBUG, "encrypt, handleIn");
      return -1;
    }
    if (tmplen > TMP_BUF_SIZE) {
      tlog(LL_DEBUG, "recv, handleIn, tmpLen > TMP_BUF_SIZE");
      exit(EXIT_FAILURE);
    }

    plainbuf = tmpBuf;
    plainNumRead = tmplen;
  }

  if (handleUdp(einfo, plainbuf, plainNumRead, (struct sockaddr *)&src_addr,
                addrlen) == -1) {
    tlog(LL_DEBUG, "handleUdp error");
    return -1;
  }
  return 0;
}

int destroyAll() {
  tlog(LL_DEBUG, "destroying resources.");

  listIteratorDestroy(evinfolistIter);
  listDestroy(evinfolist);

  dictIteratorDestroy(udpRelayDictIterator);
  dictDestroy(udpRelayDict);

  if (serverflag == 0) {
    close(tcpListenEvinfo->fd);
    free(tcpListenEvinfo);
  }

  close(udpListenEvinfo->fd);
  free(udpListenEvinfo);

  close(udpListenOutEvinfo->fd);
  free(udpListenOutEvinfo);

  rdpSocketDestroy(rdpS);
  free(rdpListenEvinfo);

  exit(EXIT_SUCCESS);
}

void onquit(int signum) { destroyAll(); }

void onexit(int signum) { destroyAll(); }

int afterSleep() {
  nowms = mstime();

  return 0;
}

int beforeSleep() {
  if (nowms - lastCheckIdle >= CHECK_IDLE_INTERVAL) {
    udpRelayDictSweep();

    connectionSweep();

    lastCheckIdle = nowms;
  }

  if (nowms - lastCheckDestroy >= CHECK_DESTROY_INTERVAL) {
    evDestroy();

    lastCheckIdle = nowms;
  }

  int timeout;
  if ((timeout = rdpSocketIntervalAction(rdpS)) == -1) {
    tlog(LL_DEBUG, "rdpSocketIntervalAction");
    exit(EXIT_FAILURE);
  }
  return timeout;
}

void eloop(char *port, char *udpPort,
           int (*handleInData)(struct evinfo *, unsigned char *, ssize_t),
           int (*handleUdpIn)(struct evinfo *, unsigned char *, ssize_t,
                              struct sockaddr *, socklen_t),
           int (*handleUdpOut)(struct evinfo *, unsigned char *, ssize_t,
                               struct sockaddr *, socklen_t)) {
  evinfolist = listCreate();
  listMethodSetFree(evinfolist, evinfoPairFree);
  evinfolistIter = listIteratorCreate(evinfolist, LIST_START_HEAD);

  dictType rdpConnDictType = {
      udpRelayDictHashFn,     udpRelayDictKeyCmp,    NULL, NULL,
      udpRelayDictKeyDestroy, udpRelayDictValDestroy};
  udpRelayDict = dictCreate(&rdpConnDictType);
  udpRelayDictIterator = dictIteratorCreate(udpRelayDict);

  struct sigaction sa;
  ssize_t numRead;
  int nfds, listenTCPfd, listenUDPfd, listenUDPOutfd, infd;
  struct evinfo *einfo;
  enum evtype etype;
  struct epoll_event ev, evlist[MAX_EVENTS];
  int ret;

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

  efd = epoll_create1(0);
  if (efd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
  }

  // Local and Server are connected via rdp protocol.
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

  rdpListenEvinfo =
      eadd(RDP_LISTEN, rdpfd, -1, NULL, EPOLLIN | EPOLLOUT | EPOLLET, NULL);

  // TCP listen port is for socks application client only.
  if (serverflag == 0) {
    listenTCPfd = inetListenTCP(port, 80, NULL);
    if (listenTCPfd == -1) {
      perror("inetListenTCP");
      exit(EXIT_FAILURE);
    }

    // todo epollet?
    tcpListenEvinfo =
        eadd(PROCURATOR_TCP_LISTEN, listenTCPfd, -1, NULL, EPOLLIN, NULL);
  }

  // UDP relay server.
  listenUDPfd = inetListenUDP(udpPort, 80, NULL);
  if (listenUDPfd == -1) {
    perror("inetListenUDP");
    exit(EXIT_FAILURE);
  }

  udpListenEvinfo = eadd(UDP_LISTEN_IN, listenUDPfd, -1, NULL,
                         EPOLLIN | EPOLLOUT | EPOLLET, NULL);

  // Udp out connect port.
  char outUdpPort[5];
  snprintf(outUdpPort, 5, "%d", atoi(udpPort) + 1);
  listenUDPOutfd = inetListenUDP(outUdpPort, 80, NULL);
  if (listenUDPOutfd == -1) {
    perror("inetListenUDPOut");
    exit(EXIT_FAILURE);
  }
  udpListenOutEvinfo = eadd(UDP_LISTEN_OUT, listenUDPOutfd, -1, NULL,
                            EPOLLIN | EPOLLOUT | EPOLLET, NULL);

  udpListenEvinfo->ptr = udpListenOutEvinfo;
  udpListenOutEvinfo->ptr = udpListenEvinfo;

  tlog(LL_NOTICE, "Version: %s", version);
  tlog(LL_NOTICE, "started!");

  nowms = mstime();
  lastCheckIdle = lastCheckDestroy = nowms;

  for (;;) {
    int timeout;
    timeout = beforeSleep();
    assert(timeout > 0);
    nfds = epoll_wait(efd, evlist, MAX_EVENTS, timeout);
    // Closing laptop lid can trigger EINTR.
    if (nfds == -1 && errno != EINTR) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    afterSleep();

    for (int n = 0; n < nfds; n++) {
      einfo = (struct evinfo *)evlist[n].data.ptr;
      etype = einfo->type;

      // This is a loose check, einfo might not be connection einfo. And in RDP handle we have to check again.
      if (einfo->state == ES_CLOSED) {
        tlog(LL_DEBUG, "epoll_wait gave a ES_CLOSED evinfo.");
        continue;
      }

      if (evlist[n].events & EPOLLERR) {
        tlog(LL_DEBUG, "EPOLLERR, type: %d, buf: %d, %d, %d.", etype,
             einfo->bufStartIndex, einfo->bufEndIndex, einfo->bufLen);
        evstateTo(einfo, ES_CLOSED);
        clean(einfo);
        continue;
      }
      if (evlist[n].events & EPOLLHUP) {
        tlog(LL_DEBUG, "EPOLLHUP type: %d, buf: %d, %d, %d.", etype,
             einfo->bufStartIndex, einfo->bufEndIndex, einfo->bufLen);
        evstateTo(einfo, ES_CLOSED);
        clean(einfo);
        continue;
      }

      if (evlist[n].events & EPOLLOUT) {
        if (etype == OUT) {
          if (einfo->outconnected == 0) {
            if (connOutConnected(einfo) == -1) {
              tlog(LL_DEBUG, "not connected.");

              evstateTo(einfo, ES_CLOSED);
              clean(einfo);
              continue;
            } else {
              einfo->outconnected = 1;
              evstateTo(einfo, ES_OPENED);
            }
          }

          if (trySend(einfo) == -1) {
            tlog(LL_DEBUG, "trySend: eloop");

            evstateTo(einfo, ES_CLOSED);
            clean(einfo);
            continue;
          }
        } else if (etype == IN) {
          if (trySend(einfo) == -1) {
            tlog(LL_DEBUG, "trySend: eloop");
            evstateTo(einfo, ES_CLOSED);
            clean(einfo);
            continue;
          }
        } else if (etype == RDP_LISTEN) {
          // Resend is triggered by rdpReadPoll() return flag.
        } else if (etype == UDP_LISTEN_IN) {
        } else if (etype == UDP_LISTEN_OUT) {
        } else {
          tlog(LL_DEBUG, "wrong etype in EPOLLOUT, etype: %d\n", etype);
          exit(EXIT_FAILURE);
        }
      }
      if (evlist[n].events & EPOLLIN) {
        if (etype == PROCURATOR_TCP_LISTEN) {
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
          ret = handleIn(einfo, handleInData);

          switch (ret) {
            case -1:
            case RETEOF:
              tlog(LL_DEBUG, "handleIn, etype IN, ret: %d", ret);
              evstateTo(einfo, ES_CLOSED);
              clean(einfo);
              break;
            case 0:
              break;
            default:
              assert(0);
          }

          continue;
        } else if (etype == OUT) {
          ret = handleIn(einfo, handleOutData);

          switch (ret) {
            case -1:
              tlog(LL_DEBUG, "handleIn, etype OUT, ret: %d", ret);
              evstateTo(einfo, ES_CLOSED);
              clean(einfo);
              break;
            case RETEOF:
              tlog(LL_DEBUG, "handleIn, etype OUT, ret: %d", ret);

              // See evstateTo() for ES_HALF_CLOSED.
              if (serverflag && evBufferRemain(einfo)) {
                evstateTo(einfo, ES_HALF_CLOSED);
              } else {
                evstateTo(einfo, ES_CLOSED);
              }

              clean(einfo);
              break;
            case 0:
              break;
            default:
              assert(0);
          }

          continue;
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

            if (flag & RDP_CONN_ERROR) {
              tlog(LL_DEBUG, "RDP_CONN_ERROR");

              einfo = rdpConnGetUserData(conn);
              assert(einfo != NULL);

              if (einfo->state == ES_CLOSED) {
                tlog(LL_DEBUG, "got RDP_CONN_RRROR from a ES_CLOSED einfo");
                continue;
              }

              evstateTo(einfo, ES_CLOSED);
              clean(einfo);

              continue;
            }

            if (flag & RDP_CONNECTED) {
              einfo = rdpConnGetUserData(conn);
              assert(einfo != NULL);

              if (einfo->state == ES_CLOSED) {
                tlog(LL_DEBUG, "got RDP_CONNECTED from a ES_CLOSED einfo");
                continue;
              }

              evstateTo(einfo, ES_OPENED);

              if (trySend(einfo) == -1) {
                tlog(LL_DEBUG, "trySend: RDP_CONNECTED.");
                
                evstateTo(einfo, ES_CLOSED);
                clean(einfo);
                continue;
              }
            }

            if (flag & RDP_ACCEPT) {
              // Only accept a connection on server end.
              if (serverflag) {
                eadd(RDP_IN, 0, 0, NULL, EPOLLOUT | EPOLLIN | EPOLLET, conn);
              } else {
                rdpConnClose(conn);
                assert(0);
              }
            }

            if (flag & RDP_DATA) {
              einfo = rdpConnGetUserData(conn);
              if (einfo == NULL) {
                // It means we have called clean(einfo) in other place.
                assert(0);
                continue;
              }

              if (einfo->state == ES_CLOSED) {
                tlog(LL_DEBUG, "got RDP_DATA from a ES_CLOSED einfo");
                continue;
              }

              if (n == 0) {
                tlog(LL_DEBUG, "rdp data EOF");

                // See evstateTo for ES_HALF_CLOSED.
                if (serverflag && evBufferRemain(einfo)) {
                  evstateTo(einfo, ES_HALF_CLOSED);
                } else {
                  evstateTo(einfo, ES_CLOSED);
                }
                clean(einfo);
              } else if (n > 0) {
                if (einfo->type == RDP_IN) {
                  if (handleInBuf(einfo, handleInData, buf, n) == -1) {
                    tlog(LL_DEBUG, "handleInBuf RDP_IN");

                    evstateTo(einfo, ES_CLOSED);
                    clean(einfo);
                  }
                } else if (einfo->type == RDP_OUT) {
                  assert(serverflag == 0);
                  if (handleInBuf(einfo, handleOutData, buf, n) == -1) {
                    tlog(LL_DEBUG, "handleInBuf RDP_OUT");
                    evstateTo(einfo, ES_CLOSED);
                    clean(einfo);
                  }
                } else {
                  tlog(LL_DEBUG, "einfo type not RDP_IN or RDP_OUT");
                  assert(0);
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
                assert(0);
                continue;
              }

              if (einfo->state == ES_CLOSED) {
                tlog(LL_DEBUG, "got RDP_POLLOUT from a ES_CLOSED einfo");
                continue;
              }

              if (trySend(einfo) == -1) {
                tlog(LL_DEBUG, "trySend: eloop RDP_POLLOUT");
                evstateTo(einfo, ES_CLOSED);
                clean(einfo);
              }
            }
            if (flag & RDP_CONTINUE) {
              continue;
            }
          }
        } else if (etype == UDP_LISTEN_IN) {
          if (processUdp(einfo, handleUdpIn) == -1) {
            tlog(LL_DEBUG, "processUdp in error");
            continue;
          }
        } else if (etype == UDP_LISTEN_OUT) {
          if (processUdp(einfo, handleUdpOut) == -1) {
            tlog(LL_DEBUG, "processUdp out error");
            continue;
          }
        } else {
          tlog(LL_DEBUG, "wrong etype in EPOLLIN");
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}
