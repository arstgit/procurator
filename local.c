#include "core.h"

extern int serverflag;
extern int globalLogLevel;

static char *udpTargetHost;
static char *udpTargetPort;
static unsigned char udpTargetHeader[255];

static char reqAddr[259];
static char udpAssociateReply[10] = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";

static unsigned char udpbuf[1600];

static int handleInData(struct evinfo *einfo, unsigned char *buf,
                        ssize_t numRead) {
  int cmd, atyp;
  int addrlen;

  if (einfo->stage == 0) {
    if (connOut(einfo, remoteHost, remotePort) == -1) {
      return -1;
    }

    if (sendOrStore(1, "\x05\x00", 2, 0, einfo) == -1) {
      tlog(LL_DEBUG, "sendOrStore, stage0");
      return -1;
    }

    einfo->stage = 1;
  } else if (einfo->stage == 1) {

    /*
            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
    */

    cmd = buf[1];
    atyp = buf[3];
    if (cmd == '\x01') {
      // CONNECT
      if (atyp == '\x01') {
        // IP V4 addreseinfos
        addrlen = 7;
        memcpy(reqAddr, buf + 3, addrlen);
      } else if (atyp == '\x03') {
        // DOMAINNAME
        addrlen = 4 + buf[4];
        memcpy(reqAddr, buf + 3, addrlen);
      } else if (atyp == '\x04') {
        // IP V6 address
        tlog(LL_DEBUG, "wrong atyp \x04, stage1");
        return -1;
      } else {
        tlog(LL_DEBUG, "Not implemented atype");
        return -1;
      }

      if (sendOrStore(0, reqAddr, addrlen, 0, einfo) == -1) {
        tlog(LL_DEBUG, "sendOrStore, stage1, write to outfd");
        return -1;
      }

      if (sendOrStore(1, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x01", 10, 0,
                      einfo) == -1) {
        tlog(LL_DEBUG, "sendOrStore, stage1, write to infd");
        return -1;
      }

      einfo->stage = 2;
    } else if (cmd == '\x02') {
      // BIND
      tlog(LL_DEBUG, "Not implemented cmd 02");
      return -1;
    } else if (cmd == '\x03') {
      // UDP ASSOCIATE
      tlog(LL_DEBUG, "Got a udp associate request, cmd 03");

      if (sendOrStore(1, udpAssociateReply, 10, 0, einfo) == -1) {
        tlog(LL_DEBUG, "sendOrStore, stage1, write to infd, cmd 03");
        return -1;
      }
    } else {
      return -1;
    }
  } else if (einfo->stage == 2) {
    if (sendOrStore(0, buf, numRead, 0, einfo) == -1) {
      tlog(LL_DEBUG, "sendOrStore, stage2");
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

static void usage(void) {
  fprintf(stderr, "Version: %s\n", version);
  fprintf(stderr, "Usage: procurator-local [options]\n");
  fprintf(stderr, "       procurator-local --help\n");
  fprintf(stderr, "Examples:\n");
  fprintf(
      stderr,
      "       procurator-local --remote-host 127.0.0.1 "
      "--remote-port 8080 --remote-udp-port 8081 --local-port 1080 "
      "--local-udp-port 1081 "
      "--password foobar --udp-target-host 127.0.0.1 --udp-target-port 53\n");
  exit(1);
}

// UDP packets format received from clients.
//   +----+------+------+----------+----------+----------+
//   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//   +----+------+------+----------+----------+----------+
//   | 2  |  1   |  1   | Variable |    2     | Variable |
//   +----+------+------+----------+----------+----------+
//
int handleUdpIn(struct evinfo *einfo, unsigned char *buf, ssize_t buflen,
                struct sockaddr *src_addr, socklen_t addrlen) {
  if (udpTargetHost != NULL && udpTargetPort != NULL) {
    memcpy(udpbuf, udpTargetHeader, 10);
    memcpy(udpbuf + 10, buf, buflen);

    buf = (unsigned char *)udpbuf;
    buflen = buflen + 10;
  }

  if (buflen < 8) {
    tlog(LL_DEBUG, "buflen less than 8");
    return -1;
  }

  char fragmentFlag = buf[2];
  if (fragmentFlag != '\x00') {
    tlog(LL_DEBUG, "fragmentFlag not 0");
    return -1;
  }

  char atyp = buf[3];
  if (atyp == '\x01') {
    // IP V4 addreseinfos
    memcpy(reqAddr, buf + 3, 7);
  } else if (atyp == '\x03') {
    // DOMAINNAME
    tlog(LL_DEBUG, "wrong atyp \x03");
    return -1;
  } else if (atyp == '\x04') {
    // IP V6 address
    tlog(LL_DEBUG, "wrong atyp \x04");
    return -1;
  } else {
    tlog(LL_DEBUG, "Not implemented atype");
    return -1;
  }

  int numSend;
  numSend = sendUdpOut(einfo, buf + 3, buflen - 3, remoteHost, remoteUdpPort);
  if (numSend == -1) {
    tlog(LL_DEBUG, "sendUdp error out");
    return -1;
  }

  if (udpRelayDictAddOrUpdate(buf + 3, (struct sockaddr_storage *)src_addr,
                              addrlen) == -1) {
    tlog(LL_DEBUG, "udpRelayAdd error");
    exit(EXIT_FAILURE);
  }

  return 0;
}

int handleUdpOut(struct evinfo *einfo, unsigned char *buf, ssize_t buflen,
                 struct sockaddr *src_addr, socklen_t addrlen) {
  struct sockaddr_storage *dst_addr;
  socklen_t dst_addrlen;

  if (udpRelayDictGetByKey(buf, &dst_addr, &dst_addrlen) == -1) {
    tlog(LL_DEBUG, "udpRelayDictGetByKey return nothing");
    return -1;
  }

  memcpy(udpbuf, "\x00\x00\x00", 3);
  memcpy(udpbuf + 3, buf, buflen);
  buf = (unsigned char *)udpbuf;
  buflen = buflen + 3;

  if (udpTargetHost != NULL && udpTargetPort != NULL) {
    buf = buf + 10;
    buflen = buflen - 10;
  }

  ssize_t numSend = sendUdpIn(einfo, buf, buflen, dst_addr, dst_addrlen);
  if (numSend == -1) {
    tlog(LL_DEBUG, "sendUdpIn error");
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  serverflag = 0;
  globalLogLevel = LL_DEBUG;

  // Read config from argv.
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--help")) {
      usage();
    }

    if (!strcmp(argv[i], "--remote-host")) {
      remoteHost = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--remote-port")) {
      remotePort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--remote-udp-port")) {
      remoteUdpPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--local-port")) {
      localPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--local-udp-port")) {
      localUdpPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--password")) {
      password = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--udp-target-host")) {
      udpTargetHost = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--udp-target-port")) {
      udpTargetPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--log-level")) {
      if (!strcmp(argv[++i], "LL_DEBUG")) {
        globalLogLevel = LL_DEBUG;
      }
      if (!strcmp(argv[i], "LL_VERBOSE")) {
        globalLogLevel = LL_VERBOSE;
      }
      continue;
    }
  }

  // Return the listening udp address and port to client.
  // Addresse is 127.0.0.1 for now.
  if (remoteHost == NULL || remotePort == NULL || remoteUdpPort == NULL ||
      localPort == NULL || localUdpPort == NULL || password == NULL)
    usage();

  // Populate udp assiciate message string.
  inet_aton("127.0.0.1", (struct in_addr *)(udpAssociateReply + 4));
  snprintf(udpAssociateReply + 8, 2, "%hu",
           htons((uint16_t)atoi(localUdpPort)));

  // Populate udpTargetHeader if needed.
  // todo delete assert.
  assert(udpTargetHeader[0] == '\x00');
  if (udpTargetHost != NULL && udpTargetPort != NULL) {
    struct addrinfo *ainfo;
    if (getaddrinfoWithoutHints(udpTargetHost, udpTargetPort, &ainfo) == -1) {
      tlog(LL_DEBUG, "getaddrinfoWithoutHints error");
      return -1;
    }

    memcpy(udpTargetHeader, "\x00\x00\x00\x01", 4);
    memcpy(udpTargetHeader + 4,
           &((struct sockaddr_in *)ainfo->ai_addr)->sin_addr, 4);
    memcpy(udpTargetHeader + 8,
           &((struct sockaddr_in *)ainfo->ai_addr)->sin_port, 2);
  }

  eloop(localPort, localUdpPort, handleInData, handleUdpIn, handleUdpOut);
}
