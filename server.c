#include "core.h"

extern int serverflag;
extern int globalLogLevel;

static char outhost[256], outport[6];
static char udpbuf[1600];

static int handleInData(struct evinfo *einfo, unsigned char *buf,
                        ssize_t numRead) {
  int outfd, infd = einfo->fd;
  int atyp, headerlen, consume;
  char *ipv4;

  if (einfo->stage == 0) {

    /*
            +------+----------+----------+
            | ATYP | DST.ADDR | DST.PORT |
            +------+----------+----------+
            |  1   | Variable |    2     |
            +------+----------+----------+
    */

    atyp = buf[0];
    if (atyp == '\x01') {
      // IP V4 address
      ipv4 = inet_ntoa(*(struct in_addr *)(buf + 1));

      memcpy(outhost, ipv4, strlen(ipv4) + 1);
      snprintf(outport, 6, "%hu", ntohs(*(uint16_t *)(buf + 5)));
      headerlen = 7;
      consume = headerlen;
    } else if (atyp == '\x03') {
      // DOMAINNAME
      memcpy(outhost, buf + 2, buf[1]);
      outhost[buf[1]] = '\0';
      snprintf(outport, 6, "%hu", ntohs(*(uint16_t *)(buf + 2 + buf[1])));
      headerlen = 4 + buf[1];
      consume = headerlen;
    } else if (atyp == '\x04') {
      // IP V6 address
      tlog(LL_DEBUG, "Not implemented ipv6, stage0");
      return -1;
    } else {
      tlog(LL_DEBUG, "Wrong atype");

      return -1;
    }

    tlog(LL_DEBUG, "Connecting to: %s", outhost);

    if (connOut(einfo, outhost, outport) == -1) {
      tlog(LL_DEBUG, "connOut error");
      return -1;
    }
    // to do, numRead may exceed consume
    if (numRead > consume) {
      if (sendOrStore(0, buf + consume, numRead - consume, 0, einfo) == -1) {
        tlog(LL_DEBUG, "sendOrStore, stage0");
        return -1;
      }
    }

    einfo->stage = 1;
  } else if (einfo->stage == 1) {
    if (sendOrStore(0, buf, numRead, 0, einfo) == -1) {
      tlog(LL_DEBUG, "sendOrStore, stage1");
      return -1;
    }
  } else {
    tlog(LL_DEBUG, "unknown stage");
    return -1;
  }

  return 0;
}

int handleUdpIn(struct evinfo *einfo, unsigned char *buf, ssize_t buflen,
                struct sockaddr *src_addr, socklen_t addrlen) {
  char *ipv4;
  int headerlen;

  unsigned char atyp = buf[0];
  if (atyp == '\x01') {
    // IP V4 address
    ipv4 = inet_ntoa(*(struct in_addr *)(buf + 1));

    memcpy(outhost, ipv4, strlen(ipv4) + 1);
    snprintf(outport, 6, "%hu", ntohs(*(uint16_t *)(buf + 5)));
    headerlen = 7;
  } else if (atyp == '\x03') {
    // DOMAINNAME address.
    tlog(LL_DEBUG, "Not implemented domainname, udp");
    return -1;
  } else if (atyp == '\x04') {
    // IP V6 address
    tlog(LL_DEBUG, "Not implemented ipv6, udp");
    return -1;
  } else {
    tlog(LL_DEBUG, "Wrong atype, udp");
    return -1;
  }

  ssize_t numSend =
      sendUdpOut(einfo, buf + headerlen, buflen - headerlen, outhost, outport);
  if (numSend == -1) {
    tlog(LL_DEBUG, "sendUdp error");
    return -1;
  }

  if (udpRelayDictAddOrUpdate(buf, (struct sockaddr_storage *)src_addr,
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

  // After this, udpbuf already contain the header to be needed.
  if (udpRelayDictGetBySockaddr(src_addr, addrlen, udpbuf, &dst_addr,
                                &dst_addrlen) == -1) {

    tlog(LL_DEBUG, "udpRelayDictGetBySockaddr return nothing");
    return -1;
  }

  memcpy(udpbuf + 7, buf, buflen);

  ssize_t numSend = sendUdpIn(einfo, udpbuf, buflen + 7, dst_addr, dst_addrlen);
  if (numSend == -1) {
    tlog(LL_DEBUG, "sendUdpIn error");
    return -1;
  }

  return 0;
}

static void usage(void) {
  fprintf(stderr, "Usage: procurator-server [options]\n");
  fprintf(stderr, "       procurator-server --help\n");
  fprintf(stderr, "Examples:\n");
  fprintf(stderr, "       procurator-server --remote-port 8080 "
                  "--remote-udp-port 8081 --password foobar\n");
  exit(1);
}

int main(int argc, char **argv) {
  serverflag = 1;
  globalLogLevel = LL_DEBUG;

  // Read config from argv.
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--help")) {
      usage();
    }

    if (!strcmp(argv[i], "--remote-port")) {
      remotePort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--remote-udp-port")) {
      remoteUdpPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--password")) {
      password = argv[++i];
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

  if (remotePort == NULL || password == NULL || remoteUdpPort == NULL)
    usage();

  eloop(remotePort, remoteUdpPort, handleInData, handleUdpIn, handleUdpOut);
}
