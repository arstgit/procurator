#include "core.h"

extern int serverflag;

static char reqAddr[259];

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
      tlog(LL_DEBUG, "Not implemented cmd 03");
      return -1;
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
  fprintf(stderr, "Usage: procurator-local [options]\n");
  fprintf(stderr, "       procurator-local --help\n");
  fprintf(stderr, "Examples:\n");
  fprintf(stderr, "       procurator-local --remote-host 127.0.0.1 "
                  "--remote-port 8080 --local-port 1080 --password foobar\n");
  exit(1);
}

int main(int argc, char **argv) {
  serverflag = 0;

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
    if (!strcmp(argv[i], "--local-port")) {
      localPort = argv[++i];
      continue;
    }

    if (!strcmp(argv[i], "--password")) {
      password = argv[++i];
      continue;
    }
  }

  if (remoteHost == NULL || remotePort == NULL || localPort == NULL ||
      password == NULL)
    usage();

  eloop(localPort, handleInData);
}
