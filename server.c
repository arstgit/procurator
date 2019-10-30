#include "core.h"

static char outhost[256], outport[6];

static int handleInData(struct evinfo *einfo, unsigned char *buf,
                        ssize_t numRead) {
  int outfd, infd = einfo->fd;
  int atyp, headerlen, consume;

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
      eprint(STDOUT_FILENO, "Not implemented ipv4, stage0\n", INFO_LEVEL, 0);
      return -1;
    } else if (atyp == '\x03') {
      // DOMAINNAME
      memcpy(outhost, buf + 2, buf[1]);
      outhost[buf[1]] = '\0';
      snprintf(outport, 6, "%hu", ntohs(*(uint16_t *)(buf + 2 + buf[1])));
      headerlen = 4 + buf[1];
      consume = headerlen;
    } else if (atyp == '\x04') {
      // IP V6 address
      eprint(STDOUT_FILENO, "Not implemented ipv6, stage0\n", INFO_LEVEL, 0);
      return -1;
    } else {
      eprint(STDOUT_FILENO, "Wrong atype\n", INFO_LEVEL, 0);

      return -1;
    }
    if (connOut(einfo, outhost, outport) == -1) {
      return -1;
    }
    // to do, numRead may exceed consume
    if (numRead > consume) {
      outfd = einfo->ptr->fd;
      if (sendOrStore(outfd, buf + consume, numRead - consume, 0, einfo, 0) ==
          -1) {
        eprint(STDOUT_FILENO, "sendOrStore, stage0\n", INFO_LEVEL, 0);
        return -1;
      }
    }

    einfo->stage = 1;
  } else if (einfo->stage == 1) {
    outfd = einfo->ptr->fd;
    if (sendOrStore(outfd, buf, numRead, 0, einfo, 0) == -1) {
      eprint(STDOUT_FILENO, "sendOrStore, stage1\n", INFO_LEVEL, 0);
      return -1;
    }
  } else {
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  serverflag = 1;
  eloop(REMOTE_PORT, handleInData);
}
