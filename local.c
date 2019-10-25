#include "core.h"

char reqAddr[259];

static int handleInData(struct evinfo *einfo, unsigned char *buf,
                        ssize_t numRead) {
  int outfd, infd = einfo->fd;
  int cmd, atyp;

  if (einfo->stage == 0) {
    if (connOut(einfo, REMOTE_HOST, REMOTE_PORT) == -1) {
      return -1;
    }

    if (sendOrStore(infd, "\x05\x00", 2, 0, einfo, 1) == -1) {
      eprint(STDOUT_FILENO, "sendOrStore, stage0\n", INFO_LEVEL, 0);
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
        // IP V4 address
        eprint(STDOUT_FILENO, "Not implemented ipv4, stage1\n", INFO_LEVEL, 0);
        return -1;
      } else if (atyp == '\x03') {
        // DOMAINNAME
        memcpy(reqAddr, buf + 3, 4 + buf[4]);
      } else if (atyp == '\x04') {
        // IP V6 address
        eprint(STDOUT_FILENO, "Not implemented ipv6, stage1\n", INFO_LEVEL, 0);
        return -1;
      } else {
        eprint(STDOUT_FILENO, "Not implemented atype\n", INFO_LEVEL, 0);
        return -1;
      }

      outfd = einfo->ptr->fd;
      if (sendOrStore(outfd, reqAddr, 4 + buf[4], 0, einfo, 0) == -1) {
        eprint(STDOUT_FILENO, "sendOrStore, stage1, write to outfd\n",
               INFO_LEVEL, 0);
        return -1;
      }

      if (sendOrStore(infd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x01", 10, 0,
                      einfo, 1) == -1) {
        eprint(STDOUT_FILENO, "sendOrStore, stage1, write to infd\n",
               INFO_LEVEL, 0);
        return -1;
      }

      einfo->stage = 2;
    } else if (cmd == '\x02') {
      // BIND
      eprint(STDOUT_FILENO, "Not implemented cmd 02\n", INFO_LEVEL, 0);
      return -1;
    } else if (cmd == '\x03') {
      // UDP ASSOCIATE
      eprint(STDOUT_FILENO, "Not implemented cmd 03\n", INFO_LEVEL, 0);
      return -1;
    } else {
      return -1;
    }
  } else if (einfo->stage == 2) {
    outfd = einfo->ptr->fd;
    if (sendOrStore(outfd, buf, numRead, 0, einfo, 0) == -1) {
      eprint(STDOUT_FILENO, "sendOrStore, stage2\n", INFO_LEVEL, 0);
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  serverflag = 0;
  eloop(LOCAL_PORT, handleInData);
}
