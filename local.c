#include "core.h"

char reqAddr[259];

static int handleIn(struct evinfo *einfo) {
  int outfd, infd = einfo->fd;
  ssize_t numRead;
  int cmd, atyp;
  struct epoll_event ev;

  numRead = recv(infd, buf, BUF_SIZE, 0);
  if (numRead == -1) {
    perror("handleIn recv");
    return -1;
  }
  if (numRead == 0) {
    return -1;
  }

  if (einfo->stage == 0) {
    if (send(infd, "\x05\x00", 2, 0) == -1) {
      perror("handleIn: stage0: send");
      return -1;
    }
    if (connOut(einfo, REMOTE_HOST, REMOTE_PORT) == -1) {
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
        write(2, "4\n", 2);
        return -1;
      } else if (atyp == '\x03') {
        // DOMAINNAME
        memcpy(reqAddr, buf + 3, 4 + buf[4]);
      } else if (atyp == '\x04') {
        // IP V6 address
        write(2, "6\n", 2);
        return -1;
      } else {
        return -1;
      }

      outfd = einfo->ptr->fd;
      if (send(outfd, reqAddr, 4 + buf[4], 0) == -1) {
        perror("handleIn: stage1: send reqAddr");
        return -1;
      }

      if (send(infd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x01", 10, 0) == -1) {
        perror("handleIn: stage1: send connected info");
        return -1;
      }

      einfo->stage = 2;
    } else if (cmd == '\x02') {
      // BIND
      return -1;
    } else if (cmd == '\x03') {
      // UDP ASSOCIATE
      return -1;
    } else {
      return -1;
    }
  } else if (einfo->stage == 2) {
    outfd = einfo->ptr->fd;
    if (send(outfd, buf, numRead, 0) == -1) {
      perror("handleIn: stage4. send");
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) { eloop(LOCAL_PORT, handleIn); }
