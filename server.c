#include "core.h"

static char outhost[256], outport[6];

static int handleIn(struct evinfo *einfo) {
  int outfd, infd = einfo->fd;
  ssize_t numRead, consume;
  int atyp, headerlen;
  struct epoll_event ev;

  numRead = recv(infd, buf, BUF_SIZE, MSG_PEEK);
  if (numRead == -1) {
    perror("recv handleIn MSG_PEEK");
    return -1;
  }
  if (numRead == 0) {
    return -1;
  }
  consume = numRead;

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
      return -1;
    }

    if (connOut(einfo, outhost, outport) == -1) {
      return -1;
    }

    einfo->stage = 1;
  } else if (einfo->stage == 1) {
    outfd = einfo->ptr->fd;
    if (send(outfd, buf, numRead, 0) == -1) {
      perror("send: handleIn: stage1");
      return -1;
    }
  } else {
    return -1;
  }

  numRead = recv(infd, buf, consume, 0);
  if (numRead == -1) {
    perror("handleIn recv consume");
    return -1;
  }
  if (numRead == 0) {
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) { eloop(REMOTE_PORT, handleIn); }
