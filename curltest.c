#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUF_SIZE 10000

int main(int argc, char *argv[]) {
  pid_t spid, cpid, curlPid, w;
  int fds[2];
  struct sockaddr peaddr;
  ssize_t numRead;
  char buf[BUF_SIZE];
  int ready = 0;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
    perror("socketpair");
    exit(EXIT_FAILURE);
  }

  cpid = fork();
  if (cpid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (cpid == 0) {
    if (dup2(fds[1], STDIN_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    if (dup2(fds[1], STDOUT_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    close(fds[1]);
    execlp("./procurator-local", "procurator-local", "--remote-host",
           "127.0.0.1", "--remote-port", "8838", "--local-port", "8080",
           (char *)NULL);
  }

  spid = fork();
  if (spid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (spid == 0) {
    if (dup2(fds[1], STDIN_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    if (dup2(fds[1], STDOUT_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    close(fds[1]);

    execlp("./procurator-server", "procurator-server", "--remote-port", "8838",
           (char *)NULL);
  }

  for (;;) {
    numRead = read(fds[0], buf, BUF_SIZE);
    if (numRead == -1) {
      perror("recvfrom");
      exit(EXIT_FAILURE);
    }
    write(STDOUT_FILENO, buf, numRead);
    if (strstr(buf, "started") != NULL) {
      ready++;
      ready++;
    }
    if (ready == 2) {
      curlPid = fork();
      if (curlPid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
      }
      if (curlPid == 0) {
        execlp("curl", "curl", "-v", "http://www.example.com/", "-L",
               "--socks5-hostname", "127.0.0.1:8080", (char *)NULL);
      }
      break;
    }
  }
  if (-1 == wait(NULL)) {
    perror("wait");
    exit(EXIT_FAILURE);
  }
  kill(spid, SIGHUP);
  kill(cpid, SIGHUP);

  printf("\ntest file end!\n");
}
