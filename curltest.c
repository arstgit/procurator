#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUF_SIZE 10000

int waitForStart(int fd, unsigned char *buf, size_t buflen) {
  ssize_t numRead;
  for (;;) {
    numRead = read(fd, buf, buflen);
    if (numRead == -1) {
      perror("read");
      exit(EXIT_FAILURE);
    }
    write(STDOUT_FILENO, buf, numRead);
    if (strstr(buf, "started") != NULL) {
      break;
    }
  }

  return 0;
}

int childCommnadTest(char *name, char *pathname, char **args) {
  int pid = fork();
  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    if (execvp(pathname, args) == -1) {
      perror("execvp");
      exit(EXIT_FAILURE);
    }
  }

  // Wait for process exit.
  if (-1 == wait(NULL)) {
    perror("wait");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  pid_t spid, cpid, w;
  int fds[2];
  struct sockaddr peaddr;
  ssize_t numRead;
  char buf[BUF_SIZE];
  int ready = 0;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
    perror("socketpair");
    exit(EXIT_FAILURE);
  }

  // Start local.
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
           "127.0.0.1", "--remote-port", "8838", "--remote-udp-port", "8839",
           "--local-port", "8080", "--local-udp-port", "8081", "--password",
           "foobar", (char *)NULL);
  }

  waitForStart(fds[0], buf, BUF_SIZE);

  // Start server.
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
           "--remote-udp-port", "8839", "--password", "foobar", (char *)NULL);
  }

  waitForStart(fds[0], buf, BUF_SIZE);

  // Run tests.
  char *udpRelayArgs[] = {
      "bash", "-c",
      "echo "
      "'00000001010000010035c2290100000100000000000003777777076578616d706c65036"
      "36f6d0000010001' | xxd -r -p | nc -u -W 1 -w 2 127.0.0.1 8081",
      (char *)NULL};
  childCommnadTest("udp relay", "bash", udpRelayArgs);

  char *curlArgs[] = {"curl",
                      "-v",
                      "http://www.example.com/",
                      "-L",
                      "--socks5-hostname",
                      "127.0.0.1:8080",
                      (char *)NULL};
  // todo run it.
  // childCommnadTest("curl proxy", "curl", curlArgs);

  // Clean, kill local and server.
  kill(spid, SIGHUP);
  kill(cpid, SIGHUP);

  printf("\nAll test finished!\n");
}
