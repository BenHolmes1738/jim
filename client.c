#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8001
#define BUF_SIZE 1024
#define ADDR "127.0.0.1"

#define handle_error(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#define NUM_MSG 5

static const char *messages[NUM_MSG] = {"Hello", "Apple", "Car", "Green",
                                        "Dog"};

int main() {
  int sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd == -1) {
    handle_error("socket");
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, ADDR, &addr.sin_addr) <= 0) {
    handle_error("inet_pton");
  }

  if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    handle_error("connect");
  }

  char buf[BUF_SIZE];
  for (int i = 0; i < NUM_MSG; i++) {
    sleep(1);
    // prepare message
    // this pads the desination with NULL
    strncpy(buf, messages[i], BUF_SIZE);

    if (write(sfd, buf, BUF_SIZE) == -1) {
      handle_error("write");
    } else {
      printf("Sent: %s\n", messages[i]);
    }
  }

  exit(EXIT_SUCCESS);
}
