#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8000
#define BUF_SIZE 64
#define ADDR "127.0.0.1"

#define handle_error(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)
/*
Questions to answer at top of client.c:
(You should not need to change the code in client.c)
1. What is the address of the server it is trying to connect to (IP address and
port number). IP address = 127.0.0.1 port number = 8000
2. Is it UDP or TCP? How do you know?
TCP, binds and listens
3. The client is going to send some data to the server. Where does it get this
data from? How can you tell in the       code? i gets from user input, can tell
from read(STDIN, ...)
4. How does the client program end? How can you tell that in the code?
it ends if bytes read is less than 1, can tell from while (read(...) > 1) {...}
*/

int main() {
  struct sockaddr_in addr;
  int sfd;
  ssize_t num_read;
  char buf[BUF_SIZE];

  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd == -1) {
    handle_error("socket");
  }

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, ADDR, &addr.sin_addr) <= 0) {
    handle_error("inet_pton");
  }

  int res = connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
  if (res == -1) {
    handle_error("connect");
  }

  while ((num_read = read(STDIN_FILENO, buf, BUF_SIZE)) > 1) {
    if (write(sfd, buf, num_read) != num_read) {
      handle_error("write");
    }
    printf("Just sent %zd bytes.\n", num_read);
  }

  if (num_read == -1) {
    handle_error("read");
  }

  close(sfd);
  exit(EXIT_SUCCESS);
}

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 64
#define PORT 8000
#define LISTEN_BACKLOG 32

// Shared counters for: total # messages, and counter of clients (used for
// assigning client IDs)
int total_message_count = 0;
int client_id_counter = 1;

// Mutexs to protect above global state.
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;

struct client_info {
  int cfd;
  int client_id;
};

void *handle_client(void *arg) {
  struct client_info *client = (struct client_info *)arg;

  // TODO: print the message received from client
  // TODO: increase total_message_count per message

  char buffer[64];
  int bytes =
      snprintf(buffer, sizeof(buffer), "new client created ID %d socket %d\n",
               client->client_id, client->cfd);

  write(STDOUT_FILENO, buffer, bytes);

  while (true) {
    const int SZ = 256;
    char buf[SZ];
    ssize_t bRead = read(client->cfd, buf, SZ);

    if (bRead == 0) {
      break;
    }

    char buff[64];
    pthread_mutex_lock(&count_mutex);
    ssize_t byte =
        snprintf(buff, sizeof(buff), "msg\t%d; ID %d: ", total_message_count,
                 client->client_id);
    total_message_count++;
    pthread_mutex_unlock(&count_mutex);

    write(STDOUT_FILENO, buff, byte);
    write(STDOUT_FILENO, buf, bRead);
  }

  char buffr[64];
  int byts = snprintf(buffr, sizeof(buffr), "ending thread client ID %d\n",
                      client->client_id);

  write(STDOUT_FILENO, buffr, byts);

  return NULL;
}

int main() {
  struct sockaddr_in addr;
  int sfd;

  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd == -1) {
    handle_error("socket");
  }

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
    handle_error("bind");
  }
  if (listen(sfd, LISTEN_BACKLOG) == -1) {
    handle_error("listen");
  }

  for (;;) {
    // TODO: create a new thread when a new connection is encountered
    int cfd = accept(sfd, NULL, NULL);
    if (cfd == -1) {
      perror("accept");
    }

    struct client_info *clInfo =
        (struct client_info *)malloc(sizeof(struct client_info *));
    clInfo->cfd = cfd;
    printf("%d\n", clInfo->cfd);

    pthread_mutex_lock(&client_id_mutex);
    clInfo->client_id = client_id_counter;
    client_id_counter++;
    pthread_mutex_unlock(&client_id_mutex);

    pthread_t thr;
    pthread_create(&thr, NULL, handle_client, clInfo);

    // TODO: call handle_client() when launching a new thread, and provide
    // client_info
  }

  if (close(sfd) == -1) {
    handle_error("close");
  }

  return 0;
}
