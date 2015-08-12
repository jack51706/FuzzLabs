#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <syslog.h>
#include <json/json.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "common.h"

typedef struct {
    int port;
} Listener;

typedef struct {
    int sock;
    void *sin;
    int s_addr_len;
} Connection;

// The message structure should be as simple as:
// {"command": "<command>", "data": "<data>"}

typedef struct {
    char *command;
    char *data;
} Message;

void listener(void *l_details);
void handle_connection(void *conn);

