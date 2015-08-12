#include <syslog.h>
#include <json/json.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "common.h"

typedef struct {
    int port;
} Listener;

typedef struct {
    int sock;
    void *sin;
    int s_addr_len;
} Connection;

void listener(void *l_details);
void handle_connection(void *conn);

