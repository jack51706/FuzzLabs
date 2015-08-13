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

void *get_json_value(int r_type, json_object *jobj);
void *get_value(int r_type, char *req_key, char *data);
int kill_process(unsigned int pid);
int validate_process_id(int pid);
char *process_command(char *command, char *data);
void handle_connection(void *conn);
void listener(void *l_details);

