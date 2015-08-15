#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

typedef struct {
    int sock;
    void *sin;
    int s_addr_len;
} Connection;

void handle_connection(void *conn) {
    int running = 1;
    Connection *c = (Connection *)conn;
    int sd = c->sock;
    int rc = 0;
    struct sockaddr_in *sin = (struct sockaddr_in*)c->sin;
    char *command;
    char *response;
    char *client_ip = (char *)inet_ntoa(sin->sin_addr);
    char read_buffer[64];
    free(conn);

    syslog(LOG_INFO, "Accepted connection from: %s", client_ip);

    while (running == 1) {
        memset(read_buffer, 0x00, 64);
        rc = recv(sd, read_buffer, 4096, 0);
        if (rc <= 0) break;
        printf("received: %s\n", read_buffer);
    }

    syslog(LOG_INFO, "Disconnected from: %s", client_ip);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void main() {
    int port = 6667;
    int sd, n_sd;
    socklen_t c_len;
    struct sockaddr_in s_addr, c_addr;
    int running = 1;
    pthread_t tid[2];

    syslog(LOG_INFO, "VULNERABLE TEST APPLICATION STARTED");

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        syslog(LOG_ERR, "Failed to start listener on port %d", port);
        exit(1);
    } 

    bzero((char *) &s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);
    if (bind(sd, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
        syslog(LOG_ERR, "Failed to start listener on port %d", port);
        exit(1);
    }

    listen(sd, 2);
    c_len = sizeof(c_addr);

    while (running == 1) {
        n_sd = accept(sd,  
                      (struct sockaddr *) &c_addr, 
                      &c_len);
        if (n_sd < 0) continue;
        Connection *conn = malloc(sizeof(Connection));
        conn->sock = n_sd;
        conn->sin = &c_addr;
        conn->s_addr_len = c_len;
        if (pthread_create(&(tid[0]), NULL, &handle_connection, (void *)conn) != 0) {
            syslog (LOG_ERR, "failed to accept connection");
        }
    }
}

