#include "listener.h"
#include "connection.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

static void *handle_connection(void *c) {
    Connection *conn = (Connection *)c;
    unsigned int r_len = 1;
    char *data = (char *)malloc(RECV_BUFFER_SIZE);
    
    syslog(LOG_INFO, "Accepted connection from engine: %s", conn->address());

    while(r_len != 0) {
        r_len = conn->receive(data);
        // TODO: process data
    }
    
    memset(data, 0x00, RECV_BUFFER_SIZE);
    free(data);
    syslog(LOG_INFO, "Disconnected from engine: %s", conn->address());

}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void listener(int port) {
    int sd, n_sd;
    socklen_t c_len;
    struct sockaddr_in s_addr, c_addr;
    int running = 1;
    pthread_t tid[AGENT_MAX_CONN];

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

    listen(sd, AGENT_MAX_CONN);
    c_len = sizeof(c_addr);

    while (running == 1) {
        n_sd = accept(sd,
                      (struct sockaddr *) &c_addr,
                      &c_len);
        if (n_sd < 0) continue;

        Connection *conn = new Connection(n_sd, &c_addr);

        if (pthread_create(&(tid[0]), NULL, &handle_connection, conn) != 0) {
            syslog (LOG_ERR, "failed to accept connection");
        }

    }
}
