#include "listener.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void handle_connection(void *conn) {
    Connection *c = (Connection *)conn;
    struct sockaddr_in *sin = (struct sockaddr_in*)c->sin;
    char *client_ip = (char *)inet_ntoa(sin->sin_addr);
    syslog(LOG_ERR, "Accepted connection from: %s", client_ip);
    free(conn);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void listener(void *l_details) {
    Listener *l = (Listener *)l_details;
    int port = l->port;
    int sd, n_sd;
    socklen_t c_len;
    struct sockaddr_in s_addr, c_addr;
    int running = 1;
    pthread_t tid[AGENT_MAX_CONN];

    free(l);

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
        Connection *conn = malloc(sizeof(Connection));
        conn->sock = n_sd;
        conn->sin = &c_addr;
        conn->s_addr_len = c_len;
        if (pthread_create(&(tid[0]), NULL, &handle_connection, (void *)conn) != 0) {
            syslog (LOG_ERR, "failed to accept connection");
        }
    }
}

