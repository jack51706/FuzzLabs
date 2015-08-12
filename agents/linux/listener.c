#include "listener.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void json_parse(json_object * jobj) {
    enum json_type type;

    json_object_object_foreach(jobj, key, val) { 

    // printf("type: ",type);
    type = json_object_get_type(val);
    switch (type) {
        case json_type_boolean: 
            break; 
        case json_type_double: 
            break; 
        case json_type_int: 
            break; 
        case json_type_string:
            // Handle val
            break; 
        case json_type_object: 
            // jobj = json_object_object_get(jobj, key);
            json_parse(jobj); 
            break;
        case json_type_array:
            // json_parse_array(jobj, key);
            break;
        }
    }
} 

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void *process_message(char *data) {
    json_object *json = json_tokener_parse(data); 
    if (json == NULL) return(NULL);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void handle_connection(void *conn) {
    int running = 1;
    Connection *c = (Connection *)conn;
    int sd = c->sock;
    int rc = 0;
    struct sockaddr_in *sin = (struct sockaddr_in*)c->sin;
    char *client_ip = (char *)inet_ntoa(sin->sin_addr);
    char read_buffer[4096];		// We use a 4096 bytes receive buffer
					// which should be more than enough to
					// handle any command received from
					// the engine.
    free(conn);

    syslog(LOG_INFO, "Accepted connection from engine: %s", client_ip);

    while (running == 1) {
        memset(read_buffer, 0x00, 4096);
        rc = recv(sd, read_buffer, 4096, 0);
        if (rc <= 0) break;
        if (process_message(read_buffer) == NULL) {
            send(sd, "{}", 2, 0);
        }
        read_buffer[4095] = 0x00;
    }

    syslog(LOG_INFO, "Disconnected from engine: %s", client_ip);
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

