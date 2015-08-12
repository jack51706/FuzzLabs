#define _POSIX_SOURCE
#include "listener.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void *get_json_value(int r_type, json_object *jobj) {
    void *value;

    enum json_type type;
    type = json_object_get_type(jobj);
    switch (type) {
        case json_type_boolean:
            if (type == r_type) return (void *)json_object_get_boolean(jobj);
            break;
        case json_type_int:
            if (type == r_type) return (void *)json_object_get_int(jobj);
            break;
        case json_type_string:
            if (type == r_type) return (void *)json_object_get_string(jobj);
            break;
    }
    return NULL;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void *get_value(int r_type, char *req_key, char *data) {
    json_object *json = json_tokener_parse(data); 
    if (json == NULL) return(NULL);

    enum json_type type;

    json_object_object_foreach(json, key, val) { 
        if (strcmp(req_key, key) == 0) {
            return get_json_value(r_type, val);
        }
    }

    return NULL;
} 

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int kill_process(unsigned int pid) {
    int rc = kill(pid, SIGKILL);
    int error = errno;
    if (rc == -1) {
        if (error == EINVAL || error == EPERM) return 0;
        if (error == ESRCH) return 1;		// Even if it is considered as
                                                // an error that the process
                                                // does not exist, this is how
                                                // we report that we got rid
                                                // of it anyway. So, this is 
                                                // good for us.
        return 0;
    }
    return 1;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int get_process_id(int pid) {
    if (pid > 65535 || pid < 1) return(0);
    return(pid);
}

// ----------------------------------------------------------------------------
// TODO
// ----------------------------------------------------------------------------

char *process_command(char *command, char *data) {
    syslog(LOG_INFO, "command received: %s", command);

    if (strncmp(command, "ping", 6) == 0) {
        // TODO
        return NULL;
    } else if (strncmp(command, "process_list", 12) == 0) {
        // TODO
        return NULL;
    } else if (strncmp(command, "attach_process", 14) == 0) {
        // TODO
        return NULL;
    } else if (strncmp(command, "start_process", 13) == 0) {
        // TODO
        return NULL;
    } else if (strncmp(command, "restart_process", 15) == 0) {
        // TODO
        return NULL;
    } else if (strncmp(command, "kill_process", 12) == 0) {
        int pid = get_process_id((int)get_value(json_type_int, "data", data));
        if (pid == 0) return NULL;
        if (kill_process(pid) == 1) {
            char *msg = malloc(28);
            memset(msg, 0x00, 28);
            strncpy(msg, "{\"kill_process\": \"success\"}", 28);
            return(msg);
        } else {
            char *msg = malloc(27);
            memset(msg, 0x00, 27);
            strncpy(msg, "{\"kill_process\": \"failed\"}", 27);
            return(msg);
        }
    } else {
        return NULL;
    }
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
    char *command;
    char *response;
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
        read_buffer[4095] = 0x00;
        command = get_value(json_type_string, "command", read_buffer);
        if (command == NULL) {
	    send(sd, "{}", 2, 0);
        } else {
            response = process_command(command, read_buffer);
            if (response == NULL) {
	        send(sd, "{}", 2, 0);
            } else {
	        send(sd, response, strlen(response), 0);
                free(response);
            }
        }
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

