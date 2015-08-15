#include "listener.h"
#include "connection.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

Message *get_command(char *data) {
    cJSON *json = cJSON_Parse(data);
    if (json == NULL) return(NULL);
    cJSON *command = cJSON_GetObjectItem(json, "command");
    if (command == NULL) return(NULL);
    if (command->type != cJSON_String) return(NULL);
    
    Message *msg = (Message *)malloc(sizeof(Message));
    msg->command = command->valuestring;
    msg->j_data = NULL;
    
    if (cJSON_GetObjectItem(json, "data") != NULL)
        msg->j_data = json;
    
    return(msg);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

char *get_data(cJSON *data) {
    if (data == NULL) return(NULL);
    cJSON *j_data = cJSON_GetObjectItem(data, "data");
    if (j_data == NULL) return(NULL);
    if (j_data->type != cJSON_String) return(NULL);
    return(j_data->valuestring);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

static void *start_monitor(void *m) {
    Monitor *monitor = (Monitor *)m;
    monitor->start();
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

static void *handle_connection(void *c) {
    Connection *conn = (Connection *)c;
    unsigned int r_len = 1;
    char *data = (char *)malloc(RECV_BUFFER_SIZE);
    Message *msg = NULL;
    Monitor *monitor = NULL;
    Status *m_status = NULL;
    pthread_t tid;
    int reported = 0;
    
    syslog(LOG_INFO, "accepted connection from engine: %s", conn->address());

    while(r_len != 0) {
        // Watch monitor here
        if (monitor != NULL) {
            m_status = monitor->status();
            if (m_status->getPid() > 0 &&
                (m_status->getState() == P_TERM ||
                m_status->getState() == P_SIGTERM) &&
                reported == 0) {
                conn->transmit("{\"status\": \"crash\"}", 19);
                reported = 1;
            }
        }
        
        // Check if data received from engine
        r_len = conn->receive(data);
        if (r_len < 1) continue;
        
        if (msg != NULL) free(msg);
        msg = get_command(data);
        if (msg == NULL) continue; 
        syslog(LOG_ERR, "[%s] command: %s", 
                conn->address(),
                msg->command);
        
        // Handle command received
        if (!strcmp(msg->command, "ping")) {
            conn->transmit("{\"command\": \"pong\"}", 19);
        } else if (!strcmp(msg->command, "kill")) {
            if (monitor != NULL) {
                if (monitor->terminate()) {
                    conn->transmit("{\"kill\": \"success\"}", 19);
                } else {
                    conn->transmit("{\"kill\": \"failed\"}", 18);
                }
            }
        } else if (!strcmp(msg->command, "start")) {
            char *cmd_line = (char *)get_data(msg->j_data);
            if (cmd_line == NULL) {
                syslog (LOG_ERR, "start command data is empty");
                continue;
            }
            
            monitor = new Monitor(cmd_line);
            if (pthread_create(&tid, NULL, &start_monitor, monitor) != 0) {
                syslog (LOG_ERR, "failed to start monitor");
            }
        } else {
            syslog(LOG_ERR, "[%s] unsupported command: %s", 
                    conn->address(),
                    msg->command);
        }
    }

    memset(data, 0x00, RECV_BUFFER_SIZE);
    free(data);
    syslog(LOG_INFO, "disconnected from engine: %s", conn->address());
    if (msg != NULL) free(msg);
    if (monitor != NULL) monitor->terminate();

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
