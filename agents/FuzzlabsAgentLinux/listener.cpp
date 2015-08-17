#include "listener.h"
#include "connection.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

Message *get_command(char *data) {
    cJSON *json = cJSON_Parse(data);
    if (json == NULL) return(NULL);
    cJSON *command = cJSON_GetObjectItem(json, "command");
    if (command == NULL) {
        free(json);
        return(NULL);
    }
    if (command->type != cJSON_String) {
        free(json);
        return(NULL);
    }
    
    Message *msg = (Message *)malloc(sizeof(Message));
    msg->command = command->valuestring;
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

cJSON *createRegisterObject(char *reg_name, unsigned long long int value) {
    char *reg_str = (char *)malloc(64);
    memset(reg_str, 0x00, 64);    
    sprintf(reg_str, "0x%X", value);
    
    cJSON *r_obj = cJSON_CreateObject();  
    cJSON_AddStringToObject(r_obj, "register", reg_name);
    cJSON_AddStringToObject(r_obj, "value", reg_str);
    
    free(reg_str);
    return r_obj;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int handle_command_kill(Connection *conn, Monitor *monitor) {
    if (monitor != NULL) {
        if (monitor->terminate()) {
            conn->transmit("{\"command\": \"kill\", \"data\": \"success\"}", 38);
        } else {
            conn->transmit("{\"command\": \"kill\", \"data\": \"failed\"}", 37);
        }
    }
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int handle_command_ping(Connection *conn) {
    conn->transmit("{\"command\": \"ping\", \"data\": \"pong\"}", 35);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int handle_command_status(Connection *conn, Monitor *monitor, Message *msg) {
    if (monitor == NULL || monitor->isRunning() == 0) {
        conn->transmit("{\"command\": \"status\", \"data\": \"OK\"}", 35);
        return(0);
    }
    Status *m_status = monitor->status();
    
    if (m_status->getPid() < 1 || 
        m_status->getState() <= P_RUNNING) {
        conn->transmit("{\"command\": \"status\", \"data\": \"OK\"}", 35);
        return(0);
    }
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "command", "status");
    cJSON_AddStringToObject(root, "data", "terminated");
    cJSON_AddNumberToObject(root, "process_id", m_status->getPid());
    cJSON_AddNumberToObject(root, "term_condition", m_status->getState());
    cJSON_AddNumberToObject(root, "exit_code", m_status->getExitCode());
    cJSON_AddNumberToObject(root, "signal_num", m_status->getSignalNum());
    char *signame = (char *)malloc(256);
    m_status->getSignalStr(signame, 256);
    cJSON_AddStringToObject(root, "signal_str", signame);
    
    // Create registers

    struct user_regs_struct m_regs = monitor->getRegisters();
    cJSON *j_regs = cJSON_CreateArray();
    
    /*
    cJSON *j_rax = createRegisterObject("rax", m_regs.rax);
    cJSON_AddItemToArray(j_regs, j_rax);
    
    cJSON_AddItemToObject(root, "registers", j_regs);
    */
    char *t_json = cJSON_Print(root);
    if (t_json != NULL) conn->transmit(t_json, strlen(t_json));
    
    cJSON_Delete(root);
    free(signame);
    monitor->terminate();
    monitor->stop();
    return(1);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int handle_command_start(Connection *conn, Monitor *monitor, Message *msg) {
    pthread_t tid;
    char *cmd_line = (char *)get_data(msg->j_data);
    
    if (cmd_line == NULL) {
        syslog(LOG_ERR, "[%s]: program not specified in data", 
                conn->address());
        conn->transmit("{\"command\": \"start\", \"data\": \"failed\"}", 38);
        return(0);
    }
    
    if (monitor->setTarget(cmd_line)) {
        syslog(LOG_ERR, "[%s]: monitor failed to process command line", 
                conn->address());
        conn->transmit("{\"command\": \"start\", \"data\": \"failed\"}", 38);
        return(0);
    }

    if (pthread_create(&tid, NULL, &start_monitor, monitor) != 0) {
        syslog(LOG_ERR, "[%s]: monitor failed to start process", 
                conn->address());
        conn->transmit("{\"command\": \"start\", \"data\": \"failed\"}", 38);
        return(0);
    }
    conn->transmit("{\"command\": \"start\", \"data\": \"success\"}", 39);
    return(1);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

unsigned int process_command(Connection *conn, Monitor *monitor, char *data) {
    Message *message = NULL;
    message = get_command(data);
    if (message == NULL) return(0);

    syslog(LOG_INFO, "command received from %s: %s", conn->address(),
                message->command);
    
    //
    if (!strcmp(message->command, "ping")) {
        handle_command_ping(conn);
    } else if (!strcmp(message->command, "kill")) {
        handle_command_kill(conn, monitor);
    } else if (!strcmp(message->command, "start")) {
        handle_command_start(conn, monitor, message);
    } else if (!strcmp(message->command, "status")) {
        handle_command_status(conn, monitor, message);
    }
    
    if (message->j_data != NULL) cJSON_Delete(message->j_data);
    free(message);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

static void *handle_connection(void *c) {
    unsigned int r_len = 1;
    Monitor *monitor = new Monitor();
    Connection *conn = (Connection *)c;
    char *data = (char *)malloc(RECV_BUFFER_SIZE);
    
    syslog(LOG_INFO, "accepted connection from engine: %s", conn->address());

    while(r_len != 0) {
        r_len = conn->receive(data);
        if (r_len < 1) continue;
        process_command(conn, monitor, data);
    }

    syslog(LOG_INFO, "disconnected from engine: %s", conn->address());
    memset(data, 0x00, RECV_BUFFER_SIZE);
    free(data);
    if (monitor != NULL) {
        monitor->terminate();
        monitor->stop();
        delete monitor;
    }
    conn->terminate();
    delete conn;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void listener(unsigned int port, unsigned int max_conn) {
    int sd, n_sd;
    socklen_t c_len;
    struct sockaddr_in s_addr, c_addr;
    unsigned int running = 1;
    pthread_t tid[max_conn];

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) throw "failed to create socket for listener";

    bzero((char *) &s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);
    if (bind(sd, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) 
        throw "failed to bind listener to address";

    if (listen(sd, max_conn) != 0) throw "failed to set up listener";
    c_len = sizeof(c_addr);

    while (running) {
        n_sd = accept(sd, (struct sockaddr *) &c_addr, &c_len);
        if (n_sd < 0) continue;
        Connection *conn = new Connection(n_sd, &c_addr);
        if (pthread_create(&(tid[0]), NULL, &handle_connection, conn) != 0)
            throw "failed to accept connection";
    }
}

