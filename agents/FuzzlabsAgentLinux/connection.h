/* 
 * File:   connection.h
 * Author: keyman
 *
 * Created on 14 August 2015, 14:18
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <syslog.h>

#ifndef CONNECTION_H
#define	CONNECTION_H

#define RECV_BUFFER_SIZE    4096

class Connection {
private:
    int sock;
    struct sockaddr_in *sin;
    char *client_addr;
public:
    Connection(int c_fd, struct sockaddr_in *c_sin);
    int socket();
    void terminate();
    char *address();
    int transmit(char *data, unsigned int len);
    int receive(char *data);
};

#endif	/* CONNECTION_H */

