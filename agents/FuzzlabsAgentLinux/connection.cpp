#include "connection.h"
#include "monitor.h"

Connection::Connection(int c_fd, struct sockaddr_in *c_sin) {
    sock = c_fd;
    sin = c_sin;
    client_addr = (char *)inet_ntoa(sin->sin_addr);
}

int Connection::socket() {
    return sock;
}

char *Connection::address() {
    return client_addr;
}

int Connection::transmit(char *data, unsigned int len) {
    return send(sock, data, len, 0);
}

int Connection::receive(char *data) {
    size_t length = 0;
    unsigned int round = 0;

    memset(data, 0x00, RECV_BUFFER_SIZE);    
    return(recv(sock, data, RECV_BUFFER_SIZE - 1, MSG_DONTWAIT));
}
