#include "main.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int main(int argc, char **argv) {

    int c = 0;
    int daemon = 0;
    int running = 1;
    int port = AGENT_DEFAULT_PORT;
    pthread_t tid[1];

    while ((c = getopt (argc, argv, "hvdp:")) != -1)
    switch (c) {
        case 'h':
            print_help();
            break;
        case 'v':
            print_version();
            exit(0);
        case 'p':
            port = atoi(optarg);
            if (port > 65535 || port < 80) {
                port = AGENT_DEFAULT_PORT;
            }
            break;
        case 'd':
            daemon = 1;
            break;
        default:
            break;
        }

    if (daemon == 1) daemonize();

    openlog("fuzzlabs-agent", LOG_PID, LOG_DAEMON);
    syslog(LOG_NOTICE, "Fuzzlabs Agent is running.");

    Listener *l;
    l = malloc(sizeof(Listener));
    l->port = port;

    if (pthread_create(&(tid[0]), NULL, &listener, (void *)l) != 0) {
        syslog (LOG_ERR, "failed to create listener thread");
    }

    while (running == 1) {
        sleep(5);
    }

    return(0);
}

