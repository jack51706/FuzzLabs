/* 
 * File:   main.cpp
 * Author: keyman
 *
 * Created on 14 August 2015, 11:35
 */

#include <cstdlib>
#include <cstdio>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "main.h"
#include "listener.h"

using namespace std;

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void daemonize() {
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        printf("[e] failed to set up daemon, exiting.");
        exit(1);
    }
    if (pid > 0) exit(0);

    if (setsid() < 0) {
        printf("[e] failed to set up daemon, exiting.");
        exit(1);
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        printf("[e] failed to set up daemon, exiting.");
        exit(1);
    }
    if (pid > 0) exit(0);

    umask(0);
    chdir("/");

    int fd;
    for (fd = sysconf(_SC_OPEN_MAX); fd>0; fd--) {
        close (fd);
    }
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void print_version() {
    printf("%s version %s - %s\n", AGENT_STRING,
                                   AGENT_VERSION,
                                   AGENT_PLATFORM);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void print_help() {
    print_version();
    printf("Available options: \n"
           "\t%s\t- %s\n"
           "\t%s\t- %s\n"
           "\t%s\t- %s\n"
           "\t%s\t- %s\n",
           "-d", "Run agent as a daemon in the background",
           "-p", "Port the agent should listen on (default: 27000)",
           "-v", "Display engine version and exit",
           "-h", "Print this help message");
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int main(int argc, char** argv) {
    int c = 0;
    int daemon = 0;
    int port = AGENT_DEFAULT_PORT;

    while ((c = getopt(argc, argv, "hvdp:")) != -1) {
        switch (c) {
            case 'h':
                print_help();
                break;
            case 'v':
                print_version();
                exit(0);
            case 'p':
                port = atoi(optarg);
                if (port > 65535 || port < 1024) {
                    port = AGENT_DEFAULT_PORT;
                }
                break;
            case 'd':
                daemon = 1;
                break;
            default:
                break;
        }
    }

   if (daemon == 1) daemonize();

    openlog("fuzzlabs-agent", LOG_PID, LOG_DAEMON);
    syslog(LOG_NOTICE, "Fuzzlabs Agent is running.");

    listener(port);
    
    return 0;
}

