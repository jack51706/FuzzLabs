#include "main.h"
#include "common.h"

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

