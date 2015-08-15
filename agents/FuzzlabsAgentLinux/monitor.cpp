#include "monitor.h"

// ----------------------------------------------------------------------------
// Get the command name from the first argument. The result will be used as
// the second argument for exec...()
//
// Returns:
//   - Pointer to the original string if no "/" character found in string
//   - NULL if the original string was NULL or was shorter than 1 byte
//
//   Otherwise, returns the command name extracted from the original string.
//
// ----------------------------------------------------------------------------

char *Monitor::getCommandName(char *str) {
    if (str == NULL || strlen(str) < 1) return(NULL);
    if (strchr(str, 0x2F) == NULL) return(str);

    char *temp = NULL;

    char *t = strtok(str, "/");
    if (t != NULL) temp = t;
    while(t) {
        t = strtok(NULL, "/");
        if (t != NULL) temp = t;
    }
    return(temp);
}

// ----------------------------------------------------------------------------
// Parse a command line where arguments are separated by space. After parsing
// an array of string pointers is returned where each item in the array points
// to an argument string. The last item in the array is always NULL.
//
// Returns:
//
//  - NULL if the original string is NULL or the length of the string is less
//    than 1.
//
//  Otherwise, it returns an array of string pointers.
//
// ----------------------------------------------------------------------------

char **Monitor::parseArgs(char *str) {
    if (str == NULL || strlen(str) < 1) return(NULL);

    char **res = NULL;
    int n_spaces = 0;
    int i = 0;

    char *p = strtok(str, " ");

    while(p) {
        res = (char **)realloc(res, sizeof(char*) * ++n_spaces);
        if (res == NULL) exit(-1);
        res[n_spaces-1] = p;
        p = strtok(NULL, " ");
    }

    res = (char **)realloc(res, sizeof(char*) * (n_spaces+1));
    res[n_spaces] = 0;

    return(res);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

Monitor::Monitor(char *cmd_line) {
    // c_status = P_NOTINIT;
    p_args = Monitor::parseArgs((char *)cmd_line);
    p_full = NULL;

    if (p_args != NULL && p_args[0] != NULL) {
        p_full = (char *)malloc(strlen((char *)p_args[0]) + 1);
        memset(p_full, 0x00, strlen((char *)p_args[0]) + 1);
        strcpy(p_full, p_args[0]);
        p_args[0] = getCommandName(p_args[0]);
    }
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

Status *Monitor::status() {
    return p_status;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int Monitor::start() {
    running = 1;
    p_status = new Status();
    int status = 0;
    pid_t child;

    child = fork();
    if(child == 0) {
        if (p_full != NULL && p_args != NULL &&
            p_args[0] != NULL) {
            p_status->setPid(child);
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            p_status->setState(P_RUNNING);
            execv(p_full, p_args);
            p_status->setPid(-1);
            p_status->setState(P_ERROR);
        } else {
            p_status->setPid(-1);
            p_status->setState(P_ERROR);
        }
    } else {
        wait(NULL);
        ptrace(PTRACE_CONT, child, NULL, NULL);

        while(running) {
            wait(&status);
            if (WIFEXITED(status)) {
                p_status->setState(P_TERM);
                p_status->setExitCode(WEXITSTATUS(status));
                break;
            }
            if (WIFSIGNALED(status)) {
                p_status->setState(P_SEGFAULT);
                p_status->setSignal(WTERMSIG(status));
                break;
            }
            if (WIFSTOPPED(status)) {
                p_status->setState(P_TERM);
                p_status->setSignal(WSTOPSIG(status));
                break;
            }
        }
    }
}
