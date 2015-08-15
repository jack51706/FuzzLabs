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
    pid = 0;
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

int Monitor::terminate() {
    if (pid < 1) return 1;
    int rc = kill(pid, SIGKILL);
    int error = errno;
    if (rc == -1) {
        if (error == EINVAL || error == EPERM) return 0;
        if (error == ESRCH) return 1;           // Even if it is considered as
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
    pid_t child = 0;

    // TODO: There is an issue with p_full and p_args
    syslog(LOG_INFO, "starting process: %s (%s)", p_full, p_args[0]);
    
    child = fork();
    if(child == 0) {
        if (p_full != NULL && p_args != NULL &&
            p_args[0] != NULL) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            p_status->setState(P_RUNNING);
            execv(p_full, p_args);
            p_status->setPid(-1);
            p_status->setState(P_ERROR);
            syslog(LOG_ERR, "failed to start process: %d", errno);
        } else {
            p_status->setPid(-1);
            p_status->setState(P_ERROR);
        }
    } else {
        wait(NULL);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        syslog(LOG_INFO, "process started with pid: %d", child);
        p_status->setPid(child);
        while(running) {
            wait(&status);
            if (WIFEXITED(status)) {
                p_status->setState(P_TERM);
                p_status->setExitCode(WEXITSTATUS(status));
                syslog(LOG_INFO, "process exited with exit code: %d",
                        WEXITSTATUS(status));
                break;
            }
            if (WIFSIGNALED(status)) {
                p_status->setState(P_SIGTERM);
                p_status->setSignal(WTERMSIG(status));
                syslog(LOG_INFO, "process terminated by signal: %d",
                        WTERMSIG(status));
                break;
            }
            if (WIFSTOPPED(status)) {
                p_status->setState(P_TERM);
                p_status->setSignal(WSTOPSIG(status));
                syslog(LOG_INFO, "process stopped by signal: %d",
                        WSTOPSIG(status));
                break;
            }
        }
    }
}
