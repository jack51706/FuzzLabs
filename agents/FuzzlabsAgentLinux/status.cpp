#include "status.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

Status::Status() {
    
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void Status::setState(p_status s) {
    c_status = s;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int Status::getState() {
    return(c_status);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void Status::setPid(int p_pid) {
    pid = p_pid;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

int Status::getPid() {
    return(pid);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void Status::sigToString() {
    switch(signal) {
        case SIGABRT:
            break;
        case SIGALRM:
            break;
        case SIGFPE:
            break;
        case SIGHUP:
            break;
        case SIGILL:
            break;
        case SIGINT:
            break;
        case SIGKILL:
            break;
        case SIGPIPE:
            break;
        case SIGQUIT:
            break;
        case SIGSEGV:
            break;
        case SIGTERM:
            break;
        case SIGUSR1:
            break;
        case SIGUSR2:
            break;
        case SIGCHLD:
            break;
        case SIGCONT:
            break;
        case SIGSTOP:
            break;
        case SIGTSTP:
            break;
        case SIGTTIN:
            break;
        case SIGTTOU:
            break;
        case SIGBUS:
            break;
        case SIGPOLL:
            break;
        case SIGPROF:
            break;
        case SIGSYS:
            break;
        case SIGTRAP:
            break;
        case SIGURG:
            break;
        case SIGVTALRM:
            break;
        case SIGXCPU:
            break;
        case SIGXFSZ:
            break;
        default:
            break;
    }
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void Status::setSignal(int p_sig) {
    signal = p_sig;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void Status::setExitCode(int p_e_code) {
    e_code = p_e_code;
}
