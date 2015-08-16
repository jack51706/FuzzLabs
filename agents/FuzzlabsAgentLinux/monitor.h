/* 
 * File:   monitor.h
 * Author: keyman
 *
 * Created on 14 August 2015, 20:25
 */

#ifndef MONITOR_H
#define	MONITOR_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <syslog.h>
#include <sys/user.h>
#include "status.h"

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

class Monitor {  
private:
    int running;
    int pid;
    Status *p_status;
    char **p_args;
    char *p_full;
    struct user_regs_struct regs;
    
    char *getCommandName(char *str);
    char **parseArgs(char *str);
public:
    Monitor();
    int setTarget(char *cmd_line);
    int start();
    void stop();
    int isRunning();
    Status *status();
    int terminate();
    struct user_regs_struct getRegisters();
};

#endif	/* MONITOR_H */
