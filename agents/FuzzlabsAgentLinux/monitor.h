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
    char *getCommandName(char *str);
    char **parseArgs(char *str);
public:
    Monitor(char *cmd_line);
    int start();
    Status *status();
    int terminate();
};

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* MONITOR_H */
