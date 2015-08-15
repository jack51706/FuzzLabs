/* 
 * File:   listener.h
 * Author: keyman
 *
 * Created on 14 August 2015, 13:09
 */

#ifndef LISTENER_H
#define	LISTENER_H

#include <stdlib.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>

#define AGENT_MAX_CONN          10

// The message structure should be as simple as:
// {"command": "<command>", "data": "<data>"}

typedef struct {
    char *command;
    char *data;
} Message;

#ifdef	__cplusplus
extern "C" {
#endif

void listener(int port);
    
#ifdef	__cplusplus
}
#endif

#endif	/* LISTENER_H */

