/* 
 * File:   status.h
 * Author: keyman
 *
 * Created on 14 August 2015, 21:38
 */

#ifndef STATUS_H
#define	STATUS_H

#include <signal.h>
#include <string.h>
#include <stdlib.h>

enum p_status {
    P_ERROR = -1,
    P_NOTINIT,
    P_RUNNING,
    P_TERM,
    P_SIGTERM
};

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

class Status {
private:
    int pid;
    int signal;
    int e_code;
    p_status c_status;
public:
    Status();
    void reset();
    void setState(p_status s);
    void setPid(int p_pid);
    void setSignal(int p_sig);
    void setExitCode(int p_e_code);
    int getExitCode();
    int getState();
    int getPid();
    int getSignalNum();
    void getSignalStr(char *buf, unsigned int len);
};

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* STATUS_H */

