# =============================================================================
# Basic TEST
# This file is part of the FuzzLabs Fuzzing Framework
# =============================================================================

import syslog
from sulley import *

def file_presend(sock):
    syslog.syslog(syslog.LOG_INFO, "PRE_SEND EXECUTED")

def file_postsend(sock):
    syslog.syslog(syslog.LOG_INFO, "POST_SEND EXECUTED")

def file_callback(session, node, edge, sock):
    syslog.syslog(syslog.LOG_INFO, "CALLBACK EXECUTED")

s_initialize("TEST")
s_binary("0x00")
s_byte(0x00, full_range=True)


