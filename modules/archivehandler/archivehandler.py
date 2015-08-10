#!/usr/bin/env python

import os
import re
import sys
import json
import time
import shutil
import syslog
import threading
from threading import Thread
from pydispatch import dispatcher
from classes import Event as ev

# =============================================================================
#
# =============================================================================

class archivehandler(threading.Thread):

    def descriptor(self):
        return(dict([
            ('type', 'module'),
            ('version', '0.1'),
            ('author', 'Zsolt Imre'),
            ('author-email', 'imrexzsolt@gmail.com')
        ]))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        threading.Thread.__init__(self)
        self.root              = root
        self.config            = config
        self.running           = True
        self.jobs_dir          = self.root + "/jobs" 
        self.archived_jobs_dir = self.root + "/archived_jobs" 
        self.processing        = False

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def is_running(self):
        return self.running

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def stop(self):
        self.running = False

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def load_job_data(self, f_path):
        try:
            return json.load(open(f_path, 'r'))
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "archive handler failed to load job data (%s)" %
                          str(ex))
            return None

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def get_archived_jobs(self):
        archived = []
        for dirpath, dirnames, filenames in os.walk(self.archived_jobs_dir):
            for dirname in dirnames:
                archived.append(dirname)
        return archived

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __handle_archives_list(self, sender):
        if self.processing: return
        self.processing = True

        report = []
        archived = self.get_archived_jobs()
        c_path = self.archived_jobs_dir

        for job in archived:
            job_details = {"id": job, "job": "", "session": ""}

            for files in os.listdir(c_path + "/" + job + "/"):
                e_file = files.split(".")
                if len(e_file) < 2 or e_file[0] != job: continue
                if e_file[1] == "job" or e_file[1] == "jlock":
                    job_details["job"] = self.load_job_data(c_path + "/" + job + "/" + files)
                if e_file[1] == "session":
                    job_details["session"] = self.load_job_data(c_path + "/" + job + "/" + files)
                if e_file[1] == "crashes":
                    # Deal with this later...
                    pass

            if job_details["id"] == "" or \
               job_details["job"] == "" or \
               job_details["job"] == None: continue
            report.append(job_details)

        dispatcher.send(signal=ev.Event.EVENT__RSP_ARCHIVES_LIST,
                        sender="ARCHIVEHANDLER",
                        data=json.dumps(report))
        self.processing = False

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "archive handler started")

        dispatcher.connect(self.__handle_archives_list,
                           signal=ev.Event.EVENT__REQ_ARCHIVES_LIST,
                           sender=dispatcher.Any)

        while self.running:
            pass

        syslog.syslog(syslog.LOG_INFO, "archive handler stopped")

