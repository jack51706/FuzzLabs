#!/usr/bin/env python

import os
import sys
import json
import time
import Queue
import shutil
import syslog
import threading
import multiprocessing
from threading import Thread
from sulley import *

# =============================================================================
#
# =============================================================================

class jobworker():

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __init__(self, parent, id, job_id, c_queue, p_queue, root, config):
        self.root              = root
        self.parent            = parent
        self.id                = id
        self.c_queue           = c_queue
        self.p_queue           = p_queue
        self.config            = config
        self.running           = True
        self.core              = None

        self.job_id            = job_id
        self.job_path          = None
        self.job_data          = None
        self.job_status        = {}

        self.jobs_dir          = self.root + "/jobs" 
        self.archived_jobs_dir = self.root + "/archived_jobs" 

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_shutdown(self, cmd):
        syslog.syslog(syslog.LOG_INFO, "w[%s] shutdown request received" % self.id)
        self.core.terminate()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_ping(self, cmd):
        self.p_queue.put({
                          "to": self.parent,
                          "from": self.id,
                          "command": "pong"
                         })

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_status(self, cmd):
        if not self.core: return {}

        self.job_status = self.core.get_status()
        self.job_status.update({"path": self.job_path, 
                                "data": self.job_data
                               })

        self.p_queue.put({
                          "to": self.parent,
                          "from": self.id,
                          "command": "job_status",
                          "data": self.job_status
                         })
        self.job_status = {}

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_pause(self, cmd):
        if cmd["data"] == self.job_id:
            self.core.set_pause()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_resume(self, cmd):
        if cmd["data"] == self.job_id:
            self.core.set_resume()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def _q_handle_job_delete(self, cmd):
        if self.running == False: return
        if cmd["data"] == self.job_id:
            self.core.terminate()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    """
     Handle the received message. The handler function is dynamically looked
     up and called, this way handling of new commands can be easily implemented
     by just adding a handler function.
    """

    def handle(self, cmd):
        if not self.validate_queue_message(cmd): return
        try:
            if not self.core: return
            getattr(self, '_q_handle_' + cmd["command"], None)(cmd)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s]: failed to execute queue handler '%s' (%s)" % 
                              (self.id, cmd["command"], str(ex)))
            return

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def validate_queue_message(self, message):
        if not message.has_key("from"): return False
        if not message.has_key("to"): return False
        if not message.has_key("command"): return False
        if message["to"] != self.id: return False
        if message["from"] != self.parent: return False
        return True

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def report_finished(self):
        self.p_queue.put({
                          "to": self.parent,
                          "from": self.id,
                          "command": "job_finished",
                          "data": self.job_id
                         })

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def stop_worker(self):
        try:
            self.report_finished()
        except Exception, ex:
            pass

        try:
            # Remove everything from the queue
            while not self.c_queue.empty(): self.c_queue.get()
        except Exception, ex:
            pass

        """
        try:
            del(self.c_queue)
        except Exception, ex:
            pass
        try:
            del(self.p_queue)
        except Exception, ex:
            pass
        try:
            del(self.core)
        except Exception, ex:
            pass
        """

        try:
            self.p_queue.close()
            self.p_queue.join_thread()
        except Exception, ex:
            pass

        syslog.syslog(syslog.LOG_INFO, "w[%s] terminated" % self.id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    """
     Load the descriptor.
    """

    def __import_request_file(self):
        r_folder = self.root + "/requests"
        if r_folder not in sys.path: sys.path.insert(0, r_folder)
        __import__(self.job_data['request']['request_file'])

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def load_job_data(self, f_path):
        try:
            job_lock = self.jobs_dir + "/" + \
                       self.job_id + "/" + \
                       self.job_id + ".jlock"
            if os.path.isfile(job_lock):
                syslog.syslog(syslog.LOG_ERR, "w[%s] job %s is locked, exiting" % 
                                  (self.id, self.job_id))
                return None

            shutil.move(f_path, job_lock)
            data = json.load(open(job_lock, 'r'))
            return data
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to load job data (%s)" % 
                              (self.id, str(ex)))
            return None

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def setup_core(self):
        try:
            self.__import_request_file()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to load descriptor for job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return False

        try:
            self.core = sessions.session(self.config, 
                                 self.job_path,
                                 self.job_id, 
                                 self.job_data["session"], 
                                 self.job_data["target"]["transport"], 
                                 self.job_data["target"]["conditions"])
            self.core.add_target(
                sessions.target(self.job_data["target"]["endpoint"]))
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to initialize job %s (%s)" %
                              (self.id, self.job_id, str(ex)))
            return False

        try:
            for path in self.job_data["request"]["graph"]:
                if path.get('next') == None:
                    self.core.connect(s_get(path["current"]))
                else:
                    self.core.connect(s_get(path["current"]), s_get(path["next"]))
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to process graph for job %s (%s)" %
                              (self.id, self.job_id, str(ex)))
            return False

        return True

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def archive_job(self):
        if os.path.isdir(self.archived_jobs_dir + "/" + self.job_id):
            shutil.rmtree(self.archived_jobs_dir + "/" + self.job_id)
        shutil.move(self.jobs_dir + "/" + self.job_id, self.archived_jobs_dir + "/")

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def start_fuzzing(self):
        try:
            if not self.core: return
            self.core.fuzz()
            self.running = False
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to execute job %s (%s)" %
                              (self.id, self.job_id, str(ex)))
            return

        try:
            self.job_status = self.core.get_status()
        except Exception, ex:
            pass

        syslog.syslog(syslog.LOG_INFO, "w[%s]: job %s finished" % (self.id, self.job_id))
        try:
            self.archive_job()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s] failed to archive job %s (%s)" %
                              (self.id, self.job_id, str(ex)))
            return

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def listener(self):
        while self.running:
            try: self.handle(self.c_queue.get_nowait())
            except Exception, ex: pass

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "worker started: %s, pid: %d" % 
                          (self.id, os.getpid()))
        l = threading.Thread(target=self.listener)
        l.start()

        self.p_queue.put({
                          "to": self.parent,
                          "from": self.id,
                          "command": "pid",
                          "data": os.getpid()
                         })

        syslog.syslog(syslog.LOG_INFO, "worker %s executing job %s" % (self.id, self.job_id))
        job_data = self.load_job_data(self.jobs_dir + "/" +\
                                       self.job_id + "/" + self.job_id + ".job")

        if job_data:
            self.job_path = self.jobs_dir + "/" + self.job_id
            self.job_data = job_data
            if self.setup_core(): self.start_fuzzing()

        self.stop_worker()

