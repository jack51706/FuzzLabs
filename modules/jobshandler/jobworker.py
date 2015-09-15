"""
Job worker implementation.
"""

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
        """
        Initialize the worker

        @type  parent:   String
        @param parent:   The ID of the parent
        @type  id:       String
        @param id:       The ID of the worker
        @type  c_queue:  multiprocessing.Queue
        @param c_queue:  The queue the client receives messages on
        @type  p_queue:  multiprocessing.Queue
        @param p_queue:  The queue used to send messages to the parent
        @type  root:     String
        @param root:     The root directory of FuzzLabs
        @type  config:   Dictionary
        @param config:   A dictionary containing the FuzzLabs configuration
        """

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

        self.jobs_dir          = self.root + "/jobs/queue" 
        self.archived_jobs_dir = self.root + "/jobs/archived" 

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_shutdown(self, cmd):
        """
        Handle worker shutdown request sent by the parent. The "cmd" argument
        is not used.
        """

        syslog.syslog(syslog.LOG_INFO,
                      "w[%s] shutdown request received" % self.id)
        self.core.terminate()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_ping(self, cmd):
        """
        Reply to the ping message sent by the parent. The "cmd" argument is
        not used. 
        """

        self.p_queue.put({
                          "to": self.parent,
                          "from": self.id,
                          "command": "pong"
                         })

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_status(self, cmd):
        """
        Reply to the job status request sent by the parent. The "cmd" argument
        is not used.
        """

        if not self.core: return {}

        self.job_status = self.core.get_status()
        if self.job_status == None:
            self.job_status = {}
            return {}

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
        """
        Pause the job as requested by the parent.

        @type  cmd:      Dictionary
        @param cmd:      The job pause message as a dictionary
        """

        if cmd["data"] == self.job_id:
            self.core.set_pause()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_resume(self, cmd):
        """
        Resume the job as requested by the parent.

        @type  cmd:      Dictionary
        @param cmd:      The job resume message as a dictionary
        """

        if cmd["data"] == self.job_id:
            self.core.set_resume()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def _q_handle_job_delete(self, cmd):
        """
        Delete the job as requested by the parent.

        @type  cmd:      Dictionary
        @param cmd:      The job delete message as a dictionary
        """

        if not self.running: return
        if cmd["data"] == self.job_id:
            self.core.terminate()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def handle(self, cmd):
        """
        Handle the received message. The handler function is dynamically
        looked up and called, this way handling of new commands can be easily
        implemented by just adding a handler function.

        @type  cmd:      Dictionary
        @param cmd:      The message as a dictionary.
        """

        if not self.validate_queue_message(cmd): return
        try:
            if not self.core: return
            getattr(self, '_q_handle_' + cmd["command"], None)(cmd)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s]: failed to execute queue handler '%s' (%s)" % 
                          (self.id, cmd["command"], str(ex)))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def validate_queue_message(self, message):
        """
        Perform basic validation of a message received via the queue.

        @type  message:  Dictionary
        @param message:  The message as a dictionary
        """

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
        """
        Report to the parent that the job has been finished.
        """

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
        """
        Shut down the worker process.
        """

        try:
            self.report_finished()
        except Exception, ex:
            pass

        try:
            # Remove everything from the queue
            while not self.c_queue.empty(): self.c_queue.get()
        except Exception, ex:
            pass

        try:
            self.p_queue.close()
            self.p_queue.join_thread()
        except Exception, ex:
            pass

        syslog.syslog(syslog.LOG_INFO, "w[%s] terminated" % self.id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __import_request_file(self):
        """
        Load the protocol/file descriptor.
        """

        r_folder = self.root + "/requests"
        if r_folder not in sys.path: sys.path.insert(0, r_folder)
        descriptor = __import__(self.job_data['request']['request_file'])
        global descriptor


    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def load_job_data(self, f_path):
        """
        Load the job descriptor.

        @type  f_path:   String
        @param f_path:   Full path of the job descriptor

        @rtype:          Mixed
        @return:         Job description as a dictionary or None if failed to
                         load
        """

        try:
            job_lock = self.jobs_dir + "/" + \
                       self.job_id + "/" + \
                       self.job_id + ".jlock"
            if os.path.isfile(job_lock):
                syslog.syslog(syslog.LOG_ERR,
                              "w[%s] job %s is locked, exiting" % 
                              (self.id, self.job_id))
                return None

            shutil.move(f_path, job_lock)
            data = json.load(open(job_lock, 'r'))
            return data
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to load job data (%s)" % 
                          (self.id, str(ex)))
            return None

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def load_callbacks(self, f_name = None):
        if not f_name: return None
        try:
            f_name = getattr(descriptor, f_name)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to load pre_send function for job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            f_name = None
        return f_name

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def setup_core(self):
        """
        Set up the fuzzing core.

        @rtype:          Boolean
        @return:         True if success, otherwise False
        """

        try:
            self.__import_request_file()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to load descriptor for job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return False

        try:
            self.core = sessions.session(self.config, 
                                 self.root,
                                 self.job_path,
                                 self.job_id,
                                 self.job_data)
            self.core.add_target(
                sessions.target(self.job_data["target"]["endpoint"]))

            if ("agent" in self.job_data["target"]):
                rc = self.core.add_agent(self.job_data["target"]["agent"])
                if (rc == False):
                    syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to set up agent for job %s" %
                          (self.id, self.job_id))
                    return False
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to initialize job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return False

        pre_send = self.load_callbacks(self.job_data["request"].get('pre_send'))
        post_send = self.load_callbacks(self.job_data["request"].get('post_send'))

        self.core.set_pre_send(pre_send)
        self.core.set_post_send(post_send)

        try:
            for path in self.job_data["request"]["graph"]:
                n_c = path.get('current')
                if n_c != None: n_c = s_get(n_c)
                n_n = path.get('next')
                if n_n != None: n_n = s_get(n_n)
                callback = self.load_callbacks(path.get('callback'))
                self.core.connect(n_c, n_n, callback)

        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to process graph for job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return False

        return True

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def archive_job(self):
        """
        Archive the current job.
        """

        if os.path.isdir(self.archived_jobs_dir + "/" + self.job_id):
            shutil.rmtree(self.archived_jobs_dir + "/" + self.job_id)
        shutil.move(self.jobs_dir + "/" + self.job_id,
                    self.archived_jobs_dir + "/")

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def start_fuzzing(self):
        """
        Start the fuzzing.
        """

        try:
            if not self.core: return
            self.core.fuzz()
            self.running = False
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to execute job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return

        try:
            self.job_status = self.core.get_status()
        except Exception, ex:
            pass

        syslog.syslog(syslog.LOG_INFO,
                      "w[%s]: job %s finished" % (self.id, self.job_id))
        try:
            self.archive_job()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s] failed to archive job %s (%s)" %
                          (self.id, self.job_id, str(ex)))
            return

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def listener(self):
        """
        Listen for messages on the queue.
        """

        while self.running:
            try: self.handle(self.c_queue.get_nowait())
            except Exception, ex: pass

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        """
        Main function of the worker.
        """

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

        syslog.syslog(syslog.LOG_INFO,
                      "worker %s executing job %s" % (self.id, self.job_id))
        job_data = self.load_job_data(self.jobs_dir + "/" +\
                                      self.job_id + "/" +\
                                      self.job_id + ".job")

        if job_data:
            self.job_path = self.jobs_dir + "/" + self.job_id
            self.job_data = job_data
            if self.setup_core(): self.start_fuzzing()

        self.stop_worker()

