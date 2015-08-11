"""
Module to handle jobs.
"""

import os
import re
import sys
import json
import copy
import time
import Queue
import shutil
import random
import syslog
import signal
import inspect
import hashlib
import threading
import multiprocessing
from threading import Thread
from multiprocessing import Process
from pydispatch import dispatcher
from classes import Event as ev
from jobworker import jobworker

__author__     = "Zsolt Imre"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

# =============================================================================
#
# =============================================================================

class jobshandler(threading.Thread):

    def descriptor(self):
        return(dict([
            ('type', 'module'),
            ('version', __version__),
            ('name', 'jobshandler')
        ]))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        """
        Initialize the module.

        @type  root:     String
        @param root:     Full path to the FuzzLabs root directory
        @type  config:   Dictionary
        @param config:   The complete configuration as a dictionary
        """

        threading.Thread.__init__(self)
        self.root              = root
        self.id                = self.generate_id()
        self.config            = config
        self.running           = True
        self.jobs_dir          = self.root + "/jobs/queue" 
        self.archived_jobs_dir = self.root + "/jobs/archived" 
        self.job_status        = []
        self.jobs_registered   = []
        self.workers           = []

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def generate_id(self):
        """
        Generate random IDs to be used to identify the job handler and the 
        worker processes.

        @rtype:          String
        @return:         Generated random ID
        """

        h_in = str(random.getrandbits(64))
        h_in = str(time.time())
        return hashlib.sha1(h_in).hexdigest()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def is_status_for_worker(self, worker):
        """
        Check whether a worker has status registered or not.

        @type  worker:   String
        @param worker:   The ID of the worker process

        @rtype:          Boolean
        @return:         True if the worker has status registered, otherwise
                         False.
        """

        if len(self.job_status) == 0: return False
        for status in self.job_status:
            if worker == status["worker"]: return True
        return False

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def update_worker_status(self, worker, w_status):
        """
        Update the worker status.

        @type  worker:   String
        @param worker:   The ID of the worker process
        @type  worker:   Dictionary
        @param worker:   Dictionary representing the status of the worker.
        """

        for status in self.job_status:
            if worker == status["worker"]: status["data"] = w_status

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def delete_worker(self, worker_id):
        """
        Delete a worker. The worker is stopped then all references to it is
        deleted.

        @type  worker_id:   String
        @param worker_id:   The ID of the worker process
        """

        w_remove = None
        s_remove = None

        for worker in self.workers:
            if worker["id"] == worker_id: 
                w_remove = worker

        if not w_remove: return

        self.workers.remove(w_remove)
        w_remove["c_queue"].put({
                    "from": self.id,
                    "to": worker["id"],
                    "command": "shutdown"
            })

        w_remove["c_queue"].close()
        w_remove["c_queue"].join_thread()

        for status in self.job_status:
            if worker_id == status["worker"]: s_remove = status
        if s_remove: self.job_status.remove(s_remove)

        if w_remove:
            try:
                w_remove["process"].join()
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR, "failed to stop worker %s (%s)" %
                              (worker, str(ex)))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_job_status(self, cmd):
        """
        Handle the job status information received on the Queue associated with
        the worker the status info originates from. 

        @type  cmd:      Dictionary
        @param cmd:      A dictionary containing the job status information.
        """

        if self.is_status_for_worker(cmd["from"]):
            self.update_worker_status(cmd["from"], cmd["data"])
        else:
            self.job_status.append({
                    "worker": cmd["from"],
                    "data": cmd["data"]
                })

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_pong(self, cmd):
        """ 
        Handle the ping response sent by a worker on the associated Queue.

        @type  cmd:      Dictionary
        @param cmd:      A dictionary containing the ping message.
        """

        worker_id = cmd["from"]
        for worker in self.workers:
            if worker["id"] == worker_id:
                worker["last_report"] = time.time()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_pid(self, cmd):
        """
        Stored the pid of the worker which is sent by the worker via the 
        Queue associated with the worker. This information could be obtained
        directly by checking the pid attribute of the started worker from the
        job handler. This will be implemented later.
            
        @type  cmd:      Dictionary
        @param cmd:      A dictionary containing the pid message
        """

        worker_id = cmd["from"]
        for worker in self.workers:
            if worker["id"] == worker_id:
                worker["pid"] = cmd["data"]

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def _q_handle_job_finished(self, cmd):
        """
        When a worker finished executing a job it sends a job finished message
        on the queue associated with the worker. This handler listens for such
        messages and removes finished jobs from the list of registered jobs
        kept to maintain state information.

        @type  cmd:      Dictionary
        @param cmd:      A dictionary containing the ID of the finished job
        """

        job_id = cmd["data"]
        self.delete_worker(cmd["from"])
        if job_id in self.jobs_registered: self.jobs_registered.remove(job_id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def broadcast(self, command, data = None, excluded_workers = []):
        """
        Broadcast a message to all workers via the queues.

        @type  command:              String
        @param command:              The command to be broadcasted
        @type  data:                 String
        @param data:                 The data belonging to the command
        @type  excluded_workers:     List
        @param excluded_workers:     List of workers to be excluded from the
                                     broadcast
        """

        for worker in self.workers:
            if worker in excluded_workers: continue
            worker["c_queue"].put({
                "from": self.id,
                "to": worker["id"],
                "command": command,
                "data": data
            })

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def send_to(self, worker_id, command, data):
        """
        Send a message to a worker identified by its ID via the associated
        queue.

        @type  worker_id:  String
        @param worker_id:  The ID of the worker the message has to be sent to
        @type  command:    String
        @param command:    The command to be broadcasted
        @type  data:       String
        @param data:       The data belonging to the command
        """

        for worker in self.workers:
            if worker_id == worker["id"]:
                if self.config["general"]["debug"] > 4:
                    syslog.syslog(syslog.LOG_INFO,
                                  "sending to worker %s, cmd: %s, data: %s" % 
                                  (worker["id"], command, str(data)))

                worker["c_queue"].put({
                    "from": self.id,
                    "to": worker["id"],
                    "command": command,
                    "data": data
                })

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def handle(self, cmd):
        """
        Handle the received message. The handler function is dynamically
        looked up and called, this way handling of new commands can be easily
        implemented just by adding a handler function.

        @type  cmd:      Dictionary
        @param cmd:      A dictionary containing the message to be handled
        """

        try:
            getattr(self, '_q_handle_' + cmd["command"], None)(cmd)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "w[%s]: failed to execute queue handler '%s' (%s)" %
                          (self.id, cmd["command"], str(ex)))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def listener(self):
        """
        Check every queue assigned to workers to see if there is a message 
        sent by a worker waiting to be processed.
        """

        syslog.syslog(syslog.LOG_INFO, "queue listener started")
        while self.running:
            for worker in self.workers:
                cmd = None
                try:
                    cmd = worker["p_queue"].get_nowait()
                except Queue.Empty:
                    pass

                if cmd: self.handle(cmd)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def start_worker(self, job_id):
        """
        Spawn a worker process to executed the job identified by job_id.

        @type  job_id:   String
        @param job_id:   The ID of the job to be executed

        @rtype:          Dictionary
        @return:         Dictionary with details related to the worker
        """

        worker = {}
        worker["id"]       = self.generate_id()

        syslog.syslog(syslog.LOG_INFO,
                      "initializing worker %s ..." % worker["id"])

        worker["pid"]      = None
        worker["c_queue"]  = multiprocessing.Queue()
        worker["p_queue"]  = multiprocessing.Queue()
        worker["instance"] = jobworker(self.id,
                                       worker["id"],
                                       job_id,
                                       worker["c_queue"],
                                       worker["p_queue"],
                                       self.root,
                                       self.config)
        worker["process"]  = Process(target=worker["instance"].run)
        worker["last_report"] = time.time()
        worker["process"].start()
        self.workers.append(worker)
        return worker

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def kill_worker(self, worker):
        """
        Kill a worker process.

        @type  worker:   Dictionary
        @param worker:   The dictionary describing the worker
        """

        if worker["pid"] != 0 and worker["pid"] != None:
	    syslog.syslog(syslog.LOG_INFO,
                          "killing defunct worker %s, pid: %d" % 
                          (worker["id"], worker["pid"]))
            os.kill(worker["pid"], signal.SIGKILL)
            self.delete_worker(worker["id"])

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def is_running(self):
        """
        Return job handler status.
        """

        return self.running

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def stop(self):
        """
        Stop the job handler module. As part of the shutdown procedure all
        workers will be stopped.
        """

        for worker in self.workers:
            self.delete_worker(worker["id"])

        self.workers = []
        self.running = False
	syslog.syslog(syslog.LOG_INFO, "all workers stopped")

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def check_jobs(self):
        """
        Check whether a new job is available. This is done by checking for the
        presence of new jobs in the <FUZZLABS_ROOT>/jobs directory. If a new 
        job is found a worker process is spawned to execute the job.
        """

        for dirpath, dirnames, filenames in os.walk(self.jobs_dir):
            for filename in filenames:
                if len(filename.split(".")) < 2: continue
                if filename.split(".")[1] != "job": continue
                job_id = filename.split(".")[0]
                if job_id in self.jobs_registered: continue

                worker = self.start_worker(job_id)
                self.jobs_registered.append(job_id)
                syslog.syslog(syslog.LOG_INFO,
                              "registered new job %s" % job_id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def format_status(self):
        """
        Perform concatenation of worker related details.

        @rtype:          List
        @return:         List of dictionaries describing the status of workers
        """

        f_status = []
        for status in self.job_status:
            n_status = {"worker": status["worker"]}
            n_status.update(status["data"])
            f_status.append(n_status)
        return f_status

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_status(self, sender):
        """
        Handle job status request events sent by the web server. All worker
        related status details are being sent back to the web server.
        """

        dispatcher.send(signal=ev.Event.EVENT__RSP_JOBS_LIST,
                        sender="JOBSHANDLER",
                        data=json.dumps(self.format_status()))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_pause(self, sender, data):
        """
        Handle job pause request events sent by the web server. The requested
        job will get paused.

        @type  sender:   String
        @param sender:   The string identifying the sender of the event
        @type  data:     String
        @param data:     The ID of the job to be paused
        """

        self.broadcast("job_pause", data)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_resume(self, sender, data):
        """
        Handle job resume request events sent by the web server. The requested
        job will get resumed.

        @type  sender:   String
        @param sender:   The string identifying the sender of the event
        @type  data:     String
        @param data:     The ID of the job to be resumed
        """

        self.broadcast("job_resume", data)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_delete(self, sender, data):
        """
        Handle job delete request events sent by the web server. The requested
        job will get deleted.

        @type  sender:   String
        @param sender:   The string identifying the sender of the event
        @type  data:     String
        @param data:     The ID of the job to be deleted
        """

        self.broadcast("job_delete", data)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        """
        The main method of the job handler module.
        """

        syslog.syslog(syslog.LOG_INFO,
                      "job handler started with ID %s" % self.id)

        l = threading.Thread(target=self.listener)
        l.start()

        dispatcher.connect(self.__handle_job_status,
                           signal=ev.Event.EVENT__REQ_JOBS_LIST,
                           sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_pause,
                           signal=ev.Event.EVENT__REQ_JOB_PAUSE,
                           sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_resume,
                           signal=ev.Event.EVENT__REQ_JOB_RESUME,
                           sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_delete,
                           signal=ev.Event.EVENT__REQ_JOB_DELETE,
                           sender=dispatcher.Any)

        while self.running:
            self.broadcast("job_status", None)
            self.check_jobs()
            time.sleep(3)

        syslog.syslog(syslog.LOG_INFO, "job handler stopped")

