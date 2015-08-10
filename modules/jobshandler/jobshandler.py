#!/usr/bin/env python

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

# =============================================================================
#
# =============================================================================

class jobshandler(threading.Thread):

    def descriptor(self):
        return(dict([
            ('type', 'module'),
            ('version', '0.2'),
            ('author', 'Zsolt Imre'),
            ('author-email', 'imrexzsolt@gmail.com')
        ]))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        threading.Thread.__init__(self)
        self.root              = root
        self.id                = self.generate_id()
        self.config            = config
        self.running           = True
        self.jobs_dir          = self.root + "/jobs" 
        self.archived_jobs_dir = self.root + "/archived_jobs" 
        self.job_status        = []
        self.jobs_registered   = []
        self.workers           = []

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def generate_id(self):
        h_in = str(random.getrandbits(64))
        h_in = str(time.time())
        return hashlib.sha1(h_in).hexdigest()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def is_status_for_worker(self, worker):
        if len(self.job_status) == 0: return False
        for status in self.job_status:
            if worker == status["worker"]: return True
        return False

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def update_worker_status(self, worker, w_status):
        for status in self.job_status:
            if worker == status["worker"]: status["data"] = w_status

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def delete_worker(self, worker_id):

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
        worker_id = cmd["from"]
        for worker in self.workers:
            if worker["id"] == worker_id:
                worker["last_report"] = time.time()

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def _q_handle_pid(self, cmd):
        worker_id = cmd["from"]
        for worker in self.workers:
            if worker["id"] == worker_id:
                worker["pid"] = cmd["data"]

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def _q_handle_job_finished(self, cmd):
        job_id = cmd["data"]
        self.delete_worker(cmd["from"])
        if job_id in self.jobs_registered: self.jobs_registered.remove(job_id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def broadcast(self, command, data = None, excluded_workers = []):
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
        for worker in self.workers:
            if worker_id == worker["id"]:
                if self.config["general"]["debug"] > 4:
                    syslog.syslog(syslog.LOG_INFO, "sending to worker %s, command: %s, data: %s" % 
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

    """
     Handle the received message. The handler function is dynamically looked
     up and called, this way handling of new commands can be easily implemented
     by just adding a handler function.
    """

    def handle(self, cmd):
        try:
            getattr(self, '_q_handle_' + cmd["command"], None)(cmd)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, "w[%s]: failed to execute queue handler '%s' (%s)" %
                              (self.id, cmd["command"], str(ex)))
            return

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def listener(self):
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
        worker = {}
        worker["id"]       = self.generate_id()

        syslog.syslog(syslog.LOG_INFO, "initializing worker %s ..." % worker["id"])

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
        if worker["pid"] != 0 and worker["pid"] != None:
	    syslog.syslog(syslog.LOG_INFO, "killing defunct worker %s, pid: %d" % 
                              (worker["id"], worker["pid"]))
            os.kill(worker["pid"], signal.SIGKILL)
            self.delete_worker(worker["id"])

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def is_running(self):
        return self.running

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def stop(self):
        for worker in self.workers:
            self.delete_worker(worker["id"])

        self.workers = []
        self.running = False
	syslog.syslog(syslog.LOG_INFO, "all workers stopped")
        return

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def check_jobs(self):
        for dirpath, dirnames, filenames in os.walk(self.jobs_dir):
            for filename in filenames:
                if len(filename.split(".")) < 2: continue
                if filename.split(".")[1] != "job": continue
                job_id = filename.split(".")[0]
                if job_id in self.jobs_registered: continue

                worker = self.start_worker(job_id)
                self.jobs_registered.append(job_id)
                syslog.syslog(syslog.LOG_INFO, "registered new job %s" % job_id)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def format_status(self):
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
        dispatcher.send(signal=ev.Event.EVENT__RSP_JOBS_LIST,
                        sender="JOBSHANDLER",
                        data=json.dumps(self.format_status()))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_pause(self, sender, data):
        self.broadcast("job_pause", data)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_resume(self, sender, data):
        self.broadcast("job_resume", data)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_delete(self, sender, data):
        self.broadcast("job_delete", data)

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "job handler started with ID %s" % self.id)

        l = threading.Thread(target=self.listener)
        l.start()

        dispatcher.connect(self.__handle_job_status, signal=ev.Event.EVENT__REQ_JOBS_LIST, sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_pause, signal=ev.Event.EVENT__REQ_JOB_PAUSE, sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_resume, signal=ev.Event.EVENT__REQ_JOB_RESUME, sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_delete, signal=ev.Event.EVENT__REQ_JOB_DELETE, sender=dispatcher.Any)

        while self.running:
            self.broadcast("job_status", None)
            self.check_jobs()
            time.sleep(3)

        syslog.syslog(syslog.LOG_INFO, "job handler stopped")

