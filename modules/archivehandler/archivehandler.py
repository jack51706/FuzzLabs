"""
Handler for archived jobs.
"""

import os
import os.path
import json
import shutil
import syslog
import threading
from pydispatch import dispatcher
from classes import Event as ev

__author__     = "Zsolt Imre"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

# =============================================================================
#
# =============================================================================

class archivehandler(threading.Thread):

    def descriptor(self):
        return(dict([
            ('type', 'module'),
            ('version', __version__),
            ('name', 'archivehandler')
        ]))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        """
        Initialize the archive handler.

        @type  root:     String
        @param root:     Full path to the FuzzLabs root directory
        @type  config:   Dictionary
        @param config:   The complete configuration as a dictionary
        """

        threading.Thread.__init__(self)
        self.root              = root
        self.config            = config
        self.running           = True
        self.jobs_dir          = self.root + "/jobs/queue" 
        self.archived_jobs_dir = self.root + "/jobs/archived" 
        self.processing        = False

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def is_running(self):
        """
        Return archive handler status.
        """

        return self.running

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def stop(self):
        """
        Stop archive handler.
        """

        self.running = False

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def load_job_data(self, f_path):
        """
        Load the job descriptor as a dictionary from the job file.

        @type  f_path:   String
        @param f_path:   Full path to the job descriptor file.

        @rtype:          Mixed
        @return:         Job descriptor (dict) or None if failed to load
        """

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
        """
        Get a list of archived jobs.

        @rtype:          List
        @return:         Name of the archived jobs
        """

        archived = []
        for dirpath, dirnames, filenames in os.walk(self.archived_jobs_dir):
            for dirname in dirnames:
                archived.append(dirname)
        return archived

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def __handle_archives_list(self, sender):
        """
        Handle EVENT__REQ_ARCHIVES_LIST events sent by the web server. The 
        event is sent by the web server's archive collector in order to fetch
        the list of archived jobs.

        @type  sender:   String
        @param sender:   Sender identification string

        @rtype:          List
        @return:         A list of archived jobs described by dictionaries
        """

        if self.processing:
            return
        self.processing = True

        report = []
        archived = self.get_archived_jobs()
        c_path = self.archived_jobs_dir

        for job in archived:
            job_details = {"id": job, "job": "", "session": ""}

            for files in os.listdir(c_path + "/" + job + "/"):
                l_path = c_path + "/" + job + "/" + files
                e_file = files.split(".")
                if len(e_file) < 2 or e_file[0] != job:
                    continue
                if e_file[1] == "job" or e_file[1] == "jlock":
                    job_details["job"] = self.load_job_data(l_path)
                if e_file[1] == "session":
                    job_details["session"] = self.load_job_data(l_path)
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

    def __handle_job_start(self, sender, data):
        """
        Handle EVENT__REQ_ARCHIVES_START events sent by the web server. The
        event is sent by the web server when the user requests an arhived job
        to be started. The session file of the job is kept, meaning that the
        job will resume from the state where it was when it got terminated.

        @type  sender:   String
        @param sender:   Sender identification string
        @type  data:     String
        @param data:     The name/ID of the job to be started
        """

        a_job_path = self.archived_jobs_dir + "/" + data + "/"
        try:
            if os.path.isfile(a_job_path + data + ".jlock"):
                shutil.move(a_job_path + data + ".jlock",
                            a_job_path + data + ".job")
            if not os.path.isfile(a_job_path + data + ".job"): 
                syslog.syslog(syslog.LOG_ERR,
                              "archive handler failed to start job %s" % data)
            shutil.move(self.archived_jobs_dir + "/" + data,
                        self.jobs_dir + "/")
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "archive handler failed to start job %s (%s)" %
                          (data, str(ex)))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_restart(self, sender, data):
        """  
        Handle EVENT__REQ_ARCHIVES_RESTART events sent by the web server. The
        event is sent by the web server when the user requests an arhived job
        to be restarted. The files containing the session and crash details
        are destroyed, meaning the job will start from the beginning.
        
        @type  sender:   String 
        @param sender:   Sender identification string
        @type  data:     String
        @param data:     The name/ID of the job to be started
        """

        a_job_path = self.archived_jobs_dir + "/" + data + "/"
        try:
            if os.path.isfile(a_job_path + data + ".jlock"):
                shutil.move(a_job_path + data + ".jlock",
                            a_job_path + data + ".job")
            if not os.path.isfile(a_job_path + data + ".job"): 
                syslog.syslog(syslog.LOG_ERR,
                              "archive handler failed to restart job %s (%s)" %
                              (data, str(ex)))
            if os.path.isfile(a_job_path + data + ".session"):
                os.remove(a_job_path + data + ".session")
            if os.path.isfile(a_job_path + data + ".crashes"):
                os.remove(a_job_path + data + ".crashes")
            shutil.move(self.archived_jobs_dir + "/" + data,
                        self.jobs_dir + "/")
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "archive handler failed to start job %s (%s)" %
                          (data, str(ex)))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_job_delete(self, sender, data):
        """
        Handle EVENT__REQ_ARCHIVES_DELETE events sent by the web server. The
        event is sent by the web server when the user requests an arhived job
        to be deleted. All files and directories related to the job will get
        deleted.

        @type  sender:   String
        @param sender:   Sender identification string
        @type  data:     String
        @param data:     The name/ID of the job to be started
        """

        try:
            shutil.rmtree(self.archived_jobs_dir + "/" + data)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          "archive handler failed to delete job %s (%s)" %
                          (data, str(ex)))

    # -------------------------------------------------------------------------
    # 
    # -------------------------------------------------------------------------

    def run(self):
        """
        The main method of the archive handler. Basically, the archive handler
        is just listens for and handles events received from other modules.
        """

        syslog.syslog(syslog.LOG_INFO, "archive handler started")

        dispatcher.connect(self.__handle_archives_list,
                           signal=ev.Event.EVENT__REQ_ARCHIVES_LIST,
                           sender=dispatcher.Any)

        dispatcher.connect(self.__handle_job_start,
                           signal=ev.Event.EVENT__REQ_ARCHIVES_START,
                           sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_restart,
                           signal=ev.Event.EVENT__REQ_ARCHIVES_RESTART,
                           sender=dispatcher.Any)
        dispatcher.connect(self.__handle_job_delete,
                           signal=ev.Event.EVENT__REQ_ARCHIVES_DELETE,
                           sender=dispatcher.Any)

        while self.running:
            pass

        syslog.syslog(syslog.LOG_INFO, "archive handler stopped")

