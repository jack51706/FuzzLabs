# =============================================================================
# WebServer
# =============================================================================

import cgi
import json
import time
import threading
import psutil
import syslog
import httplib
import BaseHTTPServer
from pydispatch import dispatcher
from classes import Event as ev

__author__     = "Zsolt Imre"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

jobs_status = ""
archives_status = ""
issues_list = ""

# =============================================================================
#
# =============================================================================

class system_stats:

    def __init__(self):
        pass

    def get_cpu_stats(self):
        cpu_used = int(round((psutil.cpu_times().user * 100) + \
                   (psutil.cpu_times().system * 100), 0))
        cpu_free = int(round(psutil.cpu_times().idle * 100, 0))

        cpu_stat = {
            "used": cpu_used,
            "free": cpu_free
        }

        return cpu_stat

    def get_memory_stats(self):

        memory = {
            "physical": {
                "used": psutil.phymem_usage().used,
                "free": psutil.phymem_usage().free
            },
            "virtual": {
                "used": psutil.virtmem_usage().used,
                "free": psutil.virtmem_usage().free
            }
        }

        return memory

    def get_disk_stats(self):

        disk_stat = {
            "used": psutil.disk_usage('/').used,
            "free": psutil.disk_usage('/').free
        }

        return disk_stat

    def get_stats_summary(self):

        summary = {
            "cpu": self.get_cpu_stats(),
            "disk": self.get_disk_stats(),
            "memory": self.get_memory_stats()
        }

        return summary

# =============================================================================
#
# =============================================================================

class jobs_status_collector(threading.Thread):

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_rsp_jobs_list(self, sender, data = ""):
        global jobs_status
        jobs_status = data

        if self.config['general']['debug'] >= 1:
            syslog.syslog(syslog.LOG_INFO, "jobs status received: %s" %
                          str(jobs_status))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "jobs status collector started") 
        dispatcher.connect(self.__handle_rsp_jobs_list, 
                           signal=ev.Event.EVENT__RSP_JOBS_LIST,
                           sender=dispatcher.Any)
        while True:
            try:
                dispatcher.send(signal=ev.Event.EVENT__REQ_JOBS_LIST,
                                sender="WEBSERVER")
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR,
                              "failed to send job list request event (%s)" %
                              str(ex))
            time.sleep(3)

# =============================================================================
#
# =============================================================================

class issues_status_collector(threading.Thread):

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_rsp_issues_list(self, sender, data = ""):
        global issues_list
        issues_list = data

        if self.config['general']['debug'] >= 1:
            syslog.syslog(syslog.LOG_INFO, "issues list received: %s" %
                          str(issues_list))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "issues status collector started") 
        dispatcher.connect(self.__handle_rsp_issues_list,
                           signal=ev.Event.EVENT__RSP_ISSUES_LIST,
                           sender=dispatcher.Any)
        while True:
            try:
                dispatcher.send(signal=ev.Event.EVENT__REQ_ISSUES_LIST,
                                sender="WEBSERVER")
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR,
                              "failed to send issues list request event (%s)" %
                              str(ex))
            time.sleep(5)

# =============================================================================
#
# =============================================================================

class archives_collector(threading.Thread):

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_rsp_archives_list(self, sender, data = ""):
        global archives_status
        archives_status = data

        if self.config['general']['debug'] >= 1:
            syslog.syslog(syslog.LOG_INFO, "archives received: %s" %
                          str(archives_status))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def run(self):
        syslog.syslog(syslog.LOG_INFO, "archives status collector started") 
        dispatcher.connect(self.__handle_rsp_archives_list,
                           signal=ev.Event.EVENT__RSP_ARCHIVES_LIST,
                           sender=dispatcher.Any)
        while True:
            try:
                dispatcher.send(signal=ev.Event.EVENT__REQ_ARCHIVES_LIST,
                                sender="WEBSERVER")
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR,
                              "failed to send archives request event (%s)" %
                              str(ex))
            time.sleep(5)

# =============================================================================
#
# =============================================================================

class web_interface_handler (BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.server = server
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, 
                                                       client_address, server)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def unsupported_method (self):
        self.send_response(405)
        self.send_header('Allow', 'GET, POST')
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write("{}")

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def do_GET (self):
        self.do_everything()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def do_HEAD (self):
        self.unsupported_method()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def do_POST (self):
        self.do_everything()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def do_OPTIONS (self):
        self.send_response(200)
        self.send_header('Allow', 'GET, POST')
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers',
                         'origin, content-type, accept')
        self.end_headers()
        self.wfile.write("{}")

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def unauthenticated(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        uarsp = {"error": "authreq"}
        self.wfile.write(json.dumps(uarsp))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def check_auth(self, config, postvars):
        if not "secret" in config["general"]:
            return True
        if not "secret" in postvars:
            return False
        if str(config["general"]["secret"]) == str(postvars["secret"]):
            return True
        syslog.syslog(syslog.LOG_ERR,
                      "Authentication failed for client from %s:%s" %
                      (self.client_address[0], self.client_address[1]))
        return False

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def get_post_data(self):
        ctype, pdict = cgi.parse_header(self.headers.getheader('Content-Type'))
        if ctype == 'application/json':
            length = int(self.headers.getheader('Content-Length'))
            if length > 0:
                postvars = json.loads(self.rfile.read(length))
            else:
                postvars = {}
        else:
            postvars = {}
        return postvars

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def do_everything (self):
        post_data = {}
        response = {}
        if self.command == "POST":
            post_data = self.get_post_data()
        
        if not self.check_auth(self.server.config, post_data):
            self.unauthenticated()
            return

        uri_items = self.path.split("/")

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')

        if uri_items[1] == "status":
            response = self.view_status()
        elif uri_items[1] == "issues":
            response = self.view_issues()
        elif uri_items[1] == "system":
            response = json.dumps(system_stats().get_stats_summary())
        elif uri_items[1] == "jobs":
            if uri_items[2] == "pause":
                syslog.syslog(syslog.LOG_INFO,
                              "pause request received for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_JOB_PAUSE, 
                                sender="WEBSERVER", 
                                data=str(uri_items[3]))
            elif uri_items[2] == "resume":
                syslog.syslog(syslog.LOG_INFO,
                              "resume request received for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_JOB_RESUME, 
                                sender="WEBSERVER",
                                data=str(uri_items[3]))
            elif uri_items[2] == "delete":
                syslog.syslog(syslog.LOG_INFO, 
                              "delete request received for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_JOB_DELETE,
                                sender="WEBSERVER",
                                data=str(uri_items[3]))
        elif uri_items[1] == "archives":
            if len(uri_items) < 3:
                response = self.view_archives()
            elif uri_items[2] == "start":
                syslog.syslog(syslog.LOG_INFO,
                              "archived job start request for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_ARCHIVES_START,
                                sender="WEBSERVER",
                                data=str(uri_items[3]))
            elif uri_items[2] == "restart":
                syslog.syslog(syslog.LOG_INFO,
                              "archived job restart request for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_ARCHIVES_RESTART,
                                sender="WEBSERVER",
                                data=str(uri_items[3]))
            elif uri_items[2] == "delete":
                syslog.syslog(syslog.LOG_INFO,
                              "archived job delete received for job %s" %
                              str(uri_items[3]))
                dispatcher.send(signal=ev.Event.EVENT__REQ_ARCHIVES_DELETE,
                                sender="WEBSERVER",
                                data=str(uri_items[3]))
        else:
            response = "{}"

        self.end_headers()
        self.wfile.write(response)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def version_string (self):
        return "DCNWS"

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def view_archives (self):
        global archives_status
        return archives_status

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def view_issues (self):
        global issues_list
        return issues_list

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def view_status (self):
        global jobs_status
        return jobs_status

# =============================================================================
#
# =============================================================================

class web_interface_server (BaseHTTPServer.HTTPServer):
    '''
    http://docs.python.org/lib/module-BaseHTTPServer.html
    '''

    def __init__(self, server_address, RequestHandlerClass):
        BaseHTTPServer.HTTPServer.__init__(self, server_address,
                                           RequestHandlerClass)

# =============================================================================
#
# =============================================================================

class webserver(threading.Thread):

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def descriptor(self):
        return(dict([
            ('type', 'module'),
            ('version', __version__),
            ('name', 'webserver')
        ]))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        threading.Thread.__init__(self)
        self.root = root
        self.config = config
        self.setDaemon(True)
        self.running = True
        self.server = None
        self.jobs_collector = None
        self.archives_collector = None
        self.issues_collector = None

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

        if self.config == None:
            syslog.syslog(syslog.LOG_ERR, 'invalid configuration')
            self.running = False
        else:
            self.setDaemon(True)
            self.running = True

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __handle_event(self, sender, data):
        pass

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

    def run(self):
        syslog.syslog(syslog.LOG_INFO, 'webserver thread is accepting data')
        dispatcher.connect(self.__handle_event, signal=ev.Event.EVENT_GENERAL, 
                           sender=dispatcher.Any)
        try:
            self.jobs_collector = jobs_status_collector(self.config)
            self.jobs_collector.start()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          'failed to start job status collector (%s)' %
                          str(ex))

        try:
            self.archives_collector = archives_collector(self.config)
            self.archives_collector.start()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          'failed to start archives collector (%s)' % str(ex))

        try:
            self.issues_collector = issues_status_collector(self.config)
            self.issues_collector.start()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR,
                          'failed to start issues status collector (%s)' %
                          str(ex))

        self.server = web_interface_server(('', 26000), web_interface_handler)
        self.server.config = self.config
        while self.running:
            self.server.handle_request()
        syslog.syslog(syslog.LOG_INFO, 'webserver shutting down')

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def join(self, timeout=None):
        # A little dirty but no other solution afaik
        self._stopevent.set()
        conn = httplib.HTTPConnection("localhost:%d" % 26000)
        conn.request("GET", "/")
        conn.getresponse()

