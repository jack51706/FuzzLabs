import os
import time
import json
import syslog
import socket
import select

# =======================================================================================
#
# =======================================================================================

class agent():

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, config, session_id, settings=None):
        """
        Initialize the module.

        @type  config:       Dictionary
        @param config:       The complete configuration as a dictionary
        @type  session_id:   String
        @param session_id:   The ID of the job this agent connection belongs to
        @type  settings:     Dictionary
        @param settings:     The configuration settings used to communicate with
                             the agent
        """

        self.config           = config
        self.session_id       = session_id
        self.address          = None
        self.port             = None
        self.command          = None
        self.conn_retry       = 5
        self.conn_retry_delay = 20

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

        if settings != None:
            if "address" in settings:
                self.address = settings["address"]
            else:
                syslog.syslog(syslog.LOG_ERR, self.session_id +\
                              ": agent address is not set")

            if "port" in settings:
                self.port = settings["port"]
            else:
                syslog.syslog(syslog.LOG_ERR, self.session_id +\
                              ": agent port is not set")

            if "command" in settings:
                self.command = settings["command"]
            else:
                syslog.syslog(syslog.LOG_ERR, self.session_id +\
                              ": command to execute not set for agent")

            if "conn_retry" in settings:
                self.conn_retry = settings["conn_retry"]

            if "conn_retry_delay" in settings:
                self.conn_retry_delay = settings["conn_retry_delay"]

        self.sock = None
        self.running = True

        syslog.syslog(syslog.LOG_INFO, self.session_id +\
                              ": agent connection set: %s:%d:%s" %
                              (self.address,
                              self.port,
                              self.command))

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def check_alive(self):
        if self.sock == None: return False
        message = json.dumps({"command": "ping"})
        self.sock.send(message)
        data = self.check_response()

        if data == None: return False
        if "command" not in data: return False
        if "data" not in data: return False
        if data["command"] != "ping": return False
        if data["data"] != "pong": return False

        return True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def do_start(self):
        if self.sock == None: return False
        if not self.command: return False
        message = json.dumps({"command": "start", "data": self.command})
        self.sock.send(message)
        data = self.check_response()

        if data == None: return False
        if "command" not in data: return False
        if "data" not in data: return False
        if data["command"] != "start": return False
        if data["data"] != "success": return False

        return True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def start(self):
        self.kill()
        retry = 0
        c_stat = self.do_start()
        while not c_stat:
            if retry == self.conn_retry: return False
            time.sleep(self.conn_retry_delay)
            retry += 1
            syslog.syslog(syslog.LOG_ERR, self.session_id +
                          ": agent failed to start command, retrying ...")
            c_stat = self.do_start()

        syslog.syslog(syslog.LOG_INFO, self.session_id +
                      ": process %s started successfully" % self.command)

        time.sleep(3)
        if not self.check_alive(): return False

        return True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def status(self):
        if self.sock == None: return None
        message = json.dumps({"command": "status"})
        self.sock.send(message)
        data = self.check_response()
        if data == None or "command" not in data or \
           data["command"] != "status" or "data" not in data:
            syslog.syslog(syslog.LOG_ERR, "unexpected response from agent: %s" %
                                          str(data))
            return None
        return(data["data"])

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def kill(self):
        if self.sock == None: return None
        message = json.dumps({"command": "kill"})
        self.sock.send(message)
        data = self.check_response()

        if data == None: return False
        if "command" not in data: return False
        if "data" not in data: return False
        if data["command"] != "kill": return False
        if data["data"] != "success": return False
        return True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def do_connect(self):
        if self.sock != None: self.disconnect()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception, ex:
            self.sock = None
            return False

        try:
            self.sock.connect((self.address, self.port))
        except Exception, ex:
            try: self.sock.close()
            except: pass
            self.sock = None
            return False

        return True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def connect(self):
        reconn = 0
        c_stat = self.do_connect()
        while not c_stat:
            if reconn == self.conn_retry: return False
            time.sleep(self.conn_retry_delay)
            reconn += 1
            syslog.syslog(syslog.LOG_ERR, self.session_id +
                          ": failed to estabilish connection to the agent, retrying...")
            c_stat = self.do_connect()

        if self.check_alive(): return True

        syslog.syslog(syslog.LOG_ERR, self.session_id +
                      ": failed to estabilish connection to the agent")
        return False

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def disconnect(self):
        if self.sock == None: return None
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.sock = None

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def recv(self, timeout=1):
        if self.sock == None: return None
        self.sock.setblocking(0)

        t_data = [];
        data = '';

        begin = time.time()
        while 1:
            if t_data and time.time() - begin > timeout:
                break
            elif time.time()-begin > timeout*2:
                break

            try:
                data = self.sock.recv(4096)
                if data:
                    t_data.append(data)
                    begin = time.time()
                else:
                    time.sleep(0.1)
            except:
                pass

        self.sock.setblocking(1)
        return ''.join(t_data)

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def check_response(self):
        command = None

        data = self.recv()
        if data == None: return None
        try:
            command = json.loads(data)
        except Exception, ex:
            return None

        return command

