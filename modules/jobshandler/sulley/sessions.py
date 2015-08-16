# =======================================================================================
# Sulley
# =======================================================================================

import os
import re
import sys
import md5
import time
import json
import base64
import syslog
import socket
import threading

import media
import blocks
import pgraph
import sex
import primitives

# =======================================================================================
#
# =======================================================================================

class target:
    '''
    Target descriptor container.
    '''

    def __init__ (self, target, **kwargs):

        self.details      = target

# =======================================================================================
#
# =======================================================================================

class connection (pgraph.edge.edge):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__ (self, src, dst, callback=None):
        '''
        Extends pgraph.edge with a callback option. This allows us to register a 
        function to call between node transmissions to implement functionality such as
        challenge response systems. The callback method must follow this prototype:

            def callback(session, node, edge, sock)

        Where node is the node about to be sent, edge is the last edge along the current 
        fuzz path to "node", session is a pointer to the session instance which is
        useful for snagging data such as sesson.last_recv which contains the data
        returned from the last socket transmission and sock is the live socket. A 
        callback is also useful in situations where, for example, the size of the next
        packet is specified in the first packet.

        @type  src:      Integer
        @param src:      Edge source ID
        @type  dst:      Integer
        @param dst:      Edge destination ID
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to
        '''

        # run the parent classes initialization routine first.
        pgraph.edge.edge.__init__(self, src, dst)

        self.callback = callback

# =======================================================================================
#
# =======================================================================================

class agent:

    def __init__(self, a_address, a_port):
        self.address = a_address
        self.port = a_port

    def check_alive(self):
        pass

    def start(self, cmd):
        pass

    def kill(self):
        pass

# =======================================================================================
#
# =======================================================================================

class session (pgraph.graph):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, config, job_dir, session_id, settings=None, transport=None, 
                 conditions=None):

        pgraph.graph.__init__(self)

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

        self.session_id = session_id
        self.directory = job_dir

        if settings == None:
            syslog.syslog(syslog.LOG_ERR, self.session_id + 
                              ": no global configuration provided for job")
            return
        if settings == None:
            syslog.syslog(syslog.LOG_ERR, self.session_id + 
                              ": no settings provided for job")
            return
        if transport == None:
            syslog.syslog(syslog.LOG_ERR, self.session_id + 
                              ": no transport settings provided for job")
            return
        if conditions == None:
            syslog.syslog(syslog.LOG_ERR, self.session_id + 
                              ": no target crash detection conditions set")
            return

        self.config              = config
        self.target              = None
        self.media               = transport['media'].lower()
        self.transport_media     = None
        self.proto               = transport['protocol'].lower()
        self.conditions          = conditions
        self.agent               = None
        self.agent_settings      = None

        self.session_filename    = self.session_id + ".session"
        self.skip                = 0
        self.sleep_time          = 1.0
        self.bind                = None
        self.restart_interval    = 0
        self.timeout             = 5.0
        self.crash_threshold     = 3
        self.restart_sleep_time  = 300

        if settings.get('skip') != None: 
            self.skip = settings['skip']
        if settings.get('sleep_time') != None: 
            self.sleep_time = settings['sleep_time']
        if settings.get('bind') != None: 
            self.bind = settings['bind']
        if settings.get('restart_interval') != None: 
            self.restart_interval = settings['restart_interval']
        if settings.get('timeout') != None: 
            self.timeout = settings['timeout']
        if settings.get('crash_threshold') != None: 
            self.crash_threshold = settings['crash_threshold']
        if settings.get('restart_sleep_time') != None: 
            self.restart_sleep_time = settings['restart_sleep_time']

        self.total_num_mutations = 0
        self.total_mutant_index  = 0
        self.fuzz_node           = None
        self.pause_flag          = False
        self.stop_flag           = False
        self.finished_flag       = False
        self.crashing_primitives = {}
        self.crash_count         = 0
        self.warning_count       = 0
        self.crash_logs          = []
        self.previous_sent       = None
        self.current_sent        = None

        try:
            self.transport_media = getattr(media, self.media)(self.bind, self.timeout)
        except Exception, e:
            raise Exception("invalid media specified")
            sys.exit(1)

        if self.proto not in self.transport_media.media_protocols():
            raise Exception("protocol not supported by media")
            sys.exit(2)

        self.transport_media.media_protocol(self.proto)
        self.proto = self.transport_media.media_protocol()

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single 
        # point and the user may want to specify a number of initial requests.
        self.root       = pgraph.node()
        self.root.name  = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv  = None

        self.add_node(self.root)

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def get_status(self):

        if self.fuzz_node.name:
            current_name = self.fuzz_node.name
        else:
            current_name = "[N/A]"

        if self.finished_flag:
            state = "finished"
        elif self.stop_flag:
            state = "stopped"
        elif self.pause_flag:
            state = "paused"
        else:
            state = "running"

        progress_current     = float(self.fuzz_node.mutant_index) / \
                                     float(self.fuzz_node.num_mutations()) * 100
        progress_current     = "%.3f%%" % (progress_current)

        progress_total       = float(self.total_mutant_index) / \
                                     float(self.total_num_mutations) * 100
        progress_total       = "%.3f%%" % (progress_total)

        progress_current     = float(self.fuzz_node.mutant_index) / \
                                     float(self.fuzz_node.num_mutations()) * 100
        progress_current     = "%.3f%%" % (progress_current)

        progress_total       = float(self.total_mutant_index) / \
                               float(self.total_num_mutations) * 100
        progress_total       = "%.3f%%" % (progress_total)

        s_data = {"id": self.session_id,
                  "name": current_name,
                  "media": self.media,
                  "protocol": self.proto,
                  "state": state,
                  "crashes": self.crash_count,
                  "warnings": self.warning_count,
                  "progress": {
                      "progress": progress_total,
                      "total_mutant_index": self.total_mutant_index,
                      "num_mutations": self.total_num_mutations
                  }}

        return(s_data)

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def add_agent(self, a_details):
        if "address" in a_details and "port" in a_details and "command" in a_details:
            self.agent_settings = a_details
            return True
        return False

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def add_node (self, node):
        '''
        Add a pgraph node to the graph. We overload this routine to automatically 
        generate and assign an ID whenever a node is added.

        @type  node: pGRAPH Node
        @param node: Node to add to session graph
        '''

        node.number = len(self.nodes)
        node.id     = len(self.nodes)

        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node

        return self

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def add_target (self, target):
        '''
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        @type  target: session.target
        @param target: Target to add to session
        '''

        # add target to internal list.
        # Internal list is used to track multiple targets for parallel fuzzing.
        # Transport media target is for one given thread
        self.target = target
        self.transport_media.media_target(target)


    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def connect (self, src, dst=None, callback=None):
        '''
        Create a connection between the two requests (nodes) and register an optional 
        callback to process in between transmissions of the source and destination
        request. Leverage this functionality to handle situations such as challenge
        response systems. The session class maintains a top level node that all initial 
        requests must be connected to. Example:

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the 
        supplied node to the root node. This is a convenient alias and is identica to
        the second line from the above example::

            sess.connect(s_get("HTTP"))

        If you register callback method, it must follow this prototype::

            def callback(session, node, edge, sock)

        Where node is the node about to be sent, edge is the last edge along the current 
        fuzz path to "node", session is a pointer to the session instance which is
        useful for snagging data such as sesson.last_recv which contains the data
        returned from the last socket transmission and sock is the live socket. A 
        callback is also useful in situations where, for example, the size of the next
        packet is specified in the first packet. As another example, if you need to fill 
        in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        @type  src:      String or Request (Node)
        @param src:      Source request name or request node
        @type  dst:      String or Request (Node)
        @param dst:      Destination request name or request node
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to 

        @rtype:  pgraph.edge
        @return: The edge between the src and dst.
        '''

        # if only a source was provided, then make it the destination and set the source 
        # to the root node.
        if not dst:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if type(src) is str:
            src = self.find_node("name", src)

        if type(dst) is str:
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
            self.add_node(src)

        if not self.find_node("name", dst.name):
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def export_file (self):
        '''
        Dump various object values to disk.

        @see: import_file()
        '''

        if not self.session_filename:
            return

        data = {}
        data["session_filename"]    = self.session_filename
        data["skip"]                = self.total_mutant_index
        data["sleep_time"]          = self.sleep_time
        data["restart_sleep_time"]  = self.restart_sleep_time
        data["proto"]               = self.proto
        data["restart_interval"]    = self.restart_interval
        data["timeout"]             = self.timeout
        data["crash_threshold"]     = self.crash_threshold
        data["total_num_mutations"] = self.total_num_mutations
        data["total_mutant_index"]  = self.total_mutant_index
        data["pause_flag"]          = self.pause_flag
        data["crash_logs"]          = json.dumps(self.crash_logs)

        fh = open(self.directory + "/" + self.session_filename, "wb+")
        fh.write(json.dumps(data))
        fh.close()

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def fuzz (self, this_node=None, path=[]):
        '''
        Call this routine to get the ball rolling. No arguments are necessary as they are
        both utilized internally during the recursive traversal of the session graph.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one.
        '''

        # Initialize agent
        #   1. Make sure only initialize of self.agent == None
        #   2. Initialize the agent with the IP address of the target
        # If the agent cannot be initialized make sure the user is aware of it

        # TODO

        # if no node is specified, we start from root and initialize the session.
        if not this_node:
            # we can't fuzz if we don't have at least one target and one request.
            if not self.target:
                syslog.syslog(syslog.LOG_ERR, self.session_id + 
                                  ": no target specified for session")
                return

            if not self.edges_from(self.root.id):
                syslog.syslog(syslog.LOG_ERR, self.session_id + 
                                  ": no request specified for session")
                return

            this_node = self.root

            self.total_mutant_index  = 0
            self.total_num_mutations = self.num_mutations()

        target = self.target

        # step through every edge from the current node.

        for edge in self.edges_from(this_node.id):

            if self.stop_flag: return 

            # the destination node is the one actually being fuzzed.
            self.fuzz_node = self.nodes[edge.dst]
            num_mutations  = self.fuzz_node.num_mutations()

            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then 
            # one path through a set of given nodes we don't want any ambiguity.
            path.append(edge)

            current_path  = " -> ".join([self.nodes[e.src].name for e in path[1:]])
            current_path += " -> %s" % self.fuzz_node.name

            if self.config['general']['debug'] > 1:
                syslog.syslog(syslog.LOG_INFO, self.session_id + 
                                  ": fuzz path: %s, fuzzed %d of %d total cases" 
                                  % (current_path, self.total_mutant_index, 
                                  self.total_num_mutations) )

            done_with_fuzz_node = False

            # loop through all possible mutations of the fuzz node.

            while not done_with_fuzz_node and not self.stop_flag:
                # if we need to pause, do so.
                self.pause()

                # If we have exhausted the mutations of the fuzz node, break out of the 
                # while(1). 
                # Note: when mutate() returns False, the node has been reverted to the 
                # default (valid) state.

                if not self.fuzz_node.mutate():
                    if self.config['general']['debug'] > 0:
                        syslog.syslog(syslog.LOG_INFO, self.session_id + 
                                          ": all possible mutations exhausted")
                    done_with_fuzz_node = True
                    continue

                # make a record in the session that a mutation was made.

                self.total_mutant_index += 1

                # if we've hit the restart interval, restart the target.

                if self.restart_interval and self.total_mutant_index % self.restart_interval == 0:
                    if self.config['general']['debug'] > 0:
                        syslog.syslog(syslog.LOG_WARNING, self.session_id + ": restart interval reached")
                    self.restart_target(self.transport_media.media_target())

                # if we don't need to skip the current test case.

                if self.total_mutant_index > self.skip:
                    if self.config['general']['debug'] > 1:
                        syslog.syslog(syslog.LOG_INFO, self.session_id + ": fuzzing %d / %d" 
                                          % (self.fuzz_node.mutant_index, num_mutations))

                    # attempt to complete a fuzz transmission. keep trying until we are 
                    # successful, whenever a failure occurs, restart the target.

                    while not self.stop_flag:
                        try:
                            self.transport_media.connect()
                        except Exception, ex:
                            syslog.syslog(syslog.LOG_ERR, self.session_id + ": " + str(ex))
                            self.handle_crash("fail_connection", 
                                              "failed to connect to target, possible crash?")

                        # if the user registered a pre-send function, pass it the sock 
                        # and let it do the deed.

                        try:
                            self.pre_send(self.transport_media.media_socket())
                        except Exception, ex:
                            if self.config['general']['debug'] > 0:
                                syslog.syslog(syslog.LOG_ERR, self.session_id + ": pre_send() failed (%s)" % str(ex))
                            self.handle_crash("fail_send", 
                                              "pre_send() failed, possible crash?")
                            continue

                        # send out valid requests for each node in the current path up to 
                        # the node we are fuzzing.

                        try:
                            for e in path[:-1]:
                                node = self.nodes[e.dst]
                                self.transmit(self.transport_media.media_socket(), node, 
                                              e, self.transport_media.media_target())
                        except Exception, ex:
                            if self.config['general']['debug'] > 0:
                                syslog.syslog(syslog.LOG_ERR, self.session_id + 
                                                  ": failed to transmit a node up the " +
                                                  "path (%s)" % str(ex))
                            self.handle_crash("fail_send", 
                                              "failed to transmit a node up the path, possible crash?")
                            continue

                        # now send the current node we are fuzzing.

                        try:
                            self.transmit(self.transport_media.media_socket(), 
                                          self.fuzz_node, edge, 
                                          self.transport_media.media_target())
                        except Exception, ex:
                            if self.config['general']['debug'] > 0:
                                syslog.syslog(syslog.LOG_ERR, self.session_id + 
                                                  ": failed transmitting fuzz node (%s)" % str(ex))
                            self.handle_crash("fail_send", 
                                              "failed transmitting fuzz node, possible crash?")
                            continue

                        # if we reach this point the send was successful for break out 
                        # of the while(1).

                        break

                    try:
                        self.post_send(self.transport_media.media_socket())
                    except Exception, ex:
                            if self.config['general']['debug'] > 0:
                                syslog.syslog(syslog.LOG_ERR, self.session_id + 
                                                  ": post_send() failed %s" % str(ex))
                            self.handle_crash("fail_send", 
                                              "post_send() failed, possible crash?")
                            continue

                    # done with the socket.

                    self.transport_media.disconnect()

                    # delay in between test cases.

                    if self.config['general']['debug'] > 2:
                        syslog.syslog(syslog.LOG_INFO, self.session_id + 
                                          ": sleeping for %f seconds" % self.sleep_time )
                    time.sleep(self.sleep_time)

                    # serialize the current session state to disk.

                    self.export_file()

            # recursively fuzz the remainder of the nodes in the session graph.

            self.fuzz(self.fuzz_node, path)

        # finished with the last node on the path, pop it off the path stack.

        if path:
            path.pop()

        self.finished_flag = True
        self.stop_flag = True
        syslog.syslog(syslog.LOG_INFO, self.session_id + ": job finished")
        return

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def import_file (self):
        '''
        Load varous object values from disk.

        @see: export_file()
        '''

        try:
            fh   = open(self.directory + "/" + self.session_filename, "rb")
            data = json.loads(fh.read())
            fh.close()
        except:
            return

        # update the skip variable to pick up fuzzing from last test case.
        self.skip                = data["total_mutant_index"]

        self.session_filename    = data["session_filename"]
        self.sleep_time          = data["sleep_time"]
        self.restart_sleep_time  = data["restart_sleep_time"]
        self.proto               = data["proto"]
        self.restart_interval    = data["restart_interval"]
        self.timeout             = data["timeout"]
        self.crash_threshold     = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index  = data["total_mutant_index"]
        self.pause_flag          = data["pause_flag"]
        self.crash_logs          = json.loads(data["crash_logs"])


    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def num_mutations (self, this_node=None, path=[]):
        '''
        Number of total mutations in the graph. The logic of this routine is identical to 
        that of fuzz(). See fuzz() for inline comments. The member varialbe
        self.total_num_mutations is updated appropriately by this routine.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one 

        @rtype:  Integer
        @return: Total number of mutations in this session.
        '''

        if not this_node:
            this_node                = self.root
            self.total_num_mutations = 0

        for edge in self.edges_from(this_node.id):
            next_node                 = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def set_pause(self):
        self.pause_flag = 1

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def set_resume(self):
        self.pause_flag = 0

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def pause (self):
        '''
        If thet pause flag is raised, enter an endless loop until it is lowered.
        '''

        while 1:
            if self.pause_flag:
                time.sleep(1)
            else:
                break

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def terminate (self):
        self.stop_flag = True

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def post_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run after to each fuzz 
        request. The order of events is as follows:

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to tear down the RPC request.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.

        pass

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def pre_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run prior to each fuzz 
        request. The order of events is as follows:

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.

        pass

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def restart_target (self, target, stop_first=True):
        '''
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a 
        process monitor is available restart the target process. Otherwise, do nothing.

        @type  target: session.target
        @param target: Target we are restarting
        '''

        syslog.syslog(syslog.LOG_ERR, "sleeping for %d seconds" % self.restart_sleep_time)
        time.sleep(self.restart_sleep_time)

        # TODO: should be good to relaunch test for crash before returning False

        return False

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def transmit (self, sock, node, edge, target):
        '''
        Render and transmit a node, process callbacks accordingly.

        @type  sock:   Socket
        @param sock:   Socket to transmit node on
        @type  node:   Request (Node)
        @param node:   Request/Node to transmit
        @type  edge:   Connection (pgraph.edge)
        @param edge:   Edge along the current fuzz path from "node" to next node.
        @type  target: session.target
        @param target: Target we are transmitting to
        '''

        data = None

        try:
            self.internal_callback(node)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id + ": " + "failed to store internal state (%s)" % str(ex))

        # if the edge has a callback, process it. the callback has the option to render 
        # the node, modify it and return.

        if edge.callback:
            data = edge.callback(self, node, edge, sock)

        if self.config['general']['debug'] > 1:
            syslog.syslog(syslog.LOG_INFO, self.session_id + ": transmitting [%d.%d]" 
                              % (node.id, self.total_mutant_index) )

        # if no data was returned by the callback, render the node here.
        if not data:
            data = node.render()

        try:
            self.transport_media.send(data)
            if self.config['general']['debug'] > 1:
                syslog.syslog(syslog.LOG_INFO, self.session_id + ": packet sent: " + repr(data) )
        except Exception, e:
            if self.config['general']['debug'] > 0:
                syslog.syslog(syslog.LOG_WARNING, self.session_id + ": failed to send, socket error: " + str(e))
            self.handle_crash("fail_receive", "failed to send data, possible crash?")

        try:
            self.last_recv = self.transport_media.recv(10000)
        except Exception, e:
            self.last_recv = ""

        if len(self.last_recv) > 0:
            if self.config['general']['debug'] > 1:
                syslog.syslog(syslog.LOG_INFO, self.session_id + ": received: [%d] %s" 
                                  % (len(self.last_recv), repr(self.last_recv)) )
        else:
            if self.config['general']['debug'] > 1:
                syslog.syslog(syslog.LOG_WARNING, self.session_id + ": nothing received on socket")
            self.handle_crash("fail_receive", "nothing received on socket, possible crash?")

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def dump_crash_data(self, crash_data):
        '''
        Dump crash data to disk.
        '''

        if not self.directory:
            return

        data = self.load_crash_data()
        if (data == None or len(data) == 0):
            data = []

        try:
            data.append(crash_data)
            fh = open(self.directory + "/" + self.session_id + ".crash", "wb+")
            fh.write(json.dumps(data))
            fh.close()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id + 
                              ": failed to save crash data (%s)" % str(ex))

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def load_crash_data(self):
        data = None
        try:
            fh   = open(self.directory + "/" + self.session_id + ".crash", "rb")
            data = json.loads(fh.read())
            fh.close()
        except Exception, e:
            return None
        return data

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def handle_crash(self, event, message):
        for action in self.conditions[event]:
            if action == "log":
                syslog.syslog(syslog.LOG_ERR, self.session_id + ": " + str(message))

                self.crashing_primitives[self.fuzz_node.mutant] = \
                    self.crashing_primitives.get(self.fuzz_node.mutant,0) +1

                # Crash data is dumped into the crash file. After, the request data is
                # cleared out before storing into the crash log. This way long requests
                # will not eat up the memory and the engine still contains a reference
                # to the crash data in the crash log file.

                if event == "fail_connection":
                    self.dump_crash_data(self.previous_sent)
                    if self.previous_sent != None:
                        self.previous_sent['request'] = ""
	            self.crash_logs.append(base64.b64encode(self.previous_sent))
                    self.crash_count = self.crash_count + 1
                elif event == "fail_receive":
                    self.dump_crash_data(self.current_sent)
                    if self.current_sent != None:
                        self.current_sent['request'] = ""
	            self.crash_logs.append(base64.b64encode(self.current_sent))
                    self.warning_count = self.warning_count + 1
                else:
                    self.dump_crash_data(self.previous_sent)
                    if self.previous_sent != None:
                        self.previous_sent['request'] = ""
	            self.crash_logs.append(base64.b64encode(self.previous_sent))
                    self.warning_count = self.warning_count + 1

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def internal_callback(self, node):
        node_data = ""
        try:
            node_data = str(base64.b64encode(node.render()))
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id + ": failed to render node data when" + \
                                                " saving status (%s)" % str(ex))

        try:
            self.previous_sent = self.current_sent
            self.current_sent = {
                "id": "",
                "job_id": self.session_id,
                "time": time.time(),
                "target": self.target.details,
                "name": str(self.fuzz_node.name),
                "mutant_index": self.fuzz_node.mutant_index,
                "request": node_data
            }
            self.current_sent['id'] = md5.new(json.dumps(self.current_sent)).hexdigest()
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id + ": failed to store session status (%s)" % str(ex))


