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
import select
import threading

import media
import blocks
import pgraph
import sex
import primitives

from agent import agent
from classes import DatabaseHandler as db

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

class session (pgraph.graph):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, config, root_dir, job_dir, session_id, job_data):
        pgraph.graph.__init__(self)

        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

        self.job_data            = job_data

        settings                 = self.job_data["session"]
        transport                = self.job_data["target"]["transport"]
        conditions               = self.job_data["target"]["conditions"]

        self.session_id          = session_id
        self.directory           = job_dir
        self.job_data            = job_data
        self.root_dir            = root_dir
        self.config              = config
        self.database            = db.DatabaseHandler(self.config, self.root_dir,
                                                      self.session_id)
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

        self.pre_send            = None
        self.post_send           = None

        # State reason holds information about why the job is in a given
        # state. For example, a job can be in a paused state because the
        # user requested the pause, or, because of an error, e.g.: no
        # connection to the agent, or the target has crashed.
        # Similarly with the running state: it can be because a user 
        # requested a job or because the scheduler started a job.
        # (scheduler is not yet available, but planned)

        self.state_reason        = ""

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

    def set_pre_send(self, func):
        if not func: return None
        self.pre_send = func

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def set_post_send(self, func):
        if not func: return None
        self.post_send = func

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def get_status(self):

        if not self.fuzz_node: return None

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
                  "state_reason": self.state_reason,
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
        data["crashes"]             = self.crash_count
        data["warnings"]            = self.warning_count
        data["total_num_mutations"] = self.total_num_mutations
        data["total_mutant_index"]  = self.total_mutant_index
        data["pause_flag"]          = self.pause_flag

        fh = open(self.directory + "/" + self.session_filename, "wb+")
        fh.write(json.dumps(data))
        fh.close()

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

    def fuzz (self, this_node=None, path=[]):
        '''
        Call this routine to get the ball rolling. No arguments are necessary as they are
        both utilized internally during the recursive traversal of the session graph.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one.
        '''

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

        # If no errors above and not already connected to the agent, initialize the
        # agent connection.
        # If the agent cannot be initialized make sure the user is aware of it.

        if self.agent == None and self.agent_settings != None:
            try:
                self.agent = agent(self.config, self.session_id, self.agent_settings)
                self.agent.connect()
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR, self.session_id +
                              ": failed to establish agent connection (%s)" % str(ex))
                self.finished_flag = True
                self.stop_flag = True
                return

        # Get the agent to execute 
            try:
                self.agent.start()
            except Exception, ex:
                syslog.syslog(syslog.LOG_ERR, self.session_id +
                              ": agent failed to execute command (%s)" % str(ex))
                self.finished_flag = True
                self.stop_flag = True
                return

            syslog.syslog(syslog.LOG_INFO, self.session_id +
                          ": process started, waiting 3 seconds...")
            time.sleep(3)


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
                    # TODO: this has to be updated properly...

                    if self.agent != None and self.agent_settings != None:
                        self.agent.start()

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
                            if self.pre_send: self.pre_send(self.transport_media.media_socket())
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
                        if self.post_send: self.post_send(self.transport_media.media_socket())
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

        if self.total_mutant_index == self.total_num_mutations:
            self.finished_flag = True
            self.stop_flag = True
            syslog.syslog(syslog.LOG_INFO, self.session_id + ": job finished")
            if self.agent != None and self.agent_settings != None:
                self.agent_cleanup()

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def agent_cleanup(self):
        # If we have an agent, try to clean that up properly.

        try:
            if not self.agent.kill():
                syslog.syslog(syslog.LOG_ERR, self.session_id +
                              ": failed to terminate remote process")
            self.agent.disconnect()
            self.agent = None
            self.agent_settings = None
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id +
                          ": failed to clean up agent connection (%s)" % str(ex))

        self.agent = None
        self.agent_settings = None

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
        self.crash_count         = data["crashes"]
        self.warning_count       = data["warnings"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index  = data["total_mutant_index"]
        self.pause_flag          = data["pause_flag"]


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
        If the pause flag is raised, enter an endless loop until it is lowered.
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
        except Exception, ex:
            if self.config['general']['debug'] > 0:
                syslog.syslog(syslog.LOG_WARNING, self.session_id + ": failed to send, socket error: " + str(ex))
            self.handle_crash("fail_receive", "failed to send data, possible crash?")

        # TODO: check to make sure the receive timeout is not too long...
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
                "job_id": self.session_id,
                "time": time.time(),
                "target": self.target.details,
                "name": str(self.fuzz_node.name),
                "mutant_index": self.fuzz_node.mutant_index,
                "process_status": {},
                "request": node_data
            }
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id + ": failed to store session status (%s)" % str(ex))

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def dump_crash_data(self, crash_data, process_status = None):
        '''
        Dump crash data to disk.
        '''

        if not self.directory:
            return

        if crash_data == None:
            return

        if process_status == None:
            process_status = {}

        crash_data["process_status"] = process_status

        try:
            self.database.saveCrashDetails(json.dumps(crash_data))
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, self.session_id +
                              ": failed to save crash data (%s)" % str(ex))

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def handle_crash(self, event, message):
        """
        Handle a potential crash situation according to the configuration and the
        environment.

        The job configuration describes the actions to be taken for event. A sample
        configuration looks like below.

        "conditions": {
            "fail_connection": ["action-1", "action-2"],
            "fail_receive": ["pass"],
            "fail_send": ["action-1", "action-2"]
        }

        In the sample above the keys below the condition key are the events. The
        events can be described as:

          - fail_connection: failed to connect to the fuzz target. This can happen
                             when the target crashes and the port can no longer be
                             contacted.
          - fail_receive:    failed to receive data from the target. This can happen
                             if the service normally does not respond or, if the
                             service gets into a non-responsive condition as the result
                             of the fuzzing.
          - fail_send:       failed to send fuzz data (mutation) to the target. This
                             indicates a potential issue found.

        @type  event:    String
        @param event:    The identifier of the event
        @type  message:  String
        @param message:  The string description of the event
        """

        for action in self.conditions[event]:
            if action == "pass": continue
            if action == "handle": self.handle_event_action_default(event, message)

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def handle_event_action_default(self, event, message):
        """
        Handle cases where we suspect the target has crashed.
        """

        p_status = None
        process_running = False

        # Something has definitely happened. Check the agent (if any) to see the process
        # status.

        if self.agent != None and self.agent_settings != None:
            if self.agent.check_alive():
                p_status = self.agent.status()
            else:
                syslog.syslog(syslog.LOG_ERR,
                              self.session_id + ": could not contact agent, " +\
                              "crash might be a false positive")

            if p_status == "OK":
                process_running = True
                syslog.syslog(syslog.LOG_ERR,
                              self.session_id + ": the process is still running")

        syslog.syslog(syslog.LOG_ERR, self.session_id + ": " + str(message))

        self.crashing_primitives[self.fuzz_node.mutant] = \
            self.crashing_primitives.get(self.fuzz_node.mutant,0) +1

        # If we could not make a connection to the target then it was the
        # previous request (or one of the prev. requests) that resulted in
        # the crash of the service. As we cannot be completely sure which
        # one of the prev. requests caused the crash, the best we can do
        # is to log the previous request.

        if event == "fail_connection":
            self.dump_crash_data(self.previous_sent, p_status)
            if self.previous_sent != None:
                self.previous_sent['request'] = ""
            if process_running:
                self.warning_count = self.warning_count + 1
            else:
                self.crash_count = self.crash_count + 1

        # If we haven't received anything it is very likely that the cause
        # of the issue is the current request, therefore we save that.

        elif event == "fail_receive":
            self.dump_crash_data(self.current_sent, p_status)
            if self.current_sent != None:
                self.current_sent['request'] = ""
            if process_running:
                self.warning_count = self.warning_count + 1
            else:
                self.crash_count = self.crash_count + 1

        # If we can't send the request, similarly to fail_connection, it
        # was one of the previous requests to cause the issue.

        else:
            self.dump_crash_data(self.previous_sent, p_status)
            if self.previous_sent != None:
                self.previous_sent['request'] = ""
            if process_running:
                self.warning_count = self.warning_count + 1
            else:
                self.crash_count = self.crash_count + 1

        # In any of the above cases we pause the job or continue if we have an agent
        # and could restart the process.

        self.export_file()
        if self.agent != None and self.agent_settings != None:
            while not self.restart_process(): pass
        else:
            self.set_pause()
            self.pause()

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def restart_process(self):
        if not self.agent.start():
            syslog.syslog(syslog.LOG_ERR,
                          self.session_id + ": failed to restart process, pausing job.")
            self.set_pause()
            self.pause()
        return self.agent.check_alive()

