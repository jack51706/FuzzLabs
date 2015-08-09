# =======================================================================================
# Transport Media Handlers
# =======================================================================================

import os
import abc
import sys
import json
import time
import socket
import select

from bluetooth import *

# =======================================================================================
# TRANSPORT MEDIA HANDLER SKELETON
# =======================================================================================

# ---------------------------------------------------------------------------------------
# A transport media class is an interface for the fuzzer, basically the sulley core, to
# send and receive data. The media class implements a skeleton to be used when developing
# a transport media handled class.
# ---------------------------------------------------------------------------------------

class media:
    __metaclass__  = abc.ABCMeta

    # -----------------------------------------------------------------------------------
    # Standard constructor/initialization
    # -----------------------------------------------------------------------------------

    def __init__(self, bind=None, timeout=5.0, protos = []):
        self.bind = bind
        self.timeout = timeout
        self.proto = None
        self.protos = protos
        self.socket = None
        self.target = None

    # -----------------------------------------------------------------------------------
    # The media_socket function should return the socket associated with the media.
    # -----------------------------------------------------------------------------------

    def media_socket(self):
        return self.socket

    # -----------------------------------------------------------------------------------
    # The media_target function accepts a target defined by the following structure:
    #
    #     {"property-1": "<value-1>", "property-2", <value-2>}
    #
    # If no target is given, it returns the current target set.
    # -----------------------------------------------------------------------------------

    def media_target(self, target=None):
        if target == None:
            return self.target
        else:
            self.target = target

    # -----------------------------------------------------------------------------------
    # This function is responsible of building up a connection to the target set via the
    # media_target function.
    # As each transport media might require a completely different way to build up a
    # connection, this function is empty and each transport media handler should override
    # it to implement the necessary functionality.
    # -----------------------------------------------------------------------------------

    def connect(self):
        pass

    # -----------------------------------------------------------------------------------
    # This function disconnects from the target by closing the socket.
    # -----------------------------------------------------------------------------------

    def disconnect(self):
        try:
            self.socket.close()
        except Exception, ex:
            pass
        self.socket = None

    # -----------------------------------------------------------------------------------
    # This function implements the sending of data to the target. 
    # -----------------------------------------------------------------------------------

    @abc.abstractmethod
    def send(self, data):
        """ send data to target """

    # -----------------------------------------------------------------------------------
    # This function implements the receiving of data from the target. 
    # -----------------------------------------------------------------------------------

    def recv(self, size):
        return self.socket.recv(size)

    # -----------------------------------------------------------------------------------
    # This function returns the list of protocols supported by the transport media.
    # -----------------------------------------------------------------------------------

    def media_protocols(self):
        return self.protos

    # -----------------------------------------------------------------------------------
    # The media_protocol function accepts a the name of the protocol to be used.
    # If no protocol is given, it returns the current protocol set.
    # -----------------------------------------------------------------------------------

    def media_protocol(self, proto=None):
        if proto == None:
            return self.proto
        else:
            self.proto = proto


# =======================================================================================
# HANDLER FOR NETWORK TRANSPORT MEDIA
# =======================================================================================

class network(media):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, bind, timeout):
        media.__init__(self, bind, timeout, ["tcp", "udp"])
        self.target_address = None
        self.target_port = None

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def connect(self):
        try:
            if self.proto == "tcp" or self.proto == "ssl":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif self.proto == "udp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception, e:
            raise Exception, ["failed to create socket", str(e)]

        if self.bind:
            try:
                self.socket.bind(self.bind)
            except Exception, e:
                raise Exception, ["failed to bind on socket", str(e)]

        try:
            self.target_address = self.target.details['address']
            self.target_port = self.target.details['port']
        except Exception, e:
            raise Exception, ["failed to process target details", str(e)]

        try:
            self.socket.settimeout(self.timeout)
            if self.proto == "tcp":
                self.socket.connect((self.target_address, self.target_port))
        except Exception, e:
            raise Exception, ["failed to connect to target", str(e)]

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def send(self, data):
        if self.proto == "tcp":
            try:
                self.socket.send(data)
            except Exception, e:
                raise Exception, ["failed to send data", str(e)]
        else:
            # max UDP packet size.
            # TODO: anyone know how to determine this value smarter?
            MAX_UDP = 65507

            if os.name != "nt" and os.uname()[0] == "Darwin":
                MAX_UDP = 9216

            if len(data) > MAX_UDP:
                data = data[:MAX_UDP]

            try:
                self.socket.sendto(data, (self.target_address, self.target_port))
            except Exception, e:
                raise Exception, ["failed to send data", str(e)]

# =======================================================================================
# HANDLER FOR BLUETOOTH TRANSPORT MEDIA
# =======================================================================================

class bluetooth(media):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, bind=None, timeout=5.0):
        media.__init__(self, bind, timeout, ["l2cap", "rfcomm"])

        self.target_bdaddr = None
        self.target_channel = None

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def connect(self):
        self.socket = None
        try:
            if self.proto == "rfcomm":
                self.socket = BluetoothSocket(RFCOMM)
            elif self.proto == "l2cap":
                self.socket = BluetoothSocket(L2CAP)
        except Exception, e:
            raise Exception, ["failed to create socket", str(e)]

        try:
            self.target_bdaddr = self.target.details['bdaddr']
            self.target_channel = self.target.details['channel']
        except Exception, e:
            raise Exception, ["failed to process target details", str(e)]

        self.socket.settimeout(self.timeout)
        try:
            self.socket.connect((self.target_bdaddr, int(self.target_channel)))
        except Exception as e:
            # File descriptor in bad state has code 77
            # Still, connection works. Fix this later properly.
            if str(e)[1:3] != "77":
                raise Exception, ["failed to connect to target", str(e)]

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def send(self, data):
        if (self.socket == None):
            self.connect()

        try:
            self.socket.send(data)
        except Exception, e:
            raise Exception, ["failed to send data", str(e)]

# =======================================================================================
# HANDLER FOR FILE TRANSPORT MEDIA
# =======================================================================================

class file(media):

    # -----------------------------------------------------------------------------------
    #
    # -----------------------------------------------------------------------------------

    def __init__(self, bind=None, timeout=0):
        media.__init__(self, bind, timeout, ["file"])

        self.session_counter = 0
        self.f_path = None
        self.f_name = None
        self.f_ext = None
        self.p_sub = None

    def connect(self):
        self.f_path = self.target.details['path']
        self.f_name = self.target.details['filename']
        self.f_ext = self.target.details['extension']
        if not os.path.exists(self.f_path): os.makedirs(self.f_path)
        subdir = self.f_path + "/" + str(self.session_counter / 1000)
        if subdir != self.p_sub:
            self.p_sub = subdir
            if not os.path.exists(subdir): os.makedirs(subdir)

        try:
            f_full = self.p_sub + "/" + self.f_name + "." + \
                     str(self.session_counter) + \
                     "." + self.f_ext

            self.socket = open(f_full, 'w')
        except Exception, ex:
            raise ex

    def send(self, data):
        try:
            self.socket.write(data)
            self.session_counter += 1
        except Exception, ex:
            raise ex

    def disconnect(self):
        try:
            self.socket.close()
        except Exception, ex:
            pass

    def recv(self, size):
        return("OK")

    def media_socket(self):
        return self.socket

