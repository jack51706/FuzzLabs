"""
Manage the configuration file of FuzzLabs.
"""

import os.path
import json
import fcntl

__author__     = "Zsolt Imre"
__copyright__  = "Copyright 2015, Zsolt Imre / DCNWS / FuzzLabs"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

class ConfigurationHandler:
    """
    Manage the configuration data stored in JSON format. The configuration is
    read from the JSON file, parsed and stored in a variable. The configuration
    can be retrieved using the get() method.
    """

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, c_path = None):
        """ 
        Initialize variables and reload (load) configuration.

        @type  c_path:   String
        @param c_path:   The path to the configuration file
        """

        self.config = None
        self.file = c_path
        self.reload()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __loadConfiguration(self):
        """
        Open the configuration file and read, then parse its content.
        """

        try:
            file_desc = open(self.file, "r")
            fcntl.flock(file_desc, fcntl.LOCK_EX)
            self.config = json.loads(file_desc.read())
            fcntl.flock(file_desc, fcntl.LOCK_UN)
            file_desc.close()
        except Exception, ex:
            raise Exception("failed to load configuration: " + str(ex))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __isFileExists(self, f_name):
        """
        Check whether the file exists or not.

        @type  f_name:   String
        @param f_name:   Full path to the file

        @rtype:          Boolean
        @return:         Presence of the file reported as boolean
        """

        status = False
        if os.path.isfile(f_name) and os.access(f_name, os.R_OK):
            status = True
        else:
            status = False
        return status

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def reload(self):
        """ 
        Reload the configuration by overwriting it by calling 
        __loadConfiguration().  
        """

        if self.__isFileExists(self.file):
            try:
                self.__loadConfiguration()
            except Exception, ex:
                raise Exception("failed to load configuration: " + str(ex))
        else:
            raise Exception("cannot access configuration file")

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def get(self):
        """
        Return the parsed configuration data.

        @rtype:          Dictionary
        @return:         The complete configuration as a dictionary.
        """

        return self.config

