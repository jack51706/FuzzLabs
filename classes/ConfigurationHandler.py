"""
 Provide an interface to handle the main configuration.
"""

import os.path
import json
import fcntl

class ConfigurationHandler:
    """
    Manage the configuration data stored in JSON format. The configuration is
    read from the JSON file, parsed and stored in a variable. The configuration
    can be retrieved using the get() method.
    """
    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, config_path = None):
        """ Initialize variables and reload (load) configuration. """
        self.config = None
        self.file = config_path
        self.reload()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __loadConfiguration(self):
        """ Open the configuration file and read, then parse its content. """
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

    def __isConfigFileExists(self, file_name):
        """ Check whether the configuration file exists or not. """
        status = False
        if os.path.isfile(file_name) and os.access(file_name, os.R_OK):
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
        if self.__isConfigFileExists(self.file):
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
        """ Return the parsed configuration data. """
        return self.config

