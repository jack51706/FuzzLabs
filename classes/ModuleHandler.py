"""
Manage FuzzLabs modules.
"""

import os
import sys
import time
import syslog

__author__     = "Zsolt Imre"
__copyright__  = "Copyright 2015, Zsolt Imre / DCNWS / FuzzLabs"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

class ModuleHandler():
    """
    Handle loading, unloading and reloading of modules.
    """

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, root, config):
        """
        Initialize variables and modules.

        @type  root:     String
        @param root:     Full path to the FuzzLabs root directory
        @type  config:   Dictionary
        @param config:   The complete configuration as a dictionary
        """

        self.root = root
        self.config = config
        self.lock = False
        self.loaded_modules = []
        self.modules_dir = self.root + "/modules"
        self.mtime = os.path.getmtime(self.modules_dir) * 1000000
        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
        self.__init_modules()

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def get_directories(self):
        """
        Get the list of modules from the 'modules' directory.

        @rtype:          List
        @return:         List of module paths
        """


        dirs = []
        for entry in os.listdir(self.modules_dir):
            if not os.path.isfile(os.path.join(self.modules_dir, entry)): 
                dirs.append(entry)
        return dirs

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def is_module_loaded(self, name):
        """
        Check if a module is loaded by comparing _name_ with the name of the
        loaded modules from the list.

        @type  name:     String
        @param name:     Name of the module

        @rtype:          Boolean
        @return:         Whether the module has been loaded yet
        """

        for loaded_module in self.loaded_modules:
            if loaded_module['name'] == name:
                return True
        return False

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init_modules(self):
        """
        Initial load of modules. All modules not already loaded will get 
        initialized and started.
        """

        for module_name in self.get_directories():
            if not self.is_module_loaded(module_name):
                mod = self.__load_module_by_name(module_name)
                if mod != None:
                    try:
                        mod["instance"].start()
                        self.loaded_modules.append(mod)
                    except Exception, ex:
                        syslog.syslog(syslog.LOG_ERR,
                                      'failed to load module: ' + \
                                       mod["name"] + " (%s)" % str(ex))

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def unload_module(self, module):
        """
        Unload a module. This is done by fetching the instance of each module
        from the loaded modules list and call the stop() method of the module.
        Once the module is stopped it gets removed from the list of loaded
        modules.

        @type  module:   Dictionary
        @param module:   A dictionary representing a loaded module

        @rtype:          Boolean
        @return:         Whether the module has been unloaded or not
        """

        syslog.syslog(syslog.LOG_INFO, 'unloading module: ' + module["name"])
        try:
            while module["instance"].is_running():
                module["instance"].stop()
                time.sleep(1)
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, 'failed to stop module: ' + \
                              module["name"] + " (%s)" % str(ex))
            return False
        return True

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def unload_modules(self):
        """
        Unload all modules. This is done by calling unload_module() and 
        passing the details of the module to be unloaded.
        """

        unloaded = []
        for module in self.loaded_modules:
            if self.unload_module(module): unloaded.append(module)

        for module in unloaded:
            self.loaded_modules.remove(module)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def load_module(self, module):
        """
        Load a single module defined by _module_. The name of the module is 
        extracted and passed to __load_module_by_name() to get it loaded.

        @type  module:   Dictionary
        @param module:   A dictionary representing a loaded module

        @rtype:          Boolean
        @return:         Whether the module has been loaded or not
        """

        try:
            n_mod = self.__load_module_by_name(module["name"])
            n_mod["instance"].start()
            self.loaded_modules.append(n_mod)
            return True
        except Exception, ex:
            syslog.syslog(syslog.LOG_ERR, 'failed to load module: ' + \
                               module["name"] + " (%s)" % str(ex))
            return False

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def update_modules(self):
        """
        Reload modules which have been modified. 
        """

        for module in self.loaded_modules:
            modtime = os.path.getmtime(self.modules_dir + "/" + \
                                       module["name"]) * 1000000
            if module["mtime"] != modtime:
                syslog.syslog(syslog.LOG_WARNING,
                              'module ' + module["name"] + \
                              ' changed, reloading')

                self.unload_module(module)

                if self.is_module_loaded(module["name"]):
                    syslog.syslog(syslog.LOG_ERR,
                                  "failed to reload module: %s" %
                                  module["name"])
                    continue

                self.load_module(module)

        l_mod_list = []
        for module in self.loaded_modules:
            l_mod_list.append(module['name'])

        for module_name in self.get_directories():
            if module_name not in l_mod_list:
                self.load_module(module_name)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __load_module_by_name(self, name):
        """
        Load a module specified by its name.

        @type  name:     String
        @param name:     Name of the module to be loaded

        @rtype:          Mixed
        @return:         None = not loaded, Dictionary = loaded module
        """

        if self.is_module_loaded(name):
            syslog.syslog(syslog.LOG_WARNING, 
                          name + ' module already loaded, skipping')
            return None

        counter = 1
        while self.lock and counter < 10:
            time.sleep(1)
            counter += 1

        self.lock = True

        syslog.syslog(syslog.LOG_INFO, "loading module " + name)
        module_dir = self.modules_dir + "/" + name
        if not os.path.isdir(module_dir):
            syslog.syslog(syslog.LOG_ERR, 'module ' + name + ' not found')
            return None

        l_mod = None
        try:
            sys.path.append(module_dir)
            l_mod = __import__(name, fromlist=[name])
            l_mod = reload(l_mod)
            sys.path.remove(module_dir)
        except Exception as ex:
            syslog.syslog(syslog.LOG_ERR,
                          "failed to import module " + name +\
                          " (%s)" % str(ex))
            self.lock = False
            return None

        mod_details = None

        try:
            l_class = getattr(l_mod, name)
            l_inst = l_class(self.root, self.config)
            mod_details = l_inst.descriptor()
            mod_details["name"] = name
            mod_details["mtime"] = os.path.getmtime(self.modules_dir + "/" + \
                                                    name) * 1000000
            mod_details["instance"] = l_inst
        except Exception as ex:
            syslog.syslog(syslog.LOG_ERR,
                          "failed to load module " + name + " (%s)" % str(ex))

        syslog.syslog(syslog.LOG_INFO, "module loaded: " + str(mod_details))
        self.lock = False
        return mod_details

