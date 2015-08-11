#!/usr/bin/python

""" Initialize environment for the daemon """

import os
import sys
import inspect
from daemon import runner

from classes import ConfigurationHandler as ch
from classes import FuzzlabsDaemon as fd

__author__     = "Zsolt Imre"
__copyright__  = "Copyright 2015, Zsolt Imre / DCNWS / FuzzLabs"
__license__    = "GPLv2"
__version__    = "1.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    CONFIG = None
    DAEMON = None

    ROOT_DIR = os.path.dirname(
                    os.path.abspath(
                        inspect.getfile(inspect.currentframe()
                    )))

    try:
        CONFIG = ch.ConfigurationHandler(ROOT_DIR + "/etc/fuzzlabs.config")
    except Exception, ex:
        print "[e] failed to load configuration: %s" % str(ex)
        sys.exit(1)

    try:
        DAEMON = fd.FuzzlabsDaemon(ROOT_DIR, CONFIG.get())
    except Exception, ex:
        print "[e] failed initialize daemon: %s" % str(ex)
        sys.exit(1)

    try:
        DAEMON_RUNNER = runner.DaemonRunner(DAEMON)
        DAEMON_RUNNER.do_action()
    except Exception, ex:
        print "[e] failed to start/stop daemon: %s" % str(ex)

