""" Define event codes. """

__author__     = "Zsolt Imre"
__copyright__  = "Copyright 2015, Zsolt Imre / DCNWS / FuzzLabs"
__license__    = "GPLv2"
__version__    = "2.0.0"
__maintainer__ = "Zsolt Imre"
__email__      = "imrexzsolt@gmail.com"
__status__     = "Development"

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------

class Event:
    """ Group event codes under a single class. """

    class EVENT_DEBUG: pass
    class EVENT_GENERAL: pass
    class EVENT_ALERT: pass
    class EVENT__REQ_JOBS_LIST: pass
    class EVENT__RSP_JOBS_LIST: pass
    class EVENT__REQ_JOB_STATUS: pass
    class EVENT__RSP_JOB_STATUS: pass
    class EVENT__REQ_JOB_PAUSE: pass
    class EVENT__REQ_JOB_RESUME: pass
    class EVENT__REQ_ISSUES_LIST: pass
    class EVENT__RSP_ISSUES_LIST: pass
    class EVENT__REQ_JOB_DELETE: pass
    class EVENT__REQ_ARCHIVES_LIST: pass
    class EVENT__RSP_ARCHIVES_LIST: pass
    class EVENT__REQ_ARCHIVES_START: pass
    class EVENT__RSP_ARCHIVES_START: pass
    class EVENT__REQ_ARCHIVES_RESTART: pass
    class EVENT__RSP_ARCHIVES_RESTART: pass
    class EVENT__REQ_ARCHIVES_DELETE: pass
    class EVENT__RSP_ARCHIVES_DELETE: pass

