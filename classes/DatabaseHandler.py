"""
Manage the sqlite database used to store crash data.
"""

import json
import sqlite3

class DatabaseHandler:

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def __init__(self, config = None, root = None, job_id = None):

        if config == None or root == None or job_id == None:
            self.dbinit = False
            return

        self.config   = config
        self.root     = root
        self.database = sqlite3.connect(self.root + "/" + self.config["general"]["crash_db"])
        self.cursor   = self.database.cursor()
        self.job_id   = job_id
        self.dbinit   = True

        stmt = "CREATE TABLE IF NOT EXISTS crash_details (job_id text, data text)"
        try:
            self.cursor.execute(stmt)
            self.database.commit()
        except Exception, ex:
            raise Exception(ex)

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def saveCrashDetails(self, data):
        if not self.dbinit: return False
        stmt = "INSERT INTO crash_details VALUES (?, ?)"
        try:
            self.cursor.execute(stmt, (self.job_id, data))
            self.database.commit()
        except Exception, ex:
            raise Exception(ex)

        return True

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    def loadCrashDetails(self):
        if not self.dbinit: return False
        crash_list = []
        stmt = "SELECT * FROM crash_details"
        try:
            for crash_detail in self.cursor.execute(stmt):
                crash_list.append(crash_detail)
        except Exception, ex:
            raise Exception(ex)
        return crash_list

