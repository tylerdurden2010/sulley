#!c:\\python\\python.exe

import SimpleXMLRPCServer
import xmlrpclib
import threading
import getopt
import time
import sys
import os

sys.path.append(r"..\..\..\paimei")

from pydbg         import *
from pydbg.defines import *

import utils

########################################################################################################################
class debugger_thread (threading.Thread):
    def __init__ (self, process_monitor, proc_name, record_path, test_number, ignore_pid=None):
        threading.Thread.__init__(self)

        self.process_monitor  = process_monitor
        self.proc_name        = proc_name
        self.record_path      = record_path
        self.test_number      = test_number
        self.ignore_pid       = ignore_pid
        self.target_destroyed = False

        self.active           = True
        self.dbg              = pydbg()
        self.pid              = None

        self.setName("%d" % test_number)

        # set the user callback which is response for checking if this thread has been killed.
        self.dbg.set_callback(USER_CALLBACK_DEBUG_EVENT,  self.dbg_callback_user)
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.dbg_callback_access_violation)

        print "%s: Looking for target process" % self.getName()

        # watch for the target process.
        while not self.pid:
            for (pid, name) in self.dbg.enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break


    def dbg_callback_access_violation (self, dbg):
        # ignore first chance exceptions.
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED
        
        print "%s: ***********************************************"  % self.getName()

        # null out the debugger thread handle in the server.
        #self.process_monitor.debugger_thread = None

        # let the server know that the target died.
        #self.process_monitor.target_destroyed = True
        self.target_destroyed = True

        try:
            crash_bin = utils.crash_binning.crash_binning()
            crash_bin.record_crash(dbg)
            print crash_bin.crash_synopsis()
        except:
            pass

        dbg.terminate_process()

        #dbg.terminate_process(method="exitprocess")
        #return DBG_CONTINUE


    def dbg_callback_user (self, dbg):
        if not self.active:
            print "%s: Detaching..." % self.getName()
            dbg.detach()

        return DBG_CONTINUE


    def run (self):
        print "%s: Found %s on %d, attaching..." % (self.getName(), self.proc_name, self.pid)        
        self.dbg.attach(self.pid)
        self.dbg.run()
        print "%s: Debugger detached, thread exiting." % self.getName()
        
        # null out the debugger thread handle in the server.
        #print "%s: Setting debugger thread to None" % self.getName()
        #self.process_monitor.debugger_thread = None


########################################################################################################################
class process_monitor_xmlrpc_server:
    def __init__ (self, record_path, ignore_pid=None, log_level=1):
        self.record_path      = record_path
        self.ignore_pid       = ignore_pid
        self.log_level        = log_level

        self.proc_name        = None
        self.restart_commands = []
        self.restart_interval = 0
        self.num_records      = 0
        self.debugger_thread  = None
        #self.target_destroyed = False

        self.log("Process Monitor XML-RPC server initialized:")
        self.log("\t record path: %s" % self.record_path)
        self.log("\t log level:   %d" % self.log_level)
        self.log()
        self.log("Awaiting requests...")
        self.log()


    def __stop (self):
        if self.debugger_thread:
            self.log("Stopping debugger thread.")

            self.debugger_thread.active = False
            self.debugger_thread        = None

        return True


    def is_target_destroyed (self):
        #return self.target_destroyed
        return self.debugger_thread.target_destroyed


    def log (self, msg="", level=1):
        '''
        If the log flag is raised, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)
        
        return True


    def record (self, test_number):
        self.log("Recording test #%d" % test_number)

        # if we don't already have a debugger thread, instantiate and start one now.
        if not self.debugger_thread:
            self.log("Starting initial debugger thread")
            self.debugger_thread = debugger_thread(self, self.proc_name, self.record_path, test_number, self.ignore_pid)
            self.debugger_thread.start()
        elif not self.debugger_thread.isAlive():
            if self.debugger_thread.target_destroyed:
                self.restart_target()
                #self.target_destroyed = False
                print "target process reset"

            self.log("Starting new debugger thread")
            self.debugger_thread = debugger_thread(self, self.proc_name, self.record_path, test_number, self.ignore_pid)
            self.debugger_thread.start()
            self.log("sleeping for 5 secs")
            time.sleep(5)
                
        self.num_records += 1

        # if we've hit the restart interval, restart the target process.
        if self.restart_interval and self.num_records % self.restart_interval == 0:
            print "Reached restart interval"
            self.restart_target()

        self.log("Recording underway")

        return True


    def restart_target (self):
        self.log("Restarting target process")
        self.__stop()

        if self.restart_commands:
            for command in self.restart_commands:
                if command == "TERMINATE_PID":
                    dbg = pydbg()
                    for (pid, name) in dbg.enumerate_processes():
                        if name.lower() == self.proc_name.lower():
                            os.system("taskkill /pid %d" % pid)
                            break
                else:
                    os.system(command)

        return True


    def set_proc_name (self, proc_name):
        self.log("Updating target process name to '%s'" % proc_name)

        self.proc_name = proc_name
        return True


    def set_restart_commands (self, restart_commands):
        self.log("Updating restart command tos: %s" % restart_commands)

        self.restart_commands = restart_commands
        return True


    def set_restart_interval (self, restart_interval):
        self.log("Updating restart interval to: %d" % restart_interval)

        self.restart_interval = restart_interval
        return True


########################################################################################################################
# XXX - TODO - add getopt for log path and ignore_pid.
servlet = process_monitor_xmlrpc_server("./records", ignore_pid=None)

xmlrpc_server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 26002), logRequests=False)
xmlrpc_server.register_instance(servlet)
xmlrpc_server.serve_forever()