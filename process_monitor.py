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

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
USAGE = "USAGE: process_monitor.py"                                                               \
        "\n    <-c|--crash_bin FILENAME> filename to serialize crash bin class to"                 \
        "\n    [-i|--ignore_pid PID]     ignore this PID when searching for the target process"    \
        "\n    [-l|--log_level LEVEL]    log level (default 1), increase for more verbosity"


########################################################################################################################
class debugger_thread (threading.Thread):
    def __init__ (self, process_monitor, proc_name, test_number, ignore_pid=None):
        '''
        Instantiate a new PyDbg instance and register user and access violation callbacks.
        '''
        threading.Thread.__init__(self)

        self.process_monitor  = process_monitor
        self.proc_name        = proc_name
        self.test_number      = test_number
        self.ignore_pid       = ignore_pid

        self.access_violation = False
        self.synopsis         = ""
        self.active           = True
        self.dbg              = pydbg()
        self.pid              = None

        # give this thread a unique name.
        self.setName("%d" % time.time())

        self.process_monitor.log("debugger thread initialized with UID: %s" % self.getName(), 5)

        # set the user callback which is response for checking if this thread has been killed.
        self.dbg.set_callback(USER_CALLBACK_DEBUG_EVENT,  self.dbg_callback_user)
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.dbg_callback_access_violation)


    def dbg_callback_access_violation (self, dbg):
        '''
        Ignore first chance exceptions. Record all unhandled exceptions to the process monitor crash bin and kill
        the target process.
        '''

        # ignore first chance exceptions.
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED

        # raise the access violaton flag.
        self.access_violation = True

        # record the crash to the process monitor crash bin.
        # include the test case number in the "extra" information block.
        self.process_monitor.crash_bin.record_crash(dbg, self.test_number)

        # save the first line of the crash synopsis.
        self.synopsis = self.process_monitor.crash_bin.crash_synopsis().split("\n")[0]

        self.process_monitor.log("debugger thread-%s caught access violaton: '%s'" % (self.getName(), self.synopsis))

        # this instance of pydbg should no longer be accessed, i want to know if it is.
        self.process_monitor.crash_bin.pydbg = None

        # kill the process.
        dbg.terminate_process()


    def dbg_callback_user (self, dbg):
        '''
        The user callback is run roughly every 100 milliseconds (WaitForDebugEvent() timeout from pydbg_core.py). Simply
        check if the active flag was lowered and if so detach from the target process. The thread should then exit.
        '''

        if not self.active:
            self.process_monitor.log("debugger thread-%s detaching" % self.getName(), 5)
            dbg.detach()

        return DBG_CONTINUE


    def run (self):
        '''
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        '''

        self.process_monitor.log("debugger thread-%s looking for process name: %s" % (self.getName(), self.proc_name))

        # watch for the target process.
        while not self.pid:
            for (pid, name) in self.dbg.enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break

        self.process_monitor.log("debugger thread-%s found match on pid %d" % (self.getName(), self.pid))
        self.dbg.attach(self.pid)
        self.dbg.run()
        self.process_monitor.log("debugger thread-%s exiting" % self.getName())

        # XXX - removing the following line appears to cause some concurrency issues.
        del(self.dbg)


########################################################################################################################
class process_monitor_xmlrpc_server:
    def __init__ (self, crash_filename, ignore_pid=None, log_level=1):
        '''
        @type  crash_filename: String
        @param crash_filename: Name of file to (un)serialize crash bin to/from
        @type  ignore_pid:     Integer
        @param ignore_pid:     (Optional, def=None) Ignore this PID when searching for the target process
        @type  log_level:      Integer
        @param log_level:      (Optional, def=1) Log output level, increase for more verbosity
        '''

        self.crash_filename   = crash_filename
        self.ignore_pid       = ignore_pid
        self.log_level        = log_level

        self.proc_name        = None
        self.restart_commands = []
        self.restart_interval = 0
        self.num_tests        = 0
        self.debugger_thread  = None
        self.crash_bin        = utils.crash_binning.crash_binning()

        # restore any previously recorded crashes.
        try:
            self.crash_bin.import_file(self.crash_filename)
        except:
            pass

        self.log("Process Monitor XML-RPC server initialized:")
        self.log("\t record file: %s" % self.crash_filename)
        self.log("\t # records:   %d" % len(self.crash_bin.bins))
        self.log("\t log level:   %d" % self.log_level)
        self.log("awaiting requests...")


    def __kill_debugger_thread (self):
        self.log("killing debugger thread...")
        if self.debugger_thread:
            self.debugger_thread.active = False
            self.debugger_thread        = None

        return True


    def alive (self):
        '''
        Returns True. Useful for XML-RPC clients who want to see if the XML-RPC connection is still alive.
        '''

        return True


    def crash_synopsis (self):
        '''
        Return the first line of the last recorded crash synopsis.

        @rtype:  String
        @return: First line of crash synopsis
        '''

        if not self.debugger_thread:
            return ""
        else:
            return self.debugger_thread.synopsis


    def get_bin_keys (self):
        return self.crash_bin.bins.keys()


    def get_bin (self, bin):
        if not self.crash_bin.bins.has_key(bin):
            return False

        return self.crash_bin.bins[bin]


    def log (self, msg="", level=1):
        '''
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)

        # gotta return something for XML-RPC.
        return True


    def post_send (self):
        '''
        Check on the status of the target. Return True if the target is still active, False otherwise.
        '''

        av = self.debugger_thread.access_violation

        if av:
            self.debugger_thread = None
            self.restart_target()

        # serialize the crash bin to disk.
        self.crash_bin.export_file(self.crash_filename)

        bins    = len(self.crash_bin.bins)
        crashes = 0

        for bin in self.crash_bin.bins.keys():
            crashes += len(self.crash_bin.bins[bin])

        self.log("crash bin contains %d bins with %d entries" % (bins, crashes), 3)

        return not av


    def pre_send (self, test_number):
        '''
        Ensure the debugger thread is operational and increment the test count. If the restart interval is reached,
        restart the target process before continuing.
        '''

        self.log("pre_send(%d)" % test_number, 10)

        # if we don't already have a debugger thread, instantiate and start one now.
        if not self.debugger_thread or not self.debugger_thread.isAlive():
            self.log("creating debugger thread", 5)
            self.debugger_thread = debugger_thread(self, self.proc_name, test_number, self.ignore_pid)
            self.debugger_thread.start()
            self.log("giving debugger thread 2 seconds to settle in", 5)
            time.sleep(2)

        self.num_tests += 1

        # if we've hit the restart interval, restart the target process.
        if self.restart_interval and self.num_tests % self.restart_interval == 0:
            self.log("restart interval of %d reached" % self.restart_interval)
            self.restart_target()

        return True


    def restart_target (self):
        '''
        Kill the debugger thread and restart the target process by sequentially executing the self.restart_commands[].
        '''

        # kill the debugger thread.
        self.__kill_debugger_thread()

        # give the debugger thread a chance to exit.
        time.sleep(1)

        self.log("restarting target process")

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
        self.log("updating target process name to '%s'" % proc_name)

        self.proc_name = proc_name
        return True


    def set_restart_commands (self, restart_commands):
        self.log("updating restart command tos: %s" % restart_commands)

        self.restart_commands = restart_commands
        return True


    def set_restart_interval (self, restart_interval):
        self.log("updating restart interval to: %d" % restart_interval)

        self.restart_interval = restart_interval
        return True


########################################################################################################################

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "c:i:l:", ["crash_bin=", "ignore_pid=", "log_level="])
except getopt.GetoptError:
    ERR(USAGE)

crash_bin = ignore_pid = None
log_level = 1

for opt, arg in opts:
    if opt in ("-c", "--crash_bin"):   crash_bin  = arg
    if opt in ("-i", "--ignore_pid"):  ignore_pid = int(arg)
    if opt in ("-l", "--log_level"):   log_level  = int(arg)

if not crash_bin:
    ERR(USAGE)

# spawn the XML-RPC servlet.
servlet = process_monitor_xmlrpc_server(crash_bin, ignore_pid, log_level)

# define a custom error routine for XML-RPC exceptions.
def xmlrpc_server_error (request, client_address):
    print "shit hit the fan!"
    print request
    print client_address
    pass

# spawn a new XML-RPC server container, register our servlet and serve forever.
xmlrpc_server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 26002), logRequests=False)
xmlrpc_server.handle_error = xmlrpc_server_error
xmlrpc_server.register_instance(servlet)
xmlrpc_server.serve_forever()