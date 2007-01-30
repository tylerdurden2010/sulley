#!c:\\python\\python.exe

import os
import sys
import time
import getopt

from sulley import pedrpc

PORT  = 26003
ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
USAGE = "USAGE: vmcontrol.py"                                  \
        "\n    <-x|--vmx FILENAME>    path to VMX to control"  \
        "\n    <-r|--vmrun FILENAME>  path to vmrun.exe"       \
        "\n    [-s|--snapshot NAME>   set the snapshot name"   \
        "\n    [-l|--log_level LEVEL] log level (default 1), increase for more verbosity"


########################################################################################################################
class vmcontrol_pedrpc_server (pedrpc.server):
    def __init__ (self, host, port, vmrun, vmx, snap_name=None, log_level=1):
        '''
        @type  host:      String
        @param host:      Hostname or IP address to bind server to
        @type  port:      Integer
        @param port:      Port to bind server to
        @type  vmrun:     String
        @param vmrun:     Path to VMWare vmrun.exe
        @type  vmx:       String
        @param vmx:       Path to VMX file
        @type  snap_name: String
        @param snap_name: (Optional, def=None) Snapshot name to revert to on restart
        @type  log_level: Integer
        @param log_level: (Optional, def=1) Log output level, increase for more verbosity
        '''

        # initialize the PED-RPC server.
        pedrpc.server.__init__(self, host, port)

        self.host      = host
        self.port      = port
        self.vmrun     = vmrun
        self.vmx       = vmx
        self.snap_name = snap_name
        self.log_level = log_level

        self.log("VMControl PED-RPC server initialized:")
        self.log("\t vmrun:     %s" % self.vmrun)
        self.log("\t vmx:       %s" % self.vmx)
        self.log("\t snap name: %s" % self.snap_name)
        self.log("\t log level: %d" % self.log_level)
        self.log("Awaiting requests...")


    def alive (self):
        '''
        Returns True. Useful for PED-RPC clients who want to see if the PED-RPC connection is still alive.
        '''

        return True


    def log (self, msg="", level=1):
        '''
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)


    def set_vmrun (self, vmrun):
        self.log("setting vmrun to %s" % vmrun, 2)
        self.vmrun = vmrun


    def set_vmx (self, vmx):
        self.log("setting vmx to %s" % vmx, 2)
        self.vmx = vmx


    def set_snap_name (self, snap_name):
        self.log("setting snap_name to %s" % snap_name, 2)
        self.snap_name = snap_name


    def vmcommand (self, command):
        '''
        Execute the specified command, keep trying in the event of a failure.

        @type  command: String
        @param command: VMRun command to execute
        '''

        while 1:
            self.log("executing: %s" % command, 5)

            pipe = os.popen(command)
            out  = pipe.readlines()
            pipe.close()

            if not out:
                break
            elif not out[0].lower().startswith("close failed"):
                break

            self.log("failed executing command '%s' (%s). will try again." % (command, out))
            time.sleep(1)

        return "".join(out)


    ###
    ### VMRUN COMMAND WRAPPERS
    ###


    def delete_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("deleting snapshot: %s" % snap_name, 2)
        return self.vmcommand("%s deleteSnapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name))


    def list (self):
        self.log("listing running images", 2)
        return self.vmcommand("%s list" % self.vmrun)


    def list_snapshots (self):
        self.log("listing snapshots", 2)
        return self.vmcommand("%s listSnapshots %s" % (self.vmrun, self.vmx))


    def reset (self):
        self.log("resetting image", 2)
        return self.vmcommand("%s reset %s" % (self.vmrun, self.vmx))


    def revert_to_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("reverting to snapshot: %s" % snap_name, 2)
        return self.vmcommand("%s revertToSnapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name))


    def snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("taking snapshot: %s" % snap_name, 2)
        return self.vmcommand("%s snapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name))


    def start (self):
        self.log("starting image", 2)
        return self.vmcommand("%s start %s" % (self.vmrun, self.vmx))


    def stop (self):
        self.log("stopping image", 2)
        return self.vmcommand("%s stop %s" % (self.vmrun, self.vmx))


    def suspend (self):
        self.log("suspending image", 2)
        return self.vmcommand("%s suspend %s" % (self.vmrun, self.vmx))


    ###
    ### EXTENDED COMMANDS
    ###


    def restart_target (self):
        self.log("restarting virtual machine...")
        # revert to the specified snapshot and start the image.
        self.revert_to_snapshot()
        self.start()

        # wait for the snapshot to come alive.
        self.wait()


    def is_target_running (self):
        return self.vmx.lower() in self.list().lower()


    def wait (self):
        self.log("waiting for vmx to come up: %s" % self.vmx)
        while 1:
            if self.is_target_running():
                break


########################################################################################################################
if __name__ == "__main__":
    # parse command line options.
    try:
        opts, args = getopt.getopt(sys.argv[1:], "x:r:s:l:", ["vmx=", "vmrun=", "snapshot=", "log_level="])
    except getopt.GetoptError:
        ERR(USAGE)

    vmrun     = r"C:\progra~1\vmware\vmware~1\vmrun.exe"
    vmx       = None
    snap_name = None
    log_level = 1

    for opt, arg in opts:
        if opt in ("-x", "--vmx"):       vmx       = arg
        if opt in ("-r", "--vmrun"):     vmrun     = arg
        if opt in ("-s", "--snapshot"):  snap_name = arg
        if opt in ("-l", "--log_level"): log_level = int(arg)

    if not vmx:
        ERR(USAGE)

    servlet = vmcontrol_pedrpc_server("0.0.0.0", PORT, vmrun, vmx, snap_name, log_level)
    servlet.serve_forever()
