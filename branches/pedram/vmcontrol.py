#!c:\\python\\python.exe

import os
import sys
import time
import getopt

from sulley import pedrpc

PORT  = 26003
ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
USAGE = "USAGE: vmcontrol.py"                                 \
        "\n    <-x|--vmx FILENAME>   path to VMX to control"  \
        "\n    [-r|--vmrun FILENAME] path to vmrun.exe"


########################################################################################################################
class vmcontrol_pedrpc_server (pedrpc.server):
    def __init__ (self, host, port, vmrun, vmx):
        '''
        @type  host:   String
        @param host:   Hostname or IP address to bind server to
        @type  port:   Integer
        @param port:   Port to bind server to
        @type  vmrun:  String
        @param vmrun:  Path to VMWare vmrun.exe
        @type  vmx:    String
        @param vmx:    Path to VMX file
        '''

        # initialize the PED-RPC server.
        pedrpc.server.__init__(self, host, port)

        self.host      = host
        self.port      = port
        self.vmrun     = vmrun
        self.vmx       = vmx
        self.snap_name = None
        self.log_level = 2

        self.log("VMControl PED-RPC server initialized:")
        self.log("\t vmrun: %s" % self.vmrun)
        self.log("\t vmx:   %s" % self.vmx)
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


    ###
    ### VMRUN COMMAND WRAPPERS
    ###


    def delete_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("deleting snapshot: %s" % snap_name, 2)
        return "".join(os.popen("%s deleteSnapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name)).readlines())


    def list (self):
        self.log("listing running images", 2)
        return "".join(os.popen("%s list" % self.vmrun).readlines()[1:])


    def list_snapshots (self):
        self.log("listing snapshots", 2)
        return "".join(os.popen("%s listSnapshots %s" % (self.vmrun, self.vmx)).readlines()[1:])


    def reset (self):
        self.log("resetting image", 2)
        return "".join(os.popen("%s reset %s" % (self.vmrun, self.vmx)).readlines())


    def revert_to_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("reverting to snapshot: %s" % snap_name, 2)
        return "".join(os.popen("%s revertToSnapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name)).readlines())


    def snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("taking snapshot: %s" % snap_name, 2)
        return "".join(os.popen("%s snapshot %s \"%s\"" % (self.vmrun, self.vmx, snap_name)).readlines())


    def start (self):
        self.log("starting image", 2)
        return "".join(os.popen("%s start %s" % (self.vmrun, self.vmx)).readlines())


    def stop (self):
        self.log("stopping image", 2)
        return "".join(os.popen("%s stop %s" % (self.vmrun, self.vmx)).readlines())


    def suspend (self):
        self.log("suspending image", 2)
        return "".join(os.popen("%s suspend %s" % (self.vmrun, self.vmx)).readlines())


    ###
    ### EXTENDED COMMANDS
    ###


    def restart_target (self):
        # revert to the specified snapshot and start the image.
        self.revert_to_snapshot()
        self.start()

        # wait for the snapshot to come alive.
        self.wait()


    def wait (self):
        self.log("waiting for vmx to come up: %s" % self.vmx, 2)
        while 1:
            if self.vmx.lower() in self.list().lower():
                break


########################################################################################################################
if __name__ == "__main__":
    # parse command line options.
    try:
        opts, args = getopt.getopt(sys.argv[1:], "x:r:", ["vmx=", "vmrun="])
    except getopt.GetoptError:
        ERR(USAGE)

    vmrun = r"C:\progra~1\vmware\vmware~1\vmrun.exe"
    vmx   = None

    for opt, arg in opts:
        if opt in ("-x", "--vmx"):   vmx   = arg
        if opt in ("-r", "--vmrun"): vmrun = arg

    if not vmx:
        ERR(USAGE)

    servlet = vmcontrol_pedrpc_server("0.0.0.0", PORT, vmrun, vmx)
    servlet.serve_forever()
