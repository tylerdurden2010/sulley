#!c:\\python\\python.exe

import SimpleXMLRPCServer
import xmlrpclib
import threading
import getopt
import time
import sys

import pcapy
import impacket
import impacket.ImpactDecoder


########################################################################################################################
class pcap_thread (threading.Thread):
    def __init__ (self, pcap, pcap_save_path):
        self.pcap    = pcap
        self.decoder = None
        self.dumper  = self.pcap.dump_open(pcap_save_path)
        self.active  = True

        if pcap.datalink() == pcapy.DLT_EN10MB:
            self.decoder = impacket.ImpactDecoder.EthDecoder()
        elif pcap.datalink() == pcapy.DLT_LINUX_SLL:
            self.decoder = impacket.ImpactDecoder.LinuxSLLDecoder()
        else:
            raise Exception

        threading.Thread.__init__(self)


    def run (self):
        while self.active:
            self.pcap.dispatch(0, self.packet_handler)


    def packet_handler (self, header, data):
        self.dumper.dump(header, data)


########################################################################################################################
class expector_xmlrpc_server:
    def __init__ (self, device, filter=""):
        self.device      = device
        self.filter      = filter
        self.pcap        = None
        self.pcap_thread = None

        self.log("XML-RPC server initialized:")
        self.log("\t device:   %s" % self.device)
        self.log("\t filter:   %s" % self.filter)
        self.log("\t log path: %s" % log_path)
        self.log()
        self.log("Awaiting requests...")
        self.log()


    def capture (self, test_case_number, log_path="."):
        self.log("Initializing capture for test cast #%d" % test_case_number)
        try:
            # if there is a previous capture thread, kill it.
            if self.pcap_thread:
                self.stop()

            # open the capture device and set the BPF filter.
            self.pcap = pcapy.open_live(self.device, -1, 1, 100)
            self.pcap.setfilter(self.filter)

            # instantiate the capture thread.
            pcap_log_path = "%s/%d.pcap" % (log_path, test_case_number)
            self.pcap_thread = pcap_thread(self.pcap, pcap_log_path)
            self.pcap_thread.start()

            self.log("PCAP thread instantiated. Logging to: %s" % pcap_log_path)
        except:
            return False

        return True


    def log (self, msg=""):
        print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)


    def retrieve (self, test_case_number, log_path="."):
        self.log("Retrieving capture for test case #%d" % test_case_number)

        pcap_log_path = "%s/%d.pcap" % (self.log_path, test_case_number)
        fh            = open(pcap_log_path, "rb")
        data          = fh.read()

        fh.close()

        return xmlrpclib.Binary(data)


    def set_filter (self, filter):
        self.log("Updating PCAP filter to '%s'" % filter)

        self.filter = filter
        return True


    def stop (self):
        if self.pcap_thread:
            self.log("Stopping active packet capture.")

            self.pcap_thread.active = False
            self.pcap_thread        = None

        return True


########################################################################################################################
lan     = "\\Device\\NPF_{588034E3-0E08-407E-8AD6-136B2407FBB3}"
giga    = "\\Device\\NPF_{22AC54B4-1B06-45C5-A7E0-C911714C4A12}"
bridge  = "\\Device\\NPF_{B49864CA-513F-4CAC-B735-064C1410B3F6}"

i = 0
for dev in pcapy.findalldevs():
    if sys.platform.startswith("win"):
        import _winreg
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet002\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{B49864CA-513F-4CAC-B735-064C1410B3F6}\Connection")
    print "[%d] %s" % (i, dev)
    i += 1

"""
servlet = expector_xmlrpc_server(giga)

xmlrpc_server = SimpleXMLRPCServer.SimpleXMLRPCServer(("localhost", 8888), logRequests=False)
xmlrpc_server.register_instance(servlet)
xmlrpc_server.serve_forever()
"""