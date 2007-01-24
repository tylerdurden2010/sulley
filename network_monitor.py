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

IFS   = []
ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
USAGE = "USAGE: network_monitor.py"                                                                \
        "\n    <-d|--device DEVICE #>    device to sniff on (see list below)"                      \
        "\n    [-f|--filter PCAP FILTER] BPF filter string"                                        \
        "\n    [-p|--log_path PATH]      log directory to store pcaps to"                          \
        "\n    [-l|--log_level LEVEL]    log level (default 1), increase for more verbosity"       \
        "\n\nNetwork Device List:\n"

# add the device list to the usage string.
i = 0
for dev in pcapy.findalldevs():
    IFS.append(dev)
    if sys.platform.startswith("win"):
        import _winreg

        try:
            dev = dev[dev.index("{"):dev.index("}")+1]

            key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % dev)

            try:    ip = _winreg.QueryValueEx(key, "DhcpIPAddress")[0]
            except: ip = _winreg.QueryValueEx(key, "IPAddress")[0][0]

            dev = dev + "\t" + ip
        except:
            pass

    USAGE += "    [%d] %s\n" % (i, dev)
    i += 1


########################################################################################################################
class pcap_thread (threading.Thread):
    def __init__ (self, network_monitor, pcap, pcap_save_path):
        self.network_monitor = network_monitor
        self.pcap            = pcap

        self.decoder         = None
        self.dumper          = self.pcap.dump_open(pcap_save_path)
        self.active          = True
        self.data_bytes      = 0

        if pcap.datalink() == pcapy.DLT_EN10MB:
            self.decoder = impacket.ImpactDecoder.EthDecoder()
        elif pcap.datalink() == pcapy.DLT_LINUX_SLL:
            self.decoder = impacket.ImpactDecoder.LinuxSLLDecoder()
        else:
            raise Exception

        threading.Thread.__init__(self)


    def packet_handler (self, header, data):
        # add the captured data to the PCAP.
        self.dumper.dump(header, data)

        # increment the captured byte count.
        self.data_bytes += len(data)

        # log the decoded data at the appropriate log level.
        self.network_monitor.log(self.decoder.decode(data), 15)


    def run (self):
        # process packets while the active flag is raised.
        while self.active:
            self.pcap.dispatch(0, self.packet_handler)


########################################################################################################################
class network_monitor_xmlrpc_server:
    def __init__ (self, device, filter="", log_path="./", log_level=1):
        '''
        @type  device:      String
        @param device:      Name of device to capture packets on
        @type  ignore_pid:  Integer
        @param ignore_pid:  (Optional, def=None) Ignore this PID when searching for the target process
        @type  log_path:    String
        @param log_path:    (Optional, def="./") Path to save recorded PCAPs to
        @type  log_level:   Integer
        @param log_level:   (Optional, def=1) Log output level, increase for more verbosity
        '''

        self.device      = device
        self.filter      = filter
        self.log_path    = log_path
        self.log_level   = log_level

        self.pcap        = None
        self.pcap_thread = None

        self.log("Network Monitor XML-RPC server initialized:")
        self.log("\t device: %s" % self.device)
        self.log("\t filter: %s" % self.filter)
        self.log("Awaiting requests...")


    def __stop (self):
        if self.pcap_thread:
            self.log("stopping active packet capture thread.", 10)

            self.pcap_thread.active = False
            self.pcap_thread        = None

        return True


    def post_send (self):
        '''
        Return the number of bytes captured.
        '''

        # grab the number of recorded bytes.
        data_bytes = self.pcap_thread.data_bytes

        # stop the packet capture thread.
        self.__stop()

        self.log("stopped PCAP thread, snagged %d bytes of data" % data_bytes)
        return data_bytes


    def pre_send (self, test_number):
        '''
        Spin off a packet capture thread.
        '''

        self.log("initializing capture for test cast #%d" % test_number)

        # open the capture device and set the BPF filter.
        self.pcap = pcapy.open_live(self.device, -1, 1, 100)
        self.pcap.setfilter(self.filter)

        # instantiate the capture thread.
        pcap_log_path = "%s/%d.pcap" % (self.log_path, test_number)
        self.pcap_thread = pcap_thread(self, self.pcap, pcap_log_path)
        self.pcap_thread.start()

        self.log("PCAP thread instantiated. logging to: %s" % pcap_log_path)
        return True


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


    def retrieve (self, test_number):
        self.log("retrieving PCAP for test case #%d" % test_number)

        pcap_log_path = "%s/%d.pcap" % (self.log_path, test_number)
        fh            = open(pcap_log_path, "rb")
        data          = fh.read()
        fh.close()

        return xmlrpclib.Binary(data)


    def set_filter (self, filter):
        self.log("updating PCAP filter to '%s'" % filter)

        self.filter = filter
        return True


    def set_log_path (self, log_path):
        self.log("updating log path to '%s'" % log_path)

        self.log_path = log_path
        return True


########################################################################################################################

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "d:f:p:l:", ["device=", "filter=", "log_path=", "log_level="])
except getopt.GetoptError:
    ERR(USAGE)

device    = None
filter    = ""
log_path  = "./"
log_level = 1

for opt, arg in opts:
    if opt in ("-d", "--device"):     device    = IFS[int(arg)]
    if opt in ("-f", "--filter"):     filter    = arg
    if opt in ("-p", "--log_path"):   log_path  = arg
    if opt in ("-l", "--log_level"):  log_level = int(arg)

if not device:
    ERR(USAGE)

servlet = network_monitor_xmlrpc_server(device, filter, log_path, log_level)

xmlrpc_server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 26001), logRequests=False)
xmlrpc_server.register_instance(servlet)
xmlrpc_server.serve_forever()