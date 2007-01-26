import re
import sys
import zlib
import time
import socket
import cPickle
import threading
import BaseHTTPServer

import pedrpc
import pgraph
import sex

########################################################################################################################
class extension_shell:
    def __init__ (self, *args, **kwargs):
        pass

    def __getattr__ (self, name):
        return False

    def alive (self):
        return False

    def post_send (self, *args, **kwargs):
        return True

    def pre_send (self, *args, **kwargs):
        return True


########################################################################################################################
class target:
    '''
    Target descriptor container.
    '''

    def __init__ (self, host, port, **kwargs):
        '''
        @type  host:             String
        @param host:             Hostname or IP address of target system
        @type  port:             Integer
        @param port:             Port of target service
        @type  netmon_host:      String
        @param netmon_host:      (Optional, def=None) Hostname or IP address of network monitor for this target
        @type  netmon_port:      Integer
        @param netmon_port:      (Optional, def=26001) Listening port of network monitor on this target
        @type  procmon_host:     String
        @param procmon_host:     (Optional, def=None) Hostname or IP address of process monitor for this target
        @type  procmon_port:     Integer
        @param procmon_port:     (Optional, def=26002) Listening port of process monitor on this target
        @type  proc_name:        String
        @param proc_name:        (Required for procmon) Target process name to monitor
        @type  stop_commands:    List
        @param stop_commands:    (Required for procmon) List of commands to issue to stop the target process
        @type  start_commands:   List
        @param start_commands:   (Required for procmon) List of commands to issue to start the target process
        @type  restart_interval: Integer
        @param restart_interval: (Optional, def=0) Restart the target process after n test cases
        '''

        self.host              = host
        self.port              = port
        self.netmon_host       = kwargs.get("netmon_host",      None)
        self.netmon_port       = kwargs.get("netmon_port",      26001)
        self.procmon_host      = kwargs.get("procmon_host",     None)
        self.procmon_port      = kwargs.get("procmon_port",     26002)
        self.proc_name         = kwargs.get("proc_name",        None)
        self.stop_commands     = kwargs.get("stop_commands",    None)
        self.start_commands    = kwargs.get("start_commands",   None)
        self.restart_interval  = kwargs.get("restart_interval", 0)

        # placeholders for established PED-RPC tunnels.
        self.netmon            = extension_shell()
        self.procmon           = extension_shell()


    def pedrpc_connect (self):
        if self.procmon_host:
            try:
                self.procmon = pedrpc.client(self.procmon_host, self.procmon_port)
                self.procmon.set_proc_name(self.proc_name)
                self.procmon.set_stop_commands(self.stop_commands)
                self.procmon.set_start_commands(self.start_commands)
                self.procmon.set_restart_interval(self.restart_interval)
            except:
                sys.stderr.write("Failed connecting to process monitor at %s:%d\n" % (self.procmon_host, self.procmon_port))
                raise Exception

        if self.netmon_host:
            try:
                self.netmon = pedrpc.client(self.netmon_host, self.netmon_port)
            except:
                sys.stderr.write("Failed connecting to network monitor at %s:%d\n" % (self.netmon_host, self.netmon_port))
                raise Exception


########################################################################################################################
class connection (pgraph.edge.edge):
    def __init__ (self, src, dst, callback=None):
        '''
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(node, edge, last_recv, sock)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", last_recv
        contains the data returned from the last socket transmission and sock is the live socket. A callback is also
        useful in situations where, for example, the size of the next pack is specified in the first packet.

        @type  src:      Integer
        @param src:      Edge source ID
        @type  dst:      Integer
        @param dst:      Edge destination ID
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits
        '''

        # run the parent classes initialization routine first.
        pgraph.edge.edge.__init__(self, src, dst)

        self.callback = callback


########################################################################################################################
class session (pgraph.graph):
    def __init__ (self, session_filename, skip=0, sleep_time=1.0, log_level=1, proto="tcp", timeout=5.0, web_port=26000):
        '''
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  session_filename: String
        @param session_filename: Filename to serialize persistant data to
        @type  skip:             Integer
        @param skip:             (Optional, def=0) Number of test cases to skip
        @type  sleep_time:       Float
        @param sleep_time:       (Optional, def=1.0) Time to sleep in between tests
        @type  log_level:        Integer
        @param log_level:        (Optional, def=2) Set the log level, higher number == more log messages
        @type  proto:            String
        @param proto:            (Optional, def="tcp") Communication protocol
        @type  timeout:          Float
        @param timeout:          (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        '''

        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self)

        self.session_filename    = session_filename
        self.skip                = skip
        self.sleep_time          = sleep_time
        self.log_level           = log_level
        self.proto               = proto
        self.timeout             = timeout
        self.web_port            = web_port

        self.total_num_mutations = 0
        self.total_mutant_index  = 0
        self.fuzz_node           = None
        self.targets             = []
        self.netmon_results      = {}
        self.procmon_results     = {}
        self.pause               = False

        if self.proto == "tcp":
            self.proto = socket.SOCK_STREAM
        elif self.proto == "udp":
            self.proto = socket.SOCK_DGRAM
        else:
            raise sex.error("INVALID PROTOCOL SPECIFIED: %s" % self.proto)

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root       = pgraph.node()
        self.root.name  = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv  = None

        self.add_node(self.root)


    def __pause (self):
        '''
        '''

        while 1:
            if self.pause:
                time.sleep(1)
            else:
                break


    def __transmit (self, sock, node, edge, target):
        '''
        Render and transmit a node, process callbacks accordingly. This routine is called internally by fuzz().

        @type  sock:   Socket
        @param sock:   Socket to transmit node on
        @type  node:   Request (Node)
        @param node:   Request/Node to transmit
        @type  edge:   Connection (pgraph.edge)
        @param edge:   Last edge along the current fuzz path to "node"
        @type  target: session.target
        @param target: Target we are transmitting to
        '''

        # if the edge has a callback, process it.
        if edge.callback:
            edge.callback(self, node, edge, self.last_recv)

        self.log("xmitting: [%d.%d]" % (node.id, self.total_mutant_index), level=2)

        try:
            rendered = node.render()
            self.log(self.hex_dump(rendered), level=10)
            sock.send(rendered)

            if self.proto == "tcp":
                # XXX - might have a need to increase this at some point. (possibly make it a class parameter)
                self.last_recv = sock.recv(10000)
            else:
                self.last_recv = ""
        except:
            if target.procmon.alive():
                self.log("socket send failed or timed out, restart target")
                target.procmon.stop_target()
                target.procmon.start_target()
            else:
                self.log("socket send failed or timed out, sleeping for a while")
                time.sleep(10)

        self.log("received: [%d] %s" % (len(self.last_recv), self.last_recv), level=10)


    def add_node (self, node):
        '''
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        @type  node: pGRAPH Node
        @param node: Node to add to session graph
        '''

        node.number = len(self.nodes)
        node.id     = len(self.nodes)

        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node

        return self


    def add_target (self, target):
        '''
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        @type  target: session.target
        @param target: Target to add to session
        '''

        self.targets.append(target)


    def connect (self, src, dst=None, callback=None):
        '''
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. Leverage this functionality to handle situations such as
        challenge response systems. The session class maintains a top level node that all initial requests must be
        connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias and is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        If you register callback method, it must follow this prototype::

            def callback(node, edge, last_recv, sock)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", last_recv
        contains the data returned from the last socket transmission and sock is the live socket. A callback is also
        useful in situations where, for example, the size of the next pack is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        @type  src:      String or Request (Node)
        @param src:      Source request name or request node
        @type  dst:      String or Request (Node)
        @param dst:      Destination request name or request node
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits

        @rtype:  pgraph.edge
        @return: The edge between the src and dst.
        '''

        # if only a source was provided, then make it the destination and set the source to the root node.
        if not dst:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if type(src) is str:
            src = self.find_node("name", src)

        if type(dst) is str:
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
            self.add_node(src)

        if not self.find_node("name", dst.name):
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge


    ####################################################################################################################
    def export_file (self):
        '''
        Dump the entire object structure to disk.

        @see: import_file()
        '''

        # trim out attributes that can't be serialized.
        targets      = self.targets
        self.targets = None

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(cPickle.dumps(self, protocol=2)))
        fh.close()

        # restored trimmed attributes.
        self.targets = targets


    def fuzz (self, this_node=None, path=[]):
        '''
        Call this routine to get the ball rolling. No arguments are necessary as they are both utilized internally
        during the recursive traversal of the session graph.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.
        '''

        # if no node is specified, then we start from the root node and initialize the session.
        if not this_node:
            this_node = self.root

            try:    self.server_init()
            except: return

        # XXX - TODO - complete parallel fuzzing, will likely have to thread out each target
        target = self.targets[0]

        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # the destination node is the one actually being fuzzed.
            self.fuzz_node = self.nodes[edge.dst]
            num_mutations  = self.fuzz_node.num_mutations()

            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            if edge.src != self.root.id:
                path.append(edge)

            current_path  = " -> ".join([self.nodes[e.src].name for e in path])
            current_path += " -> %s" % self.fuzz_node.name

            self.log("current fuzz path: %s" % current_path, 2)
            self.log("fuzzed %d of %d total cases" % (self.total_mutant_index, self.total_num_mutations), 2)

            # loop through all possible mutations of the fuzz node.
            done_with_fuzz_node = False
            while not done_with_fuzz_node:
                # serialize session state to disk.
                self.export_file()

                # if we need to pause, do so.
                self.__pause()

                # if we have exhausted the mutations of the fuzz node, break out of the while(1).
                # note: when mutate() returns False, the node has been reverted to the default (valid) state.
                if not self.fuzz_node.mutate():
                    self.log("all possible mutations for current fuzz node exhausted", 2)
                    done_with_fuzz_node = True

                # make a record in the session that a mutation was made.
                self.total_mutant_index += 1

                # if we don't need to skip the current test case.
                if self.total_mutant_index > self.skip:
                    self.log("fuzzing %d of %d" % (self.fuzz_node.mutant_index, num_mutations), 2)

                    # instruct the debugger/sniffer that we are about to send a new fuzz.
                    target.procmon.pre_send(self.total_mutant_index)
                    target.netmon.pre_send(self.total_mutant_index)

                    # establish a connection to the target.
                    while 1:
                        try:
                            sock = socket.socket(socket.AF_INET, self.proto)
                            sock.settimeout(self.timeout)
                            sock.connect((target.host, target.port))

                            # if the user registered a pre-send function, pass it the sock and let it do the deed.
                            self.pre_send(sock)

                            # if we reached this point, break out of the loop.
                            break
                        except:
                            self.log("failed connecting to %s:%d, restarting target" % (target.host, target.port))
                            target.procmon.stop_target()
                            target.procmon.start_target()

                    # send out valid requests for each node in the current path up to the node we are fuzzing.
                    for e in path:
                        node = self.nodes[e.src]
                        self.__transmit(sock, node, e, target)

                    # now send the current node we are fuzzing.
                    self.__transmit(sock, self.fuzz_node, edge, target)

                    # if the user registered a post-send function, pass it the sock and let it do the deed.
                    self.post_send(sock)

                    # done with the socket.
                    sock.close()

                    # delay in between test cases.
                    time.sleep(self.sleep_time)

                    # check if our fuzz crashed the target.
                    if not target.procmon.post_send():
                        self.log("procmon detected access violation on test case #%d" % self.total_mutant_index)
                        self.procmon_results[self.total_mutant_index] = target.procmon.crash_synopsis()

                    # see how many bytes the sniffer recorded.
                    bytes = target.netmon.post_send()

                    # if netmon is not connected, the shell class container returns True and not an integer.
                    if type(bytes) is int:
                        self.log("netmon captured %d bytes for test case #%d" % (bytes, self.total_mutant_index), 2)
                        self.netmon_results[self.total_mutant_index] = bytes

            # recursively fuzz the remainder of the nodes in the session graph.
            self.fuzz(self.fuzz_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()


    def hex_dump (self, data, addr=0):
        '''
        Return the hex dump of the supplied data starting at the offset address specified.

        @type  data: Raw
        @param data: Data to show hex dump of
        @type  addr: Integer
        @param addr: (Optional, def=0) Offset to start displaying hex dump addresses from

        @rtype:  String
        @return: Hex dump of raw data
        '''

        dump = slice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%04x: " % addr
                slice = ""

            dump  += "%02x " % ord(byte)
            slice += byte
            addr  += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"


    def import_file (self):
        '''
        Load the entire object structure from disk.

        @see: export_file()
        '''

        try:
            fh   = open(self.session_filename, "rb")
            data = cPickle.loads(zlib.decompress(fh.read()))
            fh.close()
        except:
            return

        # update the skip variable to pick up fuzzing from last test case.
        self.skip                = data.total_mutant_index
        self.session_filename    = data.session_filename
        self.sleep_time          = data.sleep_time
        self.log_level           = data.log_level
        self.proto               = data.proto
        self.timeout             = data.timeout
        self.web_port            = data.web_port
        self.total_num_mutations = data.total_num_mutations
        self.total_mutant_index  = data.total_mutant_index
        self.fuzz_node           = data.fuzz_node
        self.netmon_results      = data.netmon_results
        self.procmon_results     = data.procmon_results
        self.pause               = data.pause


    def log (self, msg, level=1):
        '''
        If the log flag is raised, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print msg


    def num_mutations (self, this_node=None, path=[]):
        '''
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member varialbe self.total_num_mutations is updated appropriately by this routine.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.

        @rtype:  Integer
        @return: Total number of mutations in this session.
        '''

        if not this_node:
            this_node                = self.root
            self.total_num_mutations = 0

        for edge in self.edges_from(this_node.id):
            next_node                 = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations


    def post_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.
        pass


    def pre_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run affter to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to tear down the RPC request.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.
        pass


    def server_init (self):
        '''
        Called by fuzz() on first run (not on recursive re-entry) to initialize variables, web interface, etc...
        '''

        # XXX - TODO - expand this when we hvae parallel fuzzing setup.
        target = self.targets[0]

        self.total_mutant_index  = 0
        self.total_num_mutations = self.num_mutations()

        # spawn the web interface.
        t = web_interface_thread(self)
        t.start()

        # establish PED-RPC connections.
        target.pedrpc_connect()


########################################################################################################################
class web_interface_handler (BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        self.session = None


    def commify (self, number):
        number     = str(number)
        processing = 1
        regex      = re.compile(r"^(-?\d+)(\d{3})")

        while processing:
            (number, processing) = regex.subn(r"\1,\2",number)

        return number


    def do_GET (self):
        self.do_everything()


    def do_HEAD (self):
        self.do_everything()


    def do_POST (self):
        self.do_everything()


    def do_everything (self):
        if "pause" in self.path:
            self.session.pause = True

        if "resume" in self.path:
            self.session.pause = False

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if "view_crash" in self.path:
            response = self.view_crash(self.path)
        elif "view_pcap" in self.path:
            response = self.view_pcap(self.path)
        else:
            response = self.view_index()

        self.wfile.write(response)


    def log_error (self, *args, **kwargs):
        pass


    def log_message (self, *args, **kwargs):
        pass


    def version_string (self):
        return "Sulley Fuzz Session"


    def view_crash (self, path):
        test_number = int(path.split("/")[-1])
        return "<html><pre>%s</pre></html>" % self.session.procmon_results[test_number]

    def view_pcap (self, path):
        return path

    def view_index (self):
        response = """
                    <html>
                    <head>
                        <title>Sulley Fuzz Control</title>
                        <style>
                            a:link    {color: #FF8200; text-decoration: none;}
                            a:visited {color: #FF8200; text-decoration: none;}
                            a:hover   {color: #C5C5C5; text-decoration: none;}

                            body
                            {
                                background-color: #000000;
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        12px;
                                color:            #FFFFFF;
                            }

                            td
                            {
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        12px;
                                color:            #A0B0B0;
                            }

                            .fixed
                            {
                                font-family:      Courier New;
                                font-size:        12px;
                                color:            #A0B0B0;
                            }

                            .input
                            {
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        11px;
                                color:            #FFFFFF;
                                background-color: #333333;
                                border:           thin none;
                                height:           20px;
                            }
                        </style>
                    </head>
                    <body>
                    <center>
                    <table border=0 cellpadding=5 cellspacing=0 width=600><tr><td>
                    <!-- begin bounding table -->

                    <table border=0 cellpadding=5 cellspacing=0 width="100%%">
                    <tr bgcolor="#333333">
                        <td><div style="font-size: 20px;">Sulley Fuzz Control</div></td>
                        <td align=right><div style="font-weight: bold; font-size: 20px;">%(status)s</div></td>
                    </tr>
                    <tr bgcolor="#111111">
                        <td colspan=2 align="center">
                            <table border=0 cellpadding=0 cellspacing=5>
                                <tr bgcolor="#111111">
                                    <td><b>Total:</b></td>
                                    <td>%(total_mutant_index)s</td>
                                    <td>of</td>
                                    <td>%(total_num_mutations)s</td>
                                    <td class="fixed">%(progress_total_bar)s</td>
                                    <td>%(progress_total)s</td>
                                </tr>
                                <tr bgcolor="#111111">
                                    <td><b>%(current_name)s:</b></td>
                                    <td>%(current_mutant_index)s</td>
                                    <td>of</td>
                                    <td>%(current_num_mutations)s</td>
                                    <td class="fixed">%(progress_current_bar)s</td>
                                    <td>%(progress_current)s</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <form method=get action="/pause">
                                <input class="input" type="submit" value="Pause">
                            </form>
                        </td>
                        <td align=right>
                            <form method=get action="/resume">
                                <input class="input" type="submit" value="Resume">
                            </form>
                        </td>
                    </tr>
                    </table>

                    <!-- begin procmon results -->
                    <table border=0 cellpadding=5 cellspacing=0 width="100%%">
                        <tr bgcolor="#333333">
                            <td nowrap>Test Case #</td>
                            <td>Crash Synopsis</td>
                        </tr>
                    """

        keys = self.session.procmon_results.keys()
        keys.sort()
        for key in keys:
            val = self.session.procmon_results[key]
            response += '<tr><td class="fixed"><a href="/view_crash/%d">%06d</a></td><td>%s</td></tr>' % (key, key, val.split("\n")[0])

        response += """
                    <!-- end procmon results -->
                    </table>

                    <!-- end bounding table -->
                    </td></tr></table>
                    </center>
                    </body>
                    </html>
                   """

        # what is the fuzzing status.
        if self.session.pause:
            status = "<font color=red>PAUSED</font>"
        else:
            status = "<font color=green>RUNNING</font>"

        # if there is a current fuzz node.
        if self.session.fuzz_node:
            # which node (request) are we currently fuzzing.
            if self.session.fuzz_node.name:
                current_name = self.session.fuzz_node.name
            else:
                current_name = "[N/A]"

            # render sweet progress bars.
            progress_current     = float(self.session.fuzz_node.mutant_index) / float(self.session.fuzz_node.num_mutations())
            num_bars             = int(progress_current * 40)
            progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (40 - num_bars) + "]"
            progress_current     = "%.3f%%" % (progress_current * 100)

            progress_total       = float(self.session.total_mutant_index) / float(self.session.total_num_mutations)
            num_bars             = int(progress_total * 40)
            progress_total_bar   = "[" + "=" * num_bars + "&nbsp;" * (40 - num_bars) + "]"
            progress_total       = "%.3f%%" % (progress_total * 100)

            response %= \
            {
                "current_mutant_index"  : self.commify(self.session.fuzz_node.mutant_index),
                "current_name"          : current_name,
                "current_num_mutations" : self.commify(self.session.fuzz_node.num_mutations()),
                "progress_current"      : progress_current,
                "progress_current_bar"  : progress_current_bar,
                "progress_total"        : progress_total,
                "progress_total_bar"    : progress_total_bar,
                "status"                : status,
                "total_mutant_index"    : self.commify(self.session.total_mutant_index),
                "total_num_mutations"   : self.commify(self.session.total_num_mutations),
            }
        else:
            response %= \
            {
                "current_mutant_index"  : "",
                "current_name"          : "",
                "current_num_mutations" : "",
                "progress_current"      : "",
                "progress_current_bar"  : "",
                "progress_total"        : "",
                "progress_total_bar"    : "",
                "status"                : "<font color=yellow>UNAVAILABLE</font>",
                "total_mutant_index"    : "",
                "total_num_mutations"   : "",
            }

        return response


########################################################################################################################
class web_interface_server (BaseHTTPServer.HTTPServer):
    '''
    http://docs.python.org/lib/module-BaseHTTPServer.html
    '''

    def __init__(self, server_address, RequestHandlerClass, session):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.RequestHandlerClass.session = session


########################################################################################################################
class web_interface_thread (threading.Thread):
    def __init__ (self, session):
        threading.Thread.__init__(self)

        self.session = session
        self.server  = None


    def run (self):
        self.server = web_interface_server(('', self.session.web_port), web_interface_handler, self.session)
        self.server.serve_forever()