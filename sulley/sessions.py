import re
import time
import socket
import xmlrpclib
import threading
import BaseHTTPServer

import pgraph
import sex

########################################################################################################################
class target:
    '''
    Basic data structure
    '''

    def __init__ (self, host, port, netmon_host=None, netmon_port=26001, procmon_host=None, procmon_port=26002):
        '''
        @type  host:         String
        @param host:         Hostname or IP address of target system
        @type  port:         Integer
        @param port:         Port of target service
        @type  netmon_host:  String
        @param netmon_host:  (Optional, def=None) Hostname or IP address of network monitor for this target
        @type  netmon_port:  Integer
        @param netmon_port:  (Optional, def=26001) Listening port of network monitor on this target
        @type  procmon_host: String
        @param procmon_host: (Optional, def=None) Hostname or IP address of process monitor for this target
        @type  procmon_port: Integer
        @param procmon_port: (Optional, def=26002) Listening port of process monitor on this target
        '''

        self.host         = host
        self.port         = port
        self.netmon_host  = netmon_host
        self.netmon_port  = netmon_port
        self.procmon_host = procmon_host
        self.procmon_port = procmon_port


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
    def __init__ (self, session_name, skip=0, sleep_time=3.0, log_level=1, proto="tcp", timeout=5.0, web_port=26000):
        '''
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  session_name: String
        @param session_name: Name of this fuzz session. Used in creation of log files, expector pcaps and debugger traces
        @type  skip:         Integer
        @param skip:         (Optional, def=0) Number of test cases to skip
        @type  sleep_time:   Float
        @param sleep_time:   (Optional, def=3.0) Time to sleep in between tests
        @type  log_level:    Integer
        @param log_level:    (Optional, def=1) Set the log level, higher number == more log messages
        @type  proto:        String
        @param proto:        (Optional, def="tcp") Communication protocol
        @type  timeout:      Float
        @param timeout:      (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        '''

        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self)

        self.session_name        = session_name
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
        self.pause               = False

        if self.proto == "tcp":
            self.proto = socket.SOCK_STREAM
        elif self.proto == "udp":
            self.proto = socket.SOCK_DGRAM
        else:
            raise sex.error("INVALID PROTOCOL SPECIFIED: %s" % self.proto)

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root       = pgraph.node()
        self.root.name  = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv  = None

        self.add_node(self.root)


    def __fuzz_init (self):
        '''
        Called by fuzz() on first run (not on recursive re-entry) to initialize variables, web interface, etc...
        '''

        self.total_mutant_index  = 0
        self.total_num_mutations = self.num_mutations()

        # spawn the web interface.
        t = web_interface_thread(self)
        t.start()


    def __pause (self):
        '''
        '''

        while 1:
            if self.pause:
                time.sleep(1)
            else:
                break


    def __transmit (self, sock, node, edge):
        '''
        Render and transmit a node, process callbacks accordingly. This routine is called internally by fuzz().

        @type  sock: Socket
        @param sock: Socket to transmit node on
        @type  node: Request (Node)
        @param node: Request/Node to transmit
        @type  edge: Connection (pgraph.edge)
        @param edge: Last edge along the current fuzz path to "node"
        '''

        # if the edge has a callback, process it.
        if edge.callback:
            edge.callback(self, node, edge, self.last_recv)

        self.log("xmitting: [%d]" % (node.id), level=2)

        try:
            rendered = node.render()
            self.log(self.hex_dump(rendered), level=3)
            sock.send(rendered)

            if self.proto == "tcp":
                # XXX - might have a need to increase this at some point. (possibly make it a class parameter)
                self.last_recv = sock.recv(10000)
            else:
                self.last_recv = ""
        except socket.timeout:
            self.log("socket timeout, sleeping for a while")
            time.sleep(10)
        except:
            self.log("socket send failed, sleeping for a while")
            time.sleep(10)

        self.log("received: [%d] %s" % (len(self.last_recv), self.last_recv), level=2)


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


    def connect (self, src, dst, callback=None):
        '''
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. Leverage this functionality to handle situations such as
        challenge response systems. The session class maintains a top level node that all initial requests must be
        connected to. Example::

            sess = sessions.session(target=("127.0.0.1", 80))
            sess.connect(sess.root, s_get("HTTP"))

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
        '''

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
            self.__fuzz_init()

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

            self.log("current fuzz path: %s" % current_path)
            self.log("fuzzed %d of %d total cases" % (self.total_mutant_index, self.total_num_mutations))

            # loop through all possible mutations of the fuzz node.
            while 1:
                # if we need to pause, do so.
                self.__pause()

                # step through each available target and fuzz them in parallel, splitting the test cases between them.
                #for target in self.targets:
                # XXX - TODO - complete parallel fuzzing, will likely have to thread out each target
                target = self.targets[0]

                # if we have exhausted the mutations of the fuzz node, break out of the while(1).
                # note: when mutate() returns False, the node has been reverted to the default (valid) state.
                if not self.fuzz_node.mutate():
                    break

                # make a record in the session that a mutation was made.
                self.total_mutant_index += 1

                # if we don't need to skip the current test case.
                if self.total_mutant_index > self.skip:
                    self.log("fuzzing %d of %d" % (self.fuzz_node.mutant_index, num_mutations))

                    # establish a connection to the target.
                    try:
                        sock = socket.socket(socket.AF_INET, self.proto)
                        sock.settimeout(self.timeout)
                        sock.connect((target.host, target.port))
                    except:
                        raise sex.error("FAILED CONNECTING TO %s:%d" % (target.host, target.port))

                    # if the user registered a pre-send function, pass it the sock and let it do the deed.
                    self.pre_send(sock)

                    # send out valid requests for each node in the current path up to the node we are fuzzing.
                    for e in path:
                        node = self.nodes[e.src]
                        self.__transmit(sock, node, e)

                    # now send the current node we are fuzzing.
                    self.__transmit(sock, self.fuzz_node, edge)

                    # if the user registered a post-send function, pass it the sock and let it do the deed.
                    self.post_send(sock)

                    # done with the socket.
                    sock.close()

                    # delay in between test cases.
                    time.sleep(self.sleep_time)

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
                                font-family:      Arial, Helvetica, sans-serif;;
                                font-size:        12px;
                                color:            #FFFFFF;
                            }

                            td
                            {
                                font-family:      Arial, Helvetica, sans-serif;;
                                font-size:        12px;
                                color:            #A0B0B0;
                            }

                            .fixed
                            {
                                font-family:      Arial, Helvetica, sans-serif;;
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
                    <table border=0 cellpadding=0 cellspacing=0 width="100%%" height="100%%"><tr><td align=center valign=center>
                    <table border=0 cellpadding=5 cellspacing=0 width=600>
                    <!-- begin bounding table -->

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

                    <!-- end bounding table -->
                    </table>
                    </table>
                    </body>
                    </html>
                   """

        # which node (request) are we currently fuzzing.
        if self.session.fuzz_node.name:
            current_name = self.session.fuzz_node.name
        else:
            current_name = "[N/A]"

        # what is the fuzzing status.
        if self.session.pause:
            status = "<font color=red>PAUSED</font>"
        else:
            status = "<font color=green>RUNNING</font>"

        # render sweet progress bars.
        progress_current     = float(self.session.fuzz_node.mutant_index) / float(self.session.fuzz_node.num_mutations())
        num_bars             = int(progress_current * 40)
        progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (40 - num_bars) + "]"
        progress_current     = "%.3f%%" % (progress_current * 100)

        progress_total       = float(self.session.fuzz_node.mutant_index) / float(self.session.fuzz_node.num_mutations())
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

        self.wfile.write(response)


    def log_error (self, *args, **kwargs):
        pass


    def log_message (self, *args, **kwargs):
        pass


    def version_string (self):
        return "Sulley Fuzz Session"


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