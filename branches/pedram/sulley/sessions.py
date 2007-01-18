import socket
import xmlrpclib
import time

import pgraph
import sex

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
    def __init__ (self, target, project, log=True, expector=None, debugger=None, proto="tcp", timeout=5.0):
        '''
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  target:   Tuple: ("IP", port)
        @param target:   IP address and port of fuzz target
        @type  project:  String
        @param project:  Name of this fuzz project. Used in creation of log files, expector pcaps and debugger traces
        @type  log_flag: Boolean
        @param log_flag: (Optional, def=True) Toggle logging
        @type  expector: Tuple: ("IP", port)
        @param expector: (Optional, def=None) IP address and port of listening expector XML-RPC server
        @type  debugger: Tuple: ("IP", port)
        @param debugger: (Optional, def=None) IP address and port of listening debugger XML-RPC server
        @type  proto:    String
        @param proto:    (Optional, def="tcp") Communication protocol
        @type  timeout:  Float
        @param timeout:  (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        '''

        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self)

        self.target   = target
        self.project  = project
        self.log_flag = log
        self.expector = expector
        self.debugger = debugger
        self.proto    = proto
        self.timeout  = timeout

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

        # start fuzzing from the root node.
        if not this_node:
            this_node = self.root

        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # the destination node is the one actually being transmitted.
            to_send = self.nodes[edge.dst]

            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            if edge.src != self.root.id:
                path.append(edge)

            self.log(str([self.nodes[e.src].name for e in path]) + " -> " + to_send.name)

            # loop through all possible mutations of the to_send node.
            while 1:
                current_path  = " -> ".join([self.nodes[e.src].name for e in path])
                current_path += " -> %s" % to_send.name

                self.log("fuzzing %s" % current_path)

                # establish a connecton to the target.
                sock = socket.socket(socket.AF_INET, self.proto)
                sock.settimeout(self.timeout)

                try:
                    sock.connect(self.target)
                except:
                    raise sex.error("FAILED CONNECTING TO %s\nCURRENT PATH: %s" % (self.target, current_path))

                # if the user registered a pre-send function, pass it the sock and let it do the deed.
                self.pre_send(sock)

                # send out valid requests for each node in the current path up to the node we are fuzzing.
                for e in path:
                    node = self.nodes[e.src]
                    self.transmit(sock, node, e)

                # now send the current node we are fuzzing.
                self.transmit(sock, to_send, edge)

                # if the user registered a post-send function, pass it the sock and let it do the deed.
                self.post_send(sock)

                # done with the socket.
                sock.close()

                # if we have exhausted the mutations of the to_send node, break out of the while-1.
                # note: when mutate() returns False, it means the node has been reverted to the default (valid) state.
                if not to_send.mutate():
                    break

            # recursively fuzz the remainder of the nodes in the session graph.
            self.fuzz(to_send, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()


    def hex_dump (self, data, addr=0):
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


    def log (self, msg):
        '''
        If the log flag is raised, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_flag:
            print msg


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


    def transmit (self, sock, node, edge):
        '''
        Render and transmit a node, process callbacks accordingly. This routine is called internally by fuzz(), but
        who knows, maybe you will find a reason to call it directly.

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

        self.log("xmitting: [%d]" % (node.id))

        try:
            rendered = node.render()
            self.log(self.hex_dump(rendered))
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

        self.log("received: [%d] %s" % (len(self.last_recv), self.last_recv))
