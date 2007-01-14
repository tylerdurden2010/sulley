import pgraph


########################################################################################################################
class connection (pgraph.edge.edge):
    def __init__ (self, src, dst, callback=None):
        # run the parent classes initialization routine first.
        pgraph.edge.edge.__init__(self, src, dst)

        self.callback = callback


########################################################################################################################
class session (pgraph.graph):
    def __init__ (self):
        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self)

        self.root       = pgraph.node()
        self.root.name  = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv  = None

        self.add_node(self.root)


    def add_node (self, node):
        '''
        we overload this routine to automatically assign an id.
        '''

        node.number = len(self.nodes)
        node.id     = len(self.nodes)

        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node

        return self


    def connect (self, src, dst, callback=None):
        # if source is a name, resolve the actual node.
        if type(src) is str:
            src = self.find_node("name", src)

        # if destination is a name, resolve the actual node.
        if type(dst) is str:
            dst = self.find_node("name", dst)

        # if source is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
            self.add_node(src)

        # if destination is not in the graph, add it.
        if not self.find_node("name", dst.name):
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = connection(src.id, dst.id, callback)
        self.add_edge(edge)


    def fuzz (self, this_node=None, path=[]):
        if not this_node:
            this_node = self.root

        for edge in self.edges_from(this_node.id):
            to_send = self.nodes[edge.dst]

            if edge.src != self.root.id:
                path.append(edge)

            #print [self.nodes[e.src].name for e in path], "->", to_send.name

            while 1:
                # send out valid requests for each node in the current path.
                for e in path:
                    node = self.nodes[e.src]
                    self.transmit(node, e)

                self.transmit(to_send, edge)

                if not to_send.mutate():
                    break

            self.fuzz(to_send, path)

        if path:
            path.pop()


    def transmit (self, node, edge):
        if edge.callback:
            edge.callback(self, node, edge, self.last_recv)

        print "xmitting: [%d] %s" % (node.id, node.render())
        # sock send
        # sock recv
        self.last_recv = "BULLSHIT"
