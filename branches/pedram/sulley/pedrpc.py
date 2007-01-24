import sys
import socket
import cPickle

########################################################################################################################
class client:
    def __init__ (self, host, port):
        self.__host           = host
        self.__port           = port
        self.__dbg_flag       = False
        self.__server_sock    = None


    ####################################################################################################################
    def __getattr__ (self, method_name):
        '''
        This routine is called by default when a requested attribute (or method) is accessed that has no definition.
        Unfortunately __getattr__ only passes the requested method name and not the arguments. So we extend the
        functionality with a little lambda magic to the routine method_missing(). Which is actually how Ruby handles
        missing methods by default ... with arguments. Now we are just as cool as Ruby.

        @type  method_name: String
        @param method_name: The name of the requested and undefined attribute (or method in our case).

        @rtype:  Lambda
        @return: Lambda magic passing control (and in turn the arguments we want) to self.method_missing().
        '''

        return lambda *args, **kwargs: self.method_missing(method_name, *args, **kwargs)


    ####################################################################################################################
    def __log (self, msg):
        if self.__dbg_flag:
            print "PED-RPC> %s" % msg


    ####################################################################################################################
    def method_missing (self, method_name, *args, **kwargs):
        '''
        See the notes for __getattr__ for related notes. This method is called, in the Ruby fashion, with the method
        name and arguments for any requested but undefined class method.

        @type  method_name: String
        @param method_name: The name of the requested and undefined attribute (or method in our case).
        @type  *args:       Tuple
        @param *args:       Tuple of arguments.
        @type  **kwargs     Dictionary
        @param **kwargs:    Dictioanry of arguments.

        @rtype:  Mixed
        @return: Return value of the mirrored method.
        '''

        # connect to the PED-RPC server.
        self.__server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_sock.connect((self.__host, self.__port))

        # disable socket timeouts.
        self.__server_sock.settimeout(None)

        # transmit the method name and arguments.
        self.pickle_send((method_name, (args, kwargs)))

        # snag the return value.
        ret = self.pickle_recv()

        # close the sock and return.
        self.__server_sock.close()
        return ret


    ####################################################################################################################
    def pickle_recv (self):
        '''
        This routine is used for marshaling arbitrary data from the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        '''

        try:
            length   = long(self.__server_sock.recv(4), 16)
            received = self.__server_sock.recv(length)

            return cPickle.loads(received)
        except:
            sys.stderr.write("connection to PED-RPC server severed")
            raise Exception


    ####################################################################################################################
    def pickle_send (self, data):
        '''
        This routine is used for marshaling arbitrary data to the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        '''

        self.__log("sending: %s" % str(data))
        data = cPickle.dumps(data)

        try:
            self.__server_sock.send("%04x" % len(data))
            self.__server_sock.send(data)
        except:
            sys.stderr.write("connection to PED-RPC server severed")
            raise Exception


########################################################################################################################
class server:
    def __init__ (self, host, port):
        self.__host           = host
        self.__port           = port
        self.__dbg_flag       = False
        self.__client         = None
        self.__client_address = None

        try:
            # create a socket, disable timeouts and bind to the specified port.
            self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__server.settimeout(None)
            self.__server.bind((host, port))
            self.__server.listen(1)
        except:
            sys.stderr.write("unable to bind to %s:%d\n" % (host, port))
            sys.exit(1)


    ####################################################################################################################
    def __log (self, msg):
        if self.__dbg_flag:
            print "PED-RPC> %s" % msg


    ####################################################################################################################
    def pickle_recv (self):
        '''
        This routine is used for marshaling arbitrary data from the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        '''

        try:
            length   = long(self.__client.recv(4), 16)
            received = self.__client.recv(length)

            return cPickle.loads(received)
        except:
            sys.stderr.write("connection severed to %s:%d\n" % (self.__client_address[0], self.__client_address[1]))
            raise Exception


    ####################################################################################################################
    def pickle_send (self, data):
        '''
        This routine is used for marshaling arbitrary data to the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        '''

        self.__log("sending: %s" % str(data))
        data = cPickle.dumps(data)

        try:
            self.__client.send("%04x" % len(data))
            self.__client.send(data)
        except:
            sys.stderr.write("connection severed to %s:%d\n" % (self.__client_address[0], self.__client_address[1]))
            raise Exception


    ####################################################################################################################
    def serve_forever (self):
        self.__log("serving up a storm")

        while 1:
            # accept a client connection/
            (self.__client, self.__client_address) = self.__server.accept()
            self.__log("accepted connection from %s:%d" % (self.__client_address[0], self.__client_address[1]))

            # recieve the method name and arguments, continue on socket disconnect.
            try:
                (method_name, (args, kwargs)) = self.pickle_recv()
                self.__log("%s(args=%s, kwargs=%s)" % (method_name, args, kwargs))
            except:
                continue

            # resolve a pointer to the requested method.
            method_pointer = None

            try:
                exec("method_pointer = self.%s" % method_name)
            except:
                pass

            # call the method point and save the return value.
            if method_pointer:
                ret = method_pointer(*args, **kwargs)
            else:
                ret = None

            # transmit the return value to the client, continue on socket disconnect.
            try:
                self.pickle_send(ret)
            except:
                continue

            # close the client connection and continue serving up requests.
            self.__client.close()