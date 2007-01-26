import sys
import struct
import socket
import cPickle

########################################################################################################################
class client:
    def __init__ (self, host, port):
        self.__host           = host
        self.__port           = port
        self.__dbg_flag       = False
        self.__server_sock    = None
        self.NOLINGER         = struct.pack('HH', 1, 0)


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

        return lambda *args, **kwargs: self.__method_missing(method_name, *args, **kwargs)


    ####################################################################################################################
    def __connect (self):
        '''
        Connect to the PED-RPC server.
        '''

        # if we have a pre-existing server socket, ensure it's closed.
        self.__disconnect()

        # connect to the server.
        self.__server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_sock.connect((self.__host, self.__port))

        # disable timeouts and lingering.
        self.__server_sock.settimeout(None)
        self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.NOLINGER)


    ####################################################################################################################
    def __disconnect (self):
        '''
        Ensure the socket is torn down.
        '''

        if self.__server_sock != None:
            self.__log("closing server socket")
            self.__server_sock.close()
            self.__server_sock = None


    ####################################################################################################################
    def __log (self, msg):
        if self.__dbg_flag:
            print "PED-RPC> %s" % msg


    ####################################################################################################################
    def __method_missing (self, method_name, *args, **kwargs):
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
        self.__connect()

        # transmit the method name and arguments.
        while 1:
            try:
                self.__pickle_send((method_name, (args, kwargs)))
                break
            except:
                # re-connect to the PED-RPC server if the sock died.
                self.__connect()

        # snag the return value.
        ret = self.__pickle_recv()

        while 1:
            try:
                self.__pickle_send((method_name, (args, kwargs)))
                break
            except:
                # re-connect to the PED-RPC server if the sock died.
                self.__connect()

        # close the sock and return.
        self.__disconnect()
        return ret


    ####################################################################################################################
    def __pickle_recv (self):
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
        except:
            sys.stderr.write("PED-RPC> connecton to server severed\n")
            raise Exception

        return cPickle.loads(received)


    ####################################################################################################################
    def __pickle_send (self, data):
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
            sys.stderr.write("PED-RPC> connecton to server severed\n")
            raise Exception


########################################################################################################################
class server:
    def __init__ (self, host, port):
        self.__host           = host
        self.__port           = port
        self.__dbg_flag       = False
        self.__client_sock    = None
        self.__client_address = None

        try:
            # create a socket and bind to the specified port.
            self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__server.settimeout(None)
            self.__server.bind((host, port))
            self.__server.listen(1)
        except:
            sys.stderr.write("unable to bind to %s:%d\n" % (host, port))
            sys.exit(1)


    ####################################################################################################################
    def __disconnect (self):
        '''
        Ensure the socket is torn down.
        '''

        if self.__client_sock != None:
            self.__log("closing client socket")
            self.__client_sock.close()
            self.__client_sock = None


    ####################################################################################################################
    def __log (self, msg):
        if self.__dbg_flag:
            print "PED-RPC> %s" % msg


    ####################################################################################################################
    def __pickle_recv (self):
        '''
        This routine is used for marshaling arbitrary data from the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        '''

        try:
            length   = long(self.__client_sock.recv(4), 16)
            received = self.__client_sock.recv(length)

            return cPickle.loads(received)
        except:
            sys.stderr.write("PED-RPC> connection client severed\n")
            raise Exception


    ####################################################################################################################
    def __pickle_send (self, data):
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
            self.__client_sock.send("%04x" % len(data))
            self.__client_sock.send(data)
        except:
            sys.stderr.write("PED-RPC> connection to client severed\n")
            raise Exception


    ####################################################################################################################
    def serve_forever (self):
        self.__log("serving up a storm")

        while 1:
            # close any pre-existing socket.
            self.__disconnect()

            # accept a client connection.
            (self.__client_sock, self.__client_address) = self.__server.accept()

            self.__log("accepted connection from %s:%d" % (self.__client_address[0], self.__client_address[1]))

            # recieve the method name and arguments, continue on socket disconnect.
            try:
                (method_name, (args, kwargs)) = self.__pickle_recv()
                self.__log("%s(args=%s, kwargs=%s)" % (method_name, args, kwargs))
            except:
                continue

            # resolve a pointer to the requested method.
            # move on if the method can't be found.
            try:
                exec("method_pointer = self.%s" % method_name)
            except:
                continue

            # call the method point and save the return value.
            ret = method_pointer(*args, **kwargs)

            # transmit the return value to the client, continue on socket disconnect.
            try:
                self.__pickle_send(ret)
            except:
                continue