import primitives
import sex

import zlib
import md5
import sha
import struct

REQUESTS = {}
CURRENT  = None

########################################################################################################################
class request:
    def __init__ (self):
        '''
        Top level container instantiated by s_initialize(). Can hold any block structure or primitive.
        '''

        self.stack         = []      # the request stack.
        self.block_stack   = []      # list of open blocks, -1 is last open block.
        self.closed_blocks = {}      # dictionary of closed blocks.
        self.callbacks     = {}      # dictionary of list of sizers / checksums that were unable to complete rendering.
        self.names         = {}      # dictionary of directly accessible primitives.
        self.rendered      = ""      # rendered block structure.
        self.mutant_index  = 0       # current mutation index.

    
    def mutate (self):
        mutated = False
        
        for item in self.stack:
            if item.fuzzable and item.mutate():
                mutated = True
                break

        if mutated:
            self.mutant_index += 1

        return mutated


    def num_mutations (self):
        num_mutations = 0
        
        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

        return num_mutations
        
        
    def pop (self):
        '''
        The last open block was closed, so pop it off of the block stock.
        '''

        if not self.block_stack:
            raise sex.error("BLOCK STACK OUT OF SYNC")

        self.block_stack.pop()


    def push (self, item):
        '''
        Push an item into the block structure. If not block is open, the item goes onto the request stack. otherwise,
        the item goes onto the last open blocks stack.
        '''

        # if the item has a name, add it to the internal dictionary of names.
        if hasattr(item, "name") and item.name:
            self.names[item.name] = item

        # if there are no open blocks, the item gets pushed onto the request stack.
        # otherwise, the pushed item goes onto the stack of the last opened block.
        if not self.block_stack:
            self.stack.append(item)
        else:
            self.block_stack[-1].push(item)

        # add the opened block to the block stack.
        if isinstance(item, block):
            self.block_stack.append(item)


    def render (self):
        # render every item in the stack.
        for item in self.stack:
            item.render()

        # process remaining callbacks.
        for key in self.callbacks.keys():
            for item in self.callbacks[key]:
                item.render()

        # now collect, merge and return the rendered items.
        self.rendered = ""

        for item in self.stack:
            self.rendered += item.rendered

        return self.rendered


########################################################################################################################
class block:
    def __init__ (self, block_name, request, encoder=None):
        '''
        The basic building block. Can contain primitives, sizers, checksums or other blocks.

        @type  block_name: String
        @param block_name: Name of the new block
        @type  request:    s_request
        @param request:    Request this block belongs to
        @type  encoder:    Function Pointer
        @param encoder:    (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
        '''

        self.block_name = block_name
        self.request    = request
        self.encoder    = encoder
        
        self.stack      = []
        self.rendered   = ""
        self.fuzzable   = True


    def mutate (self):
        mutated = False
        
        for item in self.stack:
            if item.fuzzable and item.mutate():
                mutated = True
                break

        return mutated


    def num_mutations (self):
        num_mutations = 0
        
        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

        return num_mutations
        
                
    def push (self, item):
        '''
        Push an arbitrary item onto this blocks stack.
        '''

        self.stack.append(item)


    def render (self):
        '''
        Step through every item on this blocks stack and render it. Subsequent blocks recursively render their stacks.
        The rendered contact is added to request.rendered and the request object is continually passed down the block
        structure.
        '''

        # recursively render the items on the stack.
        for item in self.stack:
            item.render()

        # now collect and merge the rendered items.
        self.rendered = ""

        for item in self.stack:
            self.rendered += item.rendered

        # if an encoder was attached to this block, call it.
        if self.encoder:
            self.rendered = self.encoder(self.rendered)

        # add the completed block to the request dictionary.
        self.request.closed_blocks[self.block_name] = self

        # the block is now closed, clear out all the entries from the request back splice dictionary.
        if self.request.callbacks.has_key(self.block_name):
            for item in self.request.callbacks[self.block_name]:
                item.render()
        

########################################################################################################################
class checksum:
    checksum_lengths = {"crc32":4, "adler32":4, "md5":16, "sha1":20}

    def __init__(self, block_name, request, algorithm="crc32", length=0, endian="<"):
        '''
        Create a checksum block bound to the block with the specified name. You *can not* create a checksm for any
        currently open blocks.

        @type  block_name: String
        @param block_name: Name of block to apply sizer to
        @type  request:    s_request
        @param request:    Request this block belongs to
        @type  algorithm:  String
        @param algorithm:  (Optional, def=crc32) Checksum algorithm to use. (crc32, adler32, md5, sha1)
        @type  length:     Integer
        @param length:     (Optional, def=0) Length of checksum, specify 0 to auto-calculate
        @type  endian:     Character
        @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        '''

        self.block_name = block_name
        self.request    = request
        self.algorithm  = algorithm
        self.length     = length
        self.endian     = endian
        
        self.rendered   = ""
        self.fuzzable   = False

        if not self.length and self.checksum_lengths.has_key(self.algorithm):
            self.length = self.checksum_lengths[self.algorithm]


    def checksum (self, data):
        if type(self.algorithm) is str:
            if self.algorithm == "crc32":
                return struct.pack(self.endian+"L", zlib.crc32(data))

            elif self.algorithm == "adler32":
                return struct.pack(self.endian+"L", zlib.adler32(data))

            elif self.algorithm == "md5":
                digest = md5.md5(data).digest()

                # XXX - is this right?
                if self.endian == ">":
                    (a, b, c, d) = struct.unpack("<LLLL", digest)
                    digest       = struct.pack(">LLLL", a, b, c, d)

                return digest

            elif self.algorithm == "sha1":
                digest = sha.sha(data).digest()

                # XXX - is this right?
                if self.endian == ">":
                    (a, b, c, d, e) = struct.unpack("<LLLLL", digest)
                    digest          = struct.pack(">LLLLL", a, b, c, d, e)

                return digest

            else:
                raise sex.error("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self.algorithm)
        else:
            return self.algorithm(data)


    def render (self):
        self.rendered = ""

        # if the target block for this sizer is already closed, render the checksum.
        if self.block_name in self.request.closed_blocks:
            block_data    = self.request.closed_blocks[self.block_name].rendered
            self.rendered = self.checksum(block_data)

        # otherwise, add this checksum block to the factories callback list.
        else:
            if not self.request.callbacks.has_key(self.block_name):
                self.request.callbacks[self.block_name] = []

            self.request.callbacks[self.block_name].append(self)


########################################################################################################################
class size:
    def __init__ (self, block_name, request, length=4, endian="<", format="binary", fuzzable=False):
        '''
        Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
        currently open blocks.

        @type  block_name: String
        @param block_name: Name of block to apply sizer to
        @type  request:    s_request
        @param request:    Request this block belongs to
        @type  length:     Integer
        @param length:     (Optional, def=4) Length of sizer
        @type  endian:     Character
        @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  format:     String
        @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
        @type  fuzzable:   Boolean
        @param fuzzable:   (Optional, def=False) Enable/disable fuzzing of this sizer
        '''

        self.block_name = block_name
        self.request    = request
        self.length     = length
        self.endian     = endian
        self.format     = format
        self.fuzzable   = fuzzable
        self.bit_field  = primitives.bit_field(0, length*8, endian=endian)
        
        self.rendered       = ""
        self.fuzz_complete  = self.bit_field.fuzz_complete
        self.fuzz_library   = self.bit_field.fuzz_library
        self.mutant_index   = self.bit_field.mutant_index


    def render (self):
        self.rendered = ""

        # if the target block for this sizer is already closed, render the checksum.
        if self.block_name in self.request.closed_blocks:
            block                = self.request.closed_blocks[self.block_name]
            self.bit_field.value = len(block.rendered)
            
            # render the size dependant on the format specified.
            if self.format == "ascii":
                self.rendered = "%d" % self.bit_field.value
            else:
                self.rendered = self.bit_field.render()

        # otherwise, add this checksum block to the factories callback list.
        else:
            if not self.request.callbacks.has_key(self.block_name):
                self.request.callbacks[self.block_name] = []

            self.request.callbacks[self.block_name].append(self)


    def mutate (self):
        '''
        Wrap the mutation routine of the internal bit_field primitive.
        
        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        return self.bit_field.mutate()


    def num_mutations (self):
        '''
        Wrap the num_mutations routine of the internal bit_field primitive.
        
        @rtype:  Integer
        @return: Number of mutated forms this primitive can take.
        '''
        
        return self.bit_field.num_mutations()