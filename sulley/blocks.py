import pgraph
import primitives
import sex

import zlib
import md5
import sha
import struct

REQUESTS = {}
CURRENT  = None

########################################################################################################################
class request (pgraph.node):
    def __init__ (self, name):
        '''
        Top level container instantiated by s_initialize(). Can hold any block structure or primitive.

        @type  name: String
        @param name: Name of this request
        '''

        self.name          = name

        self.label         = name    # node label for graph rendering.
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
            # ensure the name doesn't already exist.
            if item.name in self.names.keys():
                raise sex.error("BLOCK NAME ALREADY EXISTS: %s" % item.name)

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
        # ensure there are no open blocks lingering.
        if self.block_stack:
            raise sex.error("UNCLOSED BLOCK: %s" % self.block_stack[-1].name)

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


    def reset (self):
        '''
        Reset every block and primitives mutant state under this request.
        '''

        self.mutant_index  = 0
        self.closed_blocks = {}

        for item in self.stack:
            if item.fuzzable:
                item.reset()


########################################################################################################################
class block:
    def __init__ (self, name, request, group=None, encoder=None, dep=None, dep_value=None):
        '''
        The basic building block. Can contain primitives, sizers, checksums or other blocks.

        @type  name:      String
        @param name:      Name of the new block
        @type  request:   s_request
        @param request:   Request this block belongs to
        @type  group:     String
        @param group:     (Optional, def=None) Name of group to associate this block with
        @type  encoder:   Function Pointer
        @param encoder:   (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
        @type  dep:       String
        @param dep:       (Optional, def=None) Optional primitive whose specific value this block is dependant on
        @type  dep_value: Mixed
        @param dep_value: (Optional, def=None) Value that field "dep" must contain for block to be rendered
        '''

        self.name          = name
        self.request       = request
        self.group         = group
        self.encoder       = encoder
        self.dep           = dep
        self.dep_value     = dep_value

        self.stack         = []     # block item stack.
        self.rendered      = ""     # rendered block contents.
        self.fuzzable      = True   # blocks are always fuzzable because they may contain fuzzable items.
        self.group_idx     = 0      # if this block is tied to a group, the index within that group.
        self.fuzz_complete = False  # whether or not we are done fuzzing this block.


    def mutate (self):
        mutated = False

        # are we dont with this block?
        if self.fuzz_complete:
            return False

        #
        # mutate every item on the stack for every possible group value.
        #

        if self.group:
            group_count = self.request.names[self.group].num_mutations()

            # update the group value to that at the current index.
            self.request.names[self.group].value = self.request.names[self.group].values[self.group_idx]

            # mutate every item on the stack at the current group value.
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True
                    break

            # if the possible mutations for the stack are exhausted.
            if not mutated:
                # increment the group value index.
                self.group_idx += 1

                # if the group values are exhausted, we are done with this block.
                if self.group_idx == group_count:
                    # restore the original group value.
                    self.request.names[self.group].value = self.request.names[self.group].original_value

                # otherwise continue mutating this group/block.
                else:
                    # update the group value to that at the current index.
                    self.request.names[self.group].value = self.request.names[self.group].values[self.group_idx]

                    # this the mutate state for every item in this blocks stack.
                    # NOT THE BLOCK ITSELF THOUGH! (hence why we didn't call self.reset())
                    for item in self.stack:
                        if item.fuzzable:
                            item.reset()

                    # now mutate the first field in this block before continuing.
                    # (we repeat a test case if we don't mutate something)
                    for item in self.stack:
                        if item.fuzzable and item.mutate():
                            mutated = True
                            break

        #
        # no grouping, mutate every item on the stack once.
        #

        else:
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True
                    break

        # if this block is dependant on another field, then manually update that fields value appropriately while we
        # mutate this block. we'll restore the original value of the field prior to continuing.
        if mutated and self.dep:
            self.request.names[self.dep].value = self.dep_value


        # we are done mutating this block.
        if not mutated:
            self.fuzz_complete = True

            # if we had a dependancy, make sure we restore the original value.
            if self.dep:
                self.request.names[self.dep].value = self.request.names[self.dep].original_value

        return mutated


    def num_mutations (self):
        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

        # if this block is associated with a group, then multiply out the number of possible mutations.
        if self.group:
            num_mutations *= len(self.request.names[self.group].values)

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

        #
        # if this block is dependant on another field and the value is not met, render nothing.
        #

        if self.dep and self.request.names[self.dep].value != self.dep_value:
            self.rendered = ""

        #
        # otherwise, render as usual.
        #
        else:
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
        self.request.closed_blocks[self.name] = self

        # the block is now closed, clear out all the entries from the request back splice dictionary.
        if self.request.callbacks.has_key(self.name):
            for item in self.request.callbacks[self.name]:
                item.render()


    def reset (self):
        '''
        Reset the primitives on this blocks stack to the starting mutation state.
        '''

        self.fuzz_complete = False
        self.group_idx     = 0

        for item in self.stack:
            if item.fuzzable:
                item.reset()


########################################################################################################################
class checksum:
    checksum_lengths = {"crc32":4, "adler32":4, "md5":16, "sha1":20}

    def __init__(self, block_name, request, algorithm="crc32", length=0, endian="<", name=None):
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
        @type  name:       String
        @param name:       Name of this checksum field
        '''

        self.block_name = block_name
        self.request    = request
        self.algorithm  = algorithm
        self.length     = length
        self.endian     = endian
        self.name       = name

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
    '''
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    '''

    def __init__ (self, block_name, request, length=4, endian="<", format="binary", fuzzable=False, name=None):
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
        @type  name:       String
        @param name:       Name of this sizer field
        '''

        self.block_name     = block_name
        self.request        = request
        self.length         = length
        self.endian         = endian
        self.format         = format
        self.fuzzable       = fuzzable
        self.name           = name

        self.bit_field      = primitives.bit_field(0, length*8, endian=endian)
        self.rendered       = ""
        self.fuzz_complete  = self.bit_field.fuzz_complete
        self.fuzz_library   = self.bit_field.fuzz_library
        self.mutant_index   = self.bit_field.mutant_index


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


    def render (self):
        '''
        Render the sizer.
        '''

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


    def reset (self):
        '''
        Wrap the reset routine of the internal bit_field primitive.
        '''

        self.bit_field.reset()