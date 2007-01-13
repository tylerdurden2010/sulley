import random
import struct

########################################################################################################################
class delim (object):
    def __init__ (self, value, max_rep=100, fuzzable=True, name=None):
        '''
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition and exclusion.
        
        @type  value:    Character
        @param value:    Original value
        @type  max_rep:  Integer
        @param max_rep:  (Optional, def=100) Maximum delimiter repetition length
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value    = self.original_value = value
        self.max_rep  = max_rep
        self.fuzzable = fuzzable
        self.name     = name
        self.rendered = ""


    def mutate (self):
        '''
        Mutate the primitive value.
        '''

        # if fuzzing was disabled and mutate() is called, restore the original value.
        if not self.fuzzable:
            self.value = self.original_value
            return

        # if the max delim string length is reached, omit the delim and then disable fuzzing.
        if len(self.value) > max_rep:
            self.value    = ""

            # disable fuzzing (ie: restore original value) on next run.
            self.fuzzable = False

        # exponentially grow the length of the delim string.
        self.value += self.value


    def render (self):
        '''
        Render the primitive.
        '''

        self.rendered = self.value
        return self.rendered


########################################################################################################################
class random (object):
    def __init__ (self, value, min_length, max_length, num_mutations=25, fuzzable=True, name=None):
        '''
        Generate a random chunk of data while maintaining a copy of the original. A random length range can be specified.
        For a static length, set min/max length to be the same.
        
        @type  value:         Raw
        @param value:         Original value
        @type  min_length:    Integer
        @param min_length:    Minimum length of random block
        @type  max_length:    Integer
        @param max_length:    Maximum length of random block
        @type  num_mutations: Integer
        @param num_mutations: (Optional, def=25) Number of mutations to make before reverting to default
        @type  fuzzable:      Boolean
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          String
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value         = self.original_value = value
        self.min_length    = min_length
        self.max_length    = max_length
        self.num_mutations = num_mutations
        self.fuzzable      = fuzzable
        self.name          = name
        self.rendered      = ""


    def mutate (self):
        '''
        Mutate the primitive value.
        '''

        # if fuzzing was disabled and mutate() is called, restore the original value.
        if not self.fuzzable:
            self.value = self.original_value
            return

        # select a random length for this string.
        length     = random.randint(self.mind_length, self.max_length)

        # reset the value and generate a random string of the determined length.
        self.value = ""
        for i in xrange(length):
            self.value += chr(random.randint(0, 255))


    def render (self):
        '''
        Render the primitive.
        '''

        self.rendered = self.value
        return self.rendered



########################################################################################################################
class static (object):
    def __init__ (self, value, name=None):
        '''
        Primitive that contains static content.
        
        @type  value: Raw
        @param value: Raw static data
        @type  name:  String
        @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value    = value
        self.name     = name
        self.fuzzable = False       # every primitive needs this attribute.
        self.rendered = ""


    def mutate (self):
        '''
        Do nothing.
        '''

        return


    def render (self):
        '''
        Render the primitive.
        '''

        self.rendered = self.value
        return self.rendered


########################################################################################################################
class string (object):
    def __init__ (self, value, size=None, padding="\x00", fuzzable=True, name=None):
        '''
        Primitive that cycles through a library of "bad" strings.
        
        @type  value:    String
        @param value:    Default string value
        @type  size:     Integer
        @param size:     (Optional, def=None) Static size of this field, leave None for dynamic.
        @type  padding:  Character
        @param padding:  (Optional, def="\x00") Value to use as padding to fill static field size.
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value    = self.original_value = value
        self.size     = size
        self.padding  = padding
        self.fuzzable = fuzzable
        self.name     = name
        self.rendered = ""

        if not self.size:
            self.size = len(self.value)


    def mutate (self):
        '''
        Mutate the primitive value.
        @todo: complete
        '''

        # if fuzzing was disabled and mutate() is called, restore the original value.
        if not self.fuzzable:
            self.value = self.original_value
            return


    def render (self):
        '''
        Render the primitive.
        '''

        self.rendered = self.value
        return self.rendered


########################################################################################################################
class bit_field (object):
    def __init__ (self, value, width, max_num=None, endian="<", fuzzable=True, name=None):
        '''
        The bit field primitive represents a number of variable length and is used to define all other integer types.
        
        @type  value:    Integer
        @param value:    Default integer value
        @type  width:    Integer
        @param width:    Width of bit fields
        @type  endian:   Character
        @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        assert(type(value) is int or long)
        assert(type(width) is int or long)

        self.value    = self.original_value = value
        self.width    = width
        self.max_num  = max_num
        self.endian   = endian
        self.fuzzable = fuzzable
        self.name     = name
        self.rendered = ""

        if self.max_num == None:
            self.max_num = self.to_decimal("1" * width)


    def mutate (self):
        '''
        Mutate the primitive value.
        @todo: complete
        '''

        # if fuzzing was disabled and mutate() is called, restore the original value.
        if not self.fuzzable:
            self.value = self.original_value
            return

        return


    def render (self):
        '''
        Render the primitive value into the factory.
        '''

        bit_stream = ""
        rendered   = ""

        # pad the bit stream to the next byte boundary.
        if self.width % 8 == 0:
            bit_stream += self.to_binary()
        else:
            bit_stream  = "0" * (8 - (self.width % 8))
            bit_stream += self.to_binary()

        # convert the bit stream from a string of bits into raw bytes.
        for i in xrange(len(bit_stream) / 8):
            chunk = bit_stream[8*i:8*i+8]
            rendered += struct.pack("B", self.to_decimal(chunk))

        # if necessary, convert the endianess of the raw bytes.
        if self.endian == "<":
            rendered = list(rendered)
            rendered.reverse()
            rendered = "".join(rendered)

        self.rendered = rendered
        return self.rendered


    def to_binary (self, number=None, bit_count=None):
        '''
        Convert a number to a binary string.

        @type  number:    Integer
        @param number:    (Optional, def=self.value) Number to convert
        @type  bit_count: Integer
        @param bit_count: (Optional, def=self.width) Width of bit string

        @rtype:  String
        @return: Bit string
        '''

        if number == None:
            number = self.value

        if bit_count == None:
            bit_count = self.width

        return "".join(map(lambda x:str((number >> x) & 1), range(bit_count -1, -1, -1)))


    def to_decimal (self, binary):
        '''
        Convert a binary string to a decimal number.

        @type  binary: String
        @param binary: Binary string

        @rtype:  Integer
        @return: Converted bit string
        '''

        return int(binary, 2)

"""
    XXX - fix up

    def fuzz (self):
        cases = \
        [
            self.max_num,
            self.max_num / 2,
            self.max_num / 4,
        ]

        # xxx - complete


    def random (self):
        return random.randint(0, self.max_num)


    def smart (self):
        # 0, -1, max, max/2, max/4, +border cases around previous (use a loop +append)
        smart_cases = \
        [
            0,
            self.max_num,
            self.max_num / 2,
            self.max_num / 4,
            # etc...
        ]

        # xxx - complete

        for case in smart_cases:
            self.value = case
            yield case
"""


########################################################################################################################
class byte (bit_field):
    def __init__ (self, value=0, max_num=None, endian="<", fuzzable=True, name=None):
        if type(value) not in [int, long]:
            value = struct.unpack(endian + "B", value)[0]

        bit_field.__init__(self, value, 8, max_num, endian, fuzzable, name)


########################################################################################################################
class word (bit_field):
    def __init__ (self, value=0, max_num=None, endian="<", fuzzable=True, name=None):
        if type(value) not in [int, long]:
            value = struct.unpack(endian + "H", value)[0]

        bit_field.__init__(self, value, 16, max_num, endian, fuzzable, name)


########################################################################################################################
class dword (bit_field):
    def __init__ (self, value=0, max_num=None, endian="<", fuzzable=True, name=None):
        if type(value) not in [int, long]:
            value = struct.unpack(endian + "L", value)[0]

        bit_field.__init__(self, value, 32, max_num, endian, fuzzable, name)


########################################################################################################################
class qword (bit_field):
    def __init__ (self, value=0, max_num=None, endian="<", fuzzable=True, name=None):
        if type(value) not in [int, long]:
            value = struct.unpack(endian + "Q", value)[0]

        bit_field.__init__(self, value, 64, max_num, endian, fuzzable, name)
