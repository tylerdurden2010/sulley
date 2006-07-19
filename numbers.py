#!c:\python\python.exe

import random
import struct

########################################################################################################################
class bit_field (object):
    '''

    @alias: bits
    '''

    BIG_ENDIAN    = 0
    LITTLE_ENDIAN = 1

    ####################################################################################################################
    def __init__ (self, width, value=0, maxval=None):
        self.width   = width
        self.max_num = self.to_decimal("1" * width)

        if not maxval == None:
            self.max_num = maxval

        self.value   = value
        self.endian  = self.BIG_ENDIAN


    ####################################################################################################################
    def flatten (self):
        '''
        Convert

        @rtype:  Raw Bytes
        @return: Raw byte representation
        '''

        # pad the bit stream to the next byte boundary.
        bit_stream = ""
        if self.width % 8 == 0:
        	bit_stream += self.to_binary()
        else:
            bit_stream  = "0" * (8 - (self.width % 8))
            bit_stream += self.to_binary()


        flattened = ""
        # convert the bit stream from a string of bits into raw bytes.
        for i in xrange(len(bit_stream) / 8):
            chunk = bit_stream[8*i:8*i+8]
            flattened += struct.pack("B", self.to_decimal(chunk))

        # if necessary, convert the endianess of the raw bytes
        if self.endian == self.LITTLE_ENDIAN:
            flattened = list(flattened)
            flattened.reverse()
            flattened = "".join(flattened)

        return flattened


    ####################################################################################################################
    def iterate (self):
        while self.value <= self.max_num:
            self.value += 1
            yield self.value


    ####################################################################################################################
    def random (self):
    	#return random.randint(0, self.max_num)
        #self.value = random.randint(0, self.max_num) #XXX: this is all wrong. fixed above.
        self.value = random.randint(0, self.max_num)
        return self


    ####################################################################################################################
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

        for case in smart_cases:
            self.value = case
            yield self


    ####################################################################################################################
    def to_binary (self, number=None, bit_count=None):
        '''
        description

        @type number:     Integer
        @param number:    (Optional, def=self.value) Number to convert
        @type bit_count:  Integer
        @param bit_count: (Optional, def=self.width) Width of bit string

        @rtype:  String
        @return: Bit string
        '''

        if number == None:
            number = self.value

        if bit_count == None:
            bit_count = self.width

        return "".join(map(lambda x:str((number >> x) & 1), range(bit_count -1, -1, -1)))


    ####################################################################################################################
    def to_decimal (self, binary):
        return int(binary, 2)


########################################################################################################################
class nibble (bit_field):
    def __init__ (self, value=0, maxval=None):
        bit_field.__init__(self, 4, value=value, maxval=None)


########################################################################################################################
class byte (bit_field):
    def __init__ (self, value=0, maxval=None):
        bit_field.__init__(self, 8, value=value, maxval=None)


########################################################################################################################
class word (bit_field):
    def __init__ (self, value=0, maxval=None):
        bit_field.__init__(self, 16, value=value, maxval=None)


########################################################################################################################
class dword (bit_field):
    def __init__ (self, value=0, maxval=None):
        bit_field.__init__(self, 32, value=value, maxval=None)


########################################################################################################################
class qword (bit_field):
    def __init__ (self, value=0, maxval=None):
        bit_field.__init__(self, 64, value=value, maxval=None)


########################################################################################################################


# class aliases
bits   = bit_field
char   = byte
short  = word
long   = dword
double = qword