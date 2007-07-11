import random
import struct

########################################################################################################################
class base_primitive (object):
    '''
    The primitive base class implements common functionality shared across most primitives.
    '''

    def __init__ (self):
        self.fuzz_complete  = False     # this flag is raised when the mutations are exhausted.
        self.fuzz_library   = []        # library of static fuzz heuristics to cycle through.
        self.fuzzable       = True      # flag controlling whether or not the given primitive is to be fuzzed.
        self.mutant_index   = 0         # current mutation index into the fuzz library.
        self.original_value = None      # original value of primitive.
        self.rendered       = ""        # rendered value of primitive.
        self.value          = None      # current value of primitive.


    def mutate (self):
        '''
        Mutate the primitive by stepping through the fuzz library, return False on completion.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # update the current value from the fuzz library.
        self.value = self.fuzz_library[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True


    def num_mutations (self):
        '''
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''

        return len(self.fuzz_library)


    def render (self):
        '''
        Nothing fancy on render, simply return the value.
        '''

        self.rendered = self.value
        return self.rendered


    def reset (self):
        '''
        Reset this primitive to the starting mutation state.
        '''

        self.fuzz_complete  = False
        self.mutant_index   = 0
        self.value          = self.original_value


########################################################################################################################
class delim (base_primitive):
    def __init__ (self, value, fuzzable=True, name=None):
        '''
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

        @type  value:    Character
        @param value:    Original value
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value         = self.original_value = value
        self.fuzzable      = fuzzable
        self.name          = name

        self.rendered      = ""        # rendered value
        self.fuzz_complete = False     # flag if this primitive has been completely fuzzed
        self.fuzz_library  = []        # library of fuzz heuristics
        self.mutant_index  = 0         # current mutation number

        #
        # build the library of fuzz heuristics.
        #

        # if the default delim is not blank, repeat it a bunch of times.
        if self.value:
            self.fuzz_library.append(self.value * 2)
            self.fuzz_library.append(self.value * 5)
            self.fuzz_library.append(self.value * 10)
            self.fuzz_library.append(self.value * 25)
            self.fuzz_library.append(self.value * 100)
            self.fuzz_library.append(self.value * 500)
            self.fuzz_library.append(self.value * 1000)

        # try ommitting the delimiter.
        self.fuzz_library.append("")

        # if the delimiter is a space, try throwing out some tabs.
        if self.value == " ":
            self.fuzz_library.append("\t")
            self.fuzz_library.append("\t" * 2)
            self.fuzz_library.append("\t" * 100)

        # toss in some other common delimiters:
        self.fuzz_library.append(" ")
        self.fuzz_library.append("\t")
        self.fuzz_library.append("\t " * 100)
        self.fuzz_library.append("\t\r\n" * 100)
        self.fuzz_library.append("!")
        self.fuzz_library.append("@")
        self.fuzz_library.append("#")
        self.fuzz_library.append("$")
        self.fuzz_library.append("%")
        self.fuzz_library.append("^")
        self.fuzz_library.append("&")
        self.fuzz_library.append("*")
        self.fuzz_library.append("(")
        self.fuzz_library.append(")")
        self.fuzz_library.append("-")
        self.fuzz_library.append("_")
        self.fuzz_library.append("+")
        self.fuzz_library.append("=")
        self.fuzz_library.append(":")
        self.fuzz_library.append(": " * 100)
        self.fuzz_library.append(":7" * 100)
        self.fuzz_library.append(";")
        self.fuzz_library.append("'")
        self.fuzz_library.append("\"")
        self.fuzz_library.append("/")
        self.fuzz_library.append("\\")
        self.fuzz_library.append("?")
        self.fuzz_library.append("<")
        self.fuzz_library.append(">")
        self.fuzz_library.append(".")
        self.fuzz_library.append(",")
        self.fuzz_library.append("\r")
        self.fuzz_library.append("\n")
        self.fuzz_library.append("\r\n" * 64)
        self.fuzz_library.append("\r\n" * 128)
        self.fuzz_library.append("\r\n" * 512)


########################################################################################################################
class group (base_primitive):
    def __init__ (self, name, values):
        '''
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        @type  name:   String
        @param name:   Name of group
        @type  values: List or raw data
        @param values: List of possible raw values this group can take.
        '''

        self.name           = name
        self.values         = values
        self.fuzzable       = True

        self.value          = self.values[0]
        self.original_value = self.values[0]
        self.rendered       = ""
        self.fuzz_complete  = False
        self.mutant_index   = 1      # XXX - should start mutating at 1, since the first item is the default. right?

        # sanity check that values list only contains strings
        if self.values != []:
            for val in self.values:
                assert type(val) is str, "Value list may only contain strings"
                

    def mutate (self):
        '''
        Move to the next item in the values list.

        @rtype:  False
        @return: False
        '''

        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.values[0]
            return False

        # step through the value list.
        self.value = self.values[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True


    def num_mutations (self):
        '''
        Number of values in this primitive.

        @rtype:  Integer
        @return: Number of values in this primitive.
        '''

        return len(self.values)


########################################################################################################################
class random_data (base_primitive):
    def __init__ (self, value, min_length, max_length, max_mutations=25, fuzzable=True, name=None):
        '''
        Generate a random chunk of data while maintaining a copy of the original. A random length range can be specified.
        For a static length, set min/max length to be the same.

        @type  value:         Raw
        @param value:         Original value
        @type  min_length:    Integer
        @param min_length:    Minimum length of random block
        @type  max_length:    Integer
        @param max_length:    Maximum length of random block
        @type  max_mutations: Integer
        @param max_mutations: (Optional, def=25) Number of mutations to make before reverting to default
        @type  fuzzable:      Boolean
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          String
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value         = self.original_value = str(value)
        self.min_length    = min_length
        self.max_length    = max_length
        self.max_mutations = max_mutations
        self.fuzzable      = fuzzable
        self.name          = name

        self.rendered      = ""        # rendered value
        self.fuzz_complete = False     # flag if this primitive has been completely fuzzed
        self.mutant_index  = 0         # current mutation number


    def mutate (self):
        '''
        Mutate the primitive value returning False on completion.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # select a random length for this string.
        length = random.randint(self.min_length, self.max_length)

        # reset the value and generate a random string of the determined length.
        self.value = ""
        for i in xrange(length):
            self.value += chr(random.randint(0, 255))

        # increment the mutation count.
        self.mutant_index += 1

        return True


    def num_mutations (self):
        '''
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''

        return self.max_mutations


########################################################################################################################
class static (base_primitive):
    def __init__ (self, value, name=None):
        '''
        Primitive that contains static content.

        @type  value: Raw
        @param value: Raw static data
        @type  name:  String
        @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value         = self.original_value = value
        self.name          = name
        self.fuzzable      = False       # every primitive needs this attribute.
        self.mutant_index  = 0
        self.rendered      = ""
        self.fuzz_complete = True


    def mutate (self):
        '''
        Do nothing.

        @rtype:  False
        @return: False
        '''

        return False


    def num_mutations (self):
        '''
        Return 0.

        @rtype:  0
        @return: 0
        '''

        return 0


########################################################################################################################
class string (base_primitive):
    def __init__ (self, value, **kwargs):
        '''
        Primitive that cycles through a library of "bad" strings.

        @type  value:    String
        @kwarg value:    Default string value
        @type  size:     Integer
        @kwarg size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  Character
        @kwarg padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: String
        @kwarg encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: Boolean
        @kwarg fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @kwarg name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        self.value         = self.original_value = value
        self.size          = kwargs.get("size",     -1)
        self.padding       = kwargs.get("padding",  "\x00")
        self.encoding      = kwargs.get("encoding", "ascii")
        self.fuzzable      = kwargs.get("fuzzable", True)
        self.name          = kwargs.get("name",     None)

        self.rendered      = ""        # rendered value
        self.fuzz_complete = False     # flag if this primitive has been completely fuzzed
        self.mutant_index  = 0         # current mutation number
        self.fuzz_library  = \
        [
            # omission and repetition.
            "",
            self.value * 2,
            self.value * 10,
            self.value * 100,

            # strings ripped from spike (and some others I added)
            "/.:/"  + "A"*5000 + "\x00\x00",
            "/.../" + "A"*5000 + "\x00\x00",
            "/.../.../.../.../.../.../.../.../.../.../",
            "/../../../../../../../../../../../../etc/passwd",
            "/../../../../../../../../../../../../boot.ini",
            "..:..:..:..:..:..:..:..:..:..:..:..:..:",
            "\\\\*",
            "\\\\?\\",
            "/\\" * 5000,
            "/." * 5000,
            "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
            "%01%02%03%04%0a%0d%0aADSF",
            "%01%02%03@%04%0a%0d%0aADSF",
            "/%00/",
            "%00/",
            "%00",
            "%u0000",

            # format strings.
            "%n"     * 100,
            "%n"     * 500,
            "\"%n\"" * 500,
            "%s"     * 100,
            "%s"     * 500,
            "\"%s\"" * 500,

            # command injection.
            "|touch /tmp/SULLEY",
            ";touch /tmp/SULLEY;",
            "|notepad",
            ";notepad;",
            "\nnotepad\n",

            # SQL injection.
            "1;SELECT%20*",
            "'sqlattempt1",
            "(sqlattempt2)",
            "OR%201=1",

            # some binary strings.
            "\xde\xad\xbe\xef",
            "\xde\xad\xbe\xef" * 10,
            "\xde\xad\xbe\xef" * 100,
            "\xde\xad\xbe\xef" * 1000,
            "\xde\xad\xbe\xef" * 10000,
            "\x00"             * 1000,

            # miscellaneous.
            "\r\n" * 100,
            "<>" * 500,         # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
        ]

        # add some long strings.
        self.add_long_strings("A")
        self.add_long_strings("B")
        self.add_long_strings("1")
        self.add_long_strings("2")
        self.add_long_strings("3")
        self.add_long_strings("<")
        self.add_long_strings(">")
        self.add_long_strings("'")
        self.add_long_strings("\"")
        self.add_long_strings("/")
        self.add_long_strings("\\")
        self.add_long_strings("?")
        self.add_long_strings("=")
        self.add_long_strings("a=")
        self.add_long_strings("&")
        self.add_long_strings(".")
        self.add_long_strings(",")
        self.add_long_strings("(")
        self.add_long_strings(")")
        self.add_long_strings("]")
        self.add_long_strings("[")
        self.add_long_strings("%")
        self.add_long_strings("*")
        self.add_long_strings("-")
        self.add_long_strings("+")
        self.add_long_strings("{")
        self.add_long_strings("}")
        self.add_long_strings("\x14")
        self.add_long_strings("\xFE")   # expands to 4 characters under utf16
        self.add_long_strings("\xFF")   # expands to 4 characters under utf16

        # add some long strings with null bytes thrown in the middle of it.
        for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
            s = "B" * length
            s = s[:len(s)/2] + "\x00" + s[len(s)/2:]
            self.fuzz_library.append(s)

        # truncate fuzz library items to user-supplied length and pad, removing duplicates
        unique_mutants = []
        if self.size != -1:
            for mutant in self.fuzz_library:
                # truncate
                if len(mutant) > self.size:
                    mutant = mutant[:self.size]
                # pad
                else:
                    mutant_list = list(mutant)
                    filler = self.size - len(mutant)
                    for i in xrange(0, filler):
                        mutant_list.insert(len(mutant_list), "\x00")
                    mutant = "".join(mutant_list)
                
                # add to unique list   
                if mutant not in unique_mutants:        
                    unique_mutants.append(mutant)

            # assign unique list as fuzz library
            self.fuzz_library = unique_mutants


    def add_long_strings (self, sequence):
        '''
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        @type  sequence: String
        @param sequence: Sequence to repeat for creation of fuzz strings.
        '''

        for length in [128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2, 99999, 100000, 500000, 1000000]:

            long_string = sequence * length
            self.fuzz_library.append(long_string)


    def render (self):
        '''
        Render the primitive, encode the string according to the specified encoding.
        '''

        # try to encode the string properly and fall back to the default value on failure.
        try:
            self.rendered = str(self.value).encode(self.encoding)
        except:
            self.rendered = self.value

        return self.rendered


########################################################################################################################
class bit_field (base_primitive):
    def __init__ (self, value, width, **kwargs):
        '''
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:      Integer
        @param value:      Default integer value
        @type  width:      Integer
        @param width:      Width of bit fields
        @type  endian:     Character
        @kwarg endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  format:     String
        @kwarg format:     (Optional, def=binary) Output format, "binary" or "ascii"
        @type  signed:     Boolean
        @kwarg signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  full_range: Boolean
        @kwarg full_range: (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:   Boolean
        @kwarg fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:       String
        @kwarg name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        assert(type(value) is int or long)
        assert(type(width) is int or long)

        self.value         = self.original_value = value
        self.width         = width
        self.max_num       = kwargs.get("max_num",     None)
        self.endian        = kwargs.get("endian",      "<")
        self.format        = kwargs.get("format",      "binary")
        self.signed        = kwargs.get("signed",      False)
        self.full_range    = kwargs.get("full_range",  False)
        self.fuzzable      = kwargs.get("fuzzable",    True)
        self.name          = kwargs.get("name",        None)

        self.rendered      = ""        # rendered value
        self.fuzz_complete = False     # flag if this primitive has been completely fuzzed
        self.fuzz_library  = []        # library of fuzz heuristics
        self.mutant_index  = 0         # current mutation number

        if self.max_num == None:
            self.max_num = self.to_decimal("1" * width)

        # build the fuzz library.
        if self.full_range:
            # add all possible values.
            for i in xrange(0, self.max_num):
                self.fuzz_library.append(i)
        else:
            # try only "smart" values.
            self.add_integer_boundaries(0)
            self.add_integer_boundaries(self.max_num / 2)
            self.add_integer_boundaries(self.max_num / 3)
            self.add_integer_boundaries(self.max_num / 4)
            self.add_integer_boundaries(self.max_num / 8)
            self.add_integer_boundaries(self.max_num / 16)
            self.add_integer_boundaries(self.max_num / 32)
            self.add_integer_boundaries(self.max_num)


    def add_integer_boundaries (self, integer):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''

        for i in xrange(-10, 10):
            case = integer + i

            # ensure the border case falls within the valid range for this field.
            if 0 <= case <= self.max_num:
                if case not in self.fuzz_library:
                    self.fuzz_library.append(case)


    def render (self):
        '''
        Render the primitive.
        '''

        #
        # binary formatting.
        #

        if self.format == "binary":
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

        #
        # ascii formatting.
        #

        else:
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if self.signed and self.to_binary()[0] == "1":
                max_num = self.to_decimal("0" + "1" * (self.width - 1))
                # chop off the sign bit.
                val = self.value & max_num

                # account for the fact that the negative scale works backwards.
                val = max_num - val

                # toss in the negative sign.
                self.rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                self.rendered = "%d" % self.value

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


########################################################################################################################
class byte (bit_field):
    def __init__ (self, value, **kwargs):
        if type(value) not in [int, long]:
            value       = struct.unpack(kwargs.get("endian", "<") + "B", value)[0]

        bit_field.__init__(self, value, 8, **kwargs)


########################################################################################################################
class word (bit_field):
    def __init__ (self, value, **kwargs):
        if type(value) not in [int, long]:
            value = struct.unpack(kwargs.get("endian", "<") + "H", value)[0]

        bit_field.__init__(self, value, 16, **kwargs)


########################################################################################################################
class dword (bit_field):
    def __init__ (self, value, **kwargs):
        if type(value) not in [int, long]:
            value = struct.unpack(kwargs.get("endian", "<") + "L", value)[0]

        bit_field.__init__(self, value, 32, **kwargs)


########################################################################################################################
class qword (bit_field):
    def __init__ (self, value, **kwargs):
        if type(value) not in [int, long]:
            value = struct.unpack(kwargs.get("endian", "<") + "Q", value)[0]

        bit_field.__init__(self, value, 64, **kwargs)