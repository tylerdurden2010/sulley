import sulley.blocks
import sulley.legos
import sulley.primitives
import sulley.sex
import sulley.sessions

BIG_ENDIAN      = ">"
LITTLE_ENDIAN   = "<"


########################################################################################################################
### REQUEST MANAGEMENT
########################################################################################################################

def s_get (name=None):
    '''
    Return the request with the specified name or the current request if name is not specified.

    @type  name: String
    @param name: (Optional, def=None) Name of request to return or current request if name is None.

    @rtype:  blocks.request
    @return: The requested request.
    '''

    if not name:
        return blocks.CURRENT

    if not blocks.REQUESTS.has_key(name):
        raise sex.error("blocks.REQUESTS NOT FOUND: %s" % name)

    return blocks.REQUESTS[name]


def s_initialize (name):
    '''
    Initialize a new block request. All blocks / primitives generated after this call apply to the named request.
    Use s_switch() to jump between factories.

    @type  name: String
    @param name: Name of request
    '''

    if blocks.REQUESTS.has_key(name):
        raise sex.error("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    blocks.REQUESTS[name] = blocks.request(name)
    blocks.CURRENT        = blocks.REQUESTS[name]


def s_mutate ():
    '''
    Mutate the current request.
    '''

    return blocks.CURRENT.mutate()


def s_render ():
    '''
    Render out and return the entire contents of the current request.
    '''

    return blocks.CURRENT.render()


def s_switch (name):
    '''
    Change the currect request to the one specified by "name".

    @type  name: String
    @param name: Name of request
    '''

    if not blocks.REQUESTS.has_key(name):
        raise sex.error("blocks.REQUESTS NOT FOUND: %s" % name)

    blocks.CURRENT = blocks.REQUESTS[name]


########################################################################################################################
### BLOCK MANAGEMENT
########################################################################################################################

def s_block_start (name, group=None, encoder=None, dep=None, dep_value=None):
    '''
    Open a new block under the current request. This routine always returns True so you can make your fuzzer pretty
    with indenting::

        if s_block_start("header"):
            s_static("\x00 \x01")
            if s_block_start("body"):
                ...

    @type  name:      String
    @param name:      Name of block being opened
    @type  group:     String
    @param group:     (Optional, def=None) Name of group to associate this block with
    @type  encoder:   Function Pointer
    @param encoder:   (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
    @type  dep:       String
    @param dep:       (Optional, def=None) Optional primitive whose specific value this block is dependant on
    @type  dep_value: Mixed
    @param dep_value: (Optional, def=None) Value that field "dep" must contain for block to be rendered
    '''

    block = blocks.block(name, blocks.CURRENT, group, encoder, dep, dep_value)
    blocks.CURRENT.push(block)

    return True


def s_block_end (name=None):
    '''
    Close the last opened block.
    '''

    blocks.CURRENT.pop()


def s_checksum (block_name, algorithm="crc32", length=0, endian="<", name=None):
    '''
    Create a checksum block bound to the block with the specified name. You *can not* create a checksum for any
    currently open blocks.

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
    @type  algorithm:  String
    @param algorithm:  (Optional, def=crc32) Checksum algorithm to use. (crc32, adler32, md5, sha1)
    @type  length:     Integer
    @param length:     (Optional, def=0) Length of checksum, specify 0 to auto-calculate
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  name:       String
    @param name:       Name of this checksum field
    '''

    # you can't add a checksum for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.error("CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")

    checksum = blocks.checksum(block_name, blocks.CURRENT, algorithm, length, endian, name)
    blocks.CURRENT.push(checksum)


def s_size (block_name, length=4, endian="<", format="binary", fuzzable=False, name=None):
    '''
    Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
    currently open blocks.

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
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

    # you can't add a size for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.error("CAN NOT ADD A SIZE FOR A BLOCK CURRENTLY IN THE STACK")

    size = blocks.size(block_name, blocks.CURRENT, length, endian, format, fuzzable, name)
    blocks.CURRENT.push(size)


def s_update (name, value):
    '''
    Update the value of the named primitive in the currently open request.

    @type  name:  String
    @param name:  Name of object whose value we wish to update
    @type  value: Mixed
    @param value: Updated value
    '''

    if not blocks.CURRENT.names.has_key(name):
        raise sex.error("NO OBJECT WITH NAME '%s' FOUND IN CURRENT REQUEST" % name)

    blocks.CURRENT.names[name].value = value


########################################################################################################################
### PRIMITIVES
########################################################################################################################

def s_binary (value, name=None):
    '''
    Parse a variable format binary string into a static value and push it onto the current block stack.

    @type  value: String
    @param value: Variable format binary string
    @type  name:  String
    @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    # parse the binary string into.
    parsed = value
    parsed = parsed.replace(" ",   "")
    parsed = parsed.replace("\t",  "")
    parsed = parsed.replace("\r",  "")
    parsed = parsed.replace("\n",  "")
    parsed = parsed.replace(",",   "")
    parsed = parsed.replace("0x",  "")
    parsed = parsed.replace("\\x", "")

    value = ""
    while parsed:
        pair   = parsed[:2]
        parsed = parsed[2:]

        value += chr(int(pair, 16))

    static = primitives.static(value, name)
    blocks.CURRENT.push(static)


def s_delim (value, fuzzable=True, name=None):
    '''
    Push a delimiter onto the current block stack.

    @type  value:    Character
    @param value:    Original value
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    delim = primitives.delim(value, fuzzable, name)
    blocks.CURRENT.push(delim)


def s_group (name, values):
    '''
    This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
    to a group primitive to specify that the block should cycle through all possible mutations for *each* value
    within the group. The group primitive is useful for example for representing a list of valid opcodes.

    @type  name:   String
    @param name:   Name of group
    @type  values: List or raw data
    @param values: List of possible raw values this group can take.
    '''

    group = primitives.group(name, values)
    blocks.CURRENT.push(group)


def s_lego (lego_type, options={}):
    '''
    Legos are pre-built blocks... XXX finish this doc
    '''

    # as legos are blocks they must have a name.
    # generate a unique name for this lego.
    name = "LEGO_%04d" % len(blocks.CURRENT.names)

    if not legos.BIN.has_key(lego_type):
        raise sex.error("INVALID LEGO TYPE SPECIFIED: %s" % lego_type)

    lego = legos.BIN[lego_type](name, blocks.CURRENT, options)
    blocks.CURRENT.push(lego)


def s_random (value, min_length, max_length, num_mutations=25, fuzzable=True, name=None):
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

    random = primitives.random_data(value, min_length, max_length, num_mutations, fuzzable, name)
    blocks.CURRENT.push(random)


def s_static (value, name=None):
    '''
    Push a static value onto the current block stack.

    @type  value: Raw
    @param value: Raw static data
    @type  name:  String
    @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    static = primitives.static(value, name)
    blocks.CURRENT.push(static)


def s_string (value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, name=None):
    '''
    Push a string onto the current block stack.

    @type  value:    String
    @param value:    Default string value
    @type  size:     Integer
    @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
    @type  padding:  Character
    @param padding:  (Optional, def="\x00") Value to use as padding to fill static field size.
    @type  encoding: String
    @param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    s = primitives.string(value, size, padding, encoding, fuzzable, name)
    blocks.CURRENT.push(s)


def s_bit_field (value, width, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a variable length bit field onto the current block stack.

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

    bit_field = primitives.bit_field(value, width, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(bit_field)


def s_byte (value, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a byte onto the current block stack.

    @type  value:    Integer
    @param value:    Default integer value
    @type  endian:   Character
    @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    byte = primitives.byte(value, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(byte)


def s_word (value, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a word onto the current block stack.

    @type  value:    Integer
    @param value:    Default integer value
    @type  endian:   Character
    @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    word = primitives.word(value, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(word)


def s_dword (value, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a double word onto the current block stack.

    @type  value:    Integer
    @param value:    Default integer value
    @type  endian:   Character
    @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    dword = primitives.dword(value, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(dword)


def s_qword (value, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a quad word onto the current block stack.

    @type  value:    Integer
    @param value:    Default integer value
    @type  endian:   Character
    @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    qword = primitives.qword(value, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(qword)


########################################################################################################################
### ALIASES
########################################################################################################################

s_dunno  = s_raw = s_static
s_sizer  = s_size
s_bits   = s_bit_field
s_char   = s_byte
s_short  = s_word
s_long   = s_int = s_dword
s_double = s_qword


########################################################################################################################
### MISC
########################################################################################################################

def s_hex_dump (data, addr=0):
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
