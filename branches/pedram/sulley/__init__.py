import sulley.blocks
import sulley.legos
import sulley.primitives
import sulley.sex

BIG_ENDIAN      = ">"
LITTLE_ENDIAN   = "<"


########################################################################################################################
### REQUEST MANAGEMENT
########################################################################################################################

def s_copy (src, dst):
    '''
    Make a copy of request src.
    '''
    
    pass


def s_initialize (name):
    '''
    Initialize a new block request. All blocks / primitives generated after this call apply to the named request.
    Use s_switch() to jump between factories.

    @type  name: String
    @param name: Name of request
    '''

    if blocks.REQUESTS.has_key(name):
        raise sex.error("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    blocks.REQUESTS[name] = blocks.request()
    blocks.CURRENT        = blocks.REQUESTS[name]


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
### BLOCKS MANAGEMENT
########################################################################################################################

def s_block_start (name, encoder=None):
    '''
    Open a new block under the current request. This routine always returns True so you can make your fuzzer pretty
    with indenting::

        if s_block_start("header"):
            s_static("\x00 \x01")
            if s_block_start("body"):
                ...

    @type  name: String
    @param name: Name of block being opened
    '''

    block = blocks.block(name, blocks.CURRENT, encoder)
    blocks.CURRENT.push(block)

    return True


def s_block_end ():
    '''
    Close the last opened block.
    '''

    blocks.CURRENT.pop()


def s_checksum (block_name, algorithm="crc32", length=0, endian="<"):
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
    '''

    # you can't add a checksum for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.error("CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")

    checksum = blocks.checksum(block_name, blocks.CURRENT, algorithm, length, endian)
    blocks.CURRENT.push(checksum)


def s_size (block_name, length=4, endian="<", fuzzable=False):
    '''
    Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
    currently open blocks.

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
    @type  length:     Integer
    @param length:     (Optional, def=4) Length of sizer
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=False) Enable/disable fuzzing of this sizer
    '''

    # you can't add a size for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.error("CAN NOT ADD A SIZE FOR A BLOCK CURRENTLY IN THE STACK")

    size = blocks.size(block_name, blocks.CURRENT, length, endian, fuzzable)
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

def s_delim (value, max_rep=100, fuzzable=True, name=None):
    '''
    Push a delimiter onto the current block stack.
    
    @type  value:    Character
    @param value:    Original value
    @type  max_rep:  Integer
    @param max_rep:  (Optional, def=100) Maximum delimiter repetition length
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''
    
    delim = primitives.delim(value, max_rep, fuzzable, name)
    blocks.CURRENT.push(delim)
    

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

    random = primitives.random(value, min_length, max_length, num_mutations, fuzzable, name)
    blocks.CURRENT.push(random)
    

def s_static (value, name=None):
    '''
    Push a stack value onto the current block stack.
    
    @type  value: Raw
    @param value: Raw static data
    @type  name:  String
    @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    static = primitives.static(value, name)
    blocks.CURRENT.push(static)


def s_string (value, length=None, fuzzable=True, name=None):
    '''
    Push a string onto the current block stack.

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
    
    s = primitives.string(value, length, fuzzable, name)
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


def s_short (value, max_num=None, endian="<", fuzzable=True, name=None):
    '''
    Push a short onto the current block stack.
    
    @type  value:    Integer
    @param value:    Default integer value
    @type  endian:   Character
    @param endian:   (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    '''

    short = primitives.short(value, max_num, endian, fuzzable, name)
    blocks.CURRENT.push(short)


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
s_dunno  = s_raw = s_static