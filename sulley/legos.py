import struct

import blocks
import primitives
import sex

# all defined legos must be added to this bin.
BIN = {}

########################################################################################################################
class tag (blocks.block):
    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.error("MISSING LEGO.tag DEFAULT VALUE")

        # <example>
        # [delim][string][delim]

        self.push(primitives.delim("<"))
        self.push(primitives.string(self.value))
        self.push(primitives.delim(">"))

BIN["tag"] = tag


########################################################################################################################
class ndr_string (blocks.block):
    '''
    XXX - UNFINISHED
        - must include padding
        - unicode formatting
        - etc...
        
    note this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    '''
    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.error("MISSING LEGO.tag DEFAULT VALUE")

        # [dword length][dword offset][dword passed size][string]

        self.push(primitives.string(self.value))


    def render (self):
        '''
        We overload and extend the render routine in order to properly pad and prefix the string.
        '''
        
        # let the parent do the initial render.
        blocks.block.render(self)
        
        # null pad.
        self.rendered += "\x00"
        length         = len(self.rendered)
        self.rendered  = struct.pack("<L", length) + struct.pack("<L", 0) + struct.pack("<L", length) + self.rendered

BIN["ndr_string"] = ndr_string