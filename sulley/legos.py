import blocks
import primitives
import sex

# all defined legos must be added to this bin.
BIN = {}

########################################################################################################################
class tag (blocks.block):
    def __init__ (self, name, request, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.options = options

        if not self.options.has_key("tag"):
            raise sex.error("MISSING LEGO OPTION: default tag value.")

        # <example>
        # [delim][string][delim]

        self.push(primitives.delim("<"))
        self.push(primitives.string(""))
        self.push(primitives.delim(">"))

BIN["tag"] = tag


########################################################################################################################