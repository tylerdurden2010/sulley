import struct
import math
import re


########################################################################################################################
def crc16 (string, value=0):
    '''
    CRC-16 poly: p(x) = x**16 + x**15 + x**2 + 1
    '''

    crc16_table = []

    for byte in range(256):
         crc = 0

         for bit in range(8):
             if (byte ^ crc) & 1: crc = (crc >> 1) ^ 0xa001  # polly
             else:                crc >>= 1

             byte >>= 1

         crc16_table.append(crc)

    for ch in string:
        value = crc16_table[ord(ch) ^ (value & 0xff)] ^ (value >> 8)

    return value


########################################################################################################################
def dce_rpc_bind (uuid, version):
    '''
    Generate the data necessary to bind to the specified interface.
    '''

    major, minor = version.split(".")

    major = struct.pack("<H", int(major))
    minor = struct.pack("<H", int(minor))

    bind  = "\x05\x00"                      # version 5.0
    bind += "\x0b"                          # packet type = bind (11)
    bind += "\x03"                          # packet flags = last/first flag set
    bind += "\x10\x00\x00\x00"              # data representation
    bind += "\x48\x00"                      # frag length: 72
    bind += "\x00\x00"                      # auth length
    bind += "\x00\x00\x00\x00"              # call id
    bind += "\xb8\x10"                      # max xmit frag (4280)
    bind += "\xb8\x10"                      # max recv frag (4280)
    bind += "\x00\x00\x00\x00"              # assoc group
    bind += "\x01"                          # number of ctx items (1)
    bind += "\x00\x00\x00"                  # padding
    bind += "\x00\x00"                      # context id (0)
    bind += "\x01"                          # number of trans items (1)
    bind += "\x00"                          # padding
    bind += uuid_str_to_bin(uuid)           # abstract syntax
    bind += major                           # interface version
    bind += minor                           # interface version minor

    # transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
    bind += "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
    bind += "\x02\x00\x00\x00"

    return bind


########################################################################################################################
def dce_rpc_bind_ack (data):
    '''
    Ensure the data is a bind ack and that the
    '''

    # packet type == bind ack (12)?
    if data[2] != "\x0c":
        return False

    # ack result == acceptance?
    if data[36:38] != "\x00\x00":
        return False

    return True


########################################################################################################################
def dce_rpc_request (opnum, data):
    '''
    Return a list of packets broken into 5k fragmented chunks necessary to make the RPC request.
    '''

    frag_size = 1000     # max frag size = 5840?
    frags     = []

    num_frags = int(math.ceil(float(len(data)) / float(frag_size)))

    for i in xrange(num_frags):
        chunk       = data[i * frag_size:(i+1) * frag_size]
        frag_length = struct.pack("<H", len(chunk) + 24)
        alloc_hint  = struct.pack("<L", len(chunk))

        flags = 0
        if i == 0:              flags |= 0x1    # first frag
        if i == num_frags - 1:  flags |= 0x2    # last frag

        request  = "\x05\x00"                   # version 5.0
        request += "\x00"                       # packet type = request (0)
        request += struct.pack("B", flags)      # packet flags
        request += "\x10\x00\x00\x00"           # data representation
        request += frag_length                  # frag length
        request += "\x00\x00"                   # auth length
        request += "\x00\x00\x00\x00"           # call id
        request += alloc_hint                   # alloc hint
        request += "\x00\x00"                   # context id (0)
        request += struct.pack("<H", opnum)     # opnum
        request += chunk

        frags.append(request)

    # you don't have to send chunks out individually. so make life easier for the user and send them all at once.
    return "".join(frags)


########################################################################################################################
def dnp3 (data, control_code="\x44", src="\x00\x00", dst="\x00\x00"):
    num_packets = int(math.ceil(float(len(data)) / 250.0))
    packets     = []

    for i in xrange(num_packets):
        slice = data[i*250 : (i+1)*250]

        p  = "\x05\x64"
        p += chr(len(slice))
        p += control_code
        p += dst
        p += src

        chksum = struct.pack("<H", crc16(p))

        p += chksum

        num_chunks = int(math.ceil(float(len(slice) / 16.0)))

        # insert the fragmentation flags / sequence number.
        # first frag: 0x40, last frag: 0x80

        frag_number = i

        if i == 0:
            frag_number |= 0x40

        if i == num_packets - 1:
            frag_number |= 0x80

        p += chr(frag_number)

        for x in xrange(num_chunks):
            chunk   = slice[i*16 : (i+1)*16]
            chksum  = struct.pack("<H", crc16(chunk))
            p      += chksum + chunk

        packets.append(p)

    return packets


########################################################################################################################
def uuid_bin_to_str (uuid):
    '''
    Convert a binary UUID to human readable string.
    '''

    (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
    (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

    return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)


########################################################################################################################
def uuid_str_to_bin (uuid):
    '''
    Ripped from Core Impacket. Converts a UUID string to binary form.
    '''

    matches = re.match('([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})', uuid)

    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: long(x, 16), matches.groups())

    uuid  = struct.pack('<LHH', uuid1, uuid2, uuid3)
    uuid += struct.pack('>HHL', uuid4, uuid5, uuid6)

    return uuid