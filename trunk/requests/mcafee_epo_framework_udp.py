from sulley import *

from struct import pack

# stupid one byte XOR
def mcafee_xor(buf, poly=0xAA):
    l = len(buf)
    new_buf = ""

    for char in buf:
        new_buf += chr(ord(char) ^ poly)
    
    return new_buf
    
########################################################################################################################
s_initialize("mcafee_epo_framework_udp")
"""
    McAfee FrameworkService.exe UDP port 8082
"""

s_static('Type=\"AgentWakeup\"', name="agent_wakeup")
s_static('\"DataSize=\"')
s_size("data", format="ascii") # must be over 234

if s_block_start("data", encoder="mcafee_xor"):
    s_static("\x50\x4f", name="signature")
    s_group(values=[pack('<L', 0x400000001), pack('<L', 0x300000001), pack('<L', 0x200000001)], name="opcode")
    s_size("data", length=4) #XXX: needs to be size of data - 1 !!!
    
    s_string(size=210)
    s_cstring("EPO", fuzzable=False)
    s_dword(1, name="other_opcode")
    
s_block_end()    

    