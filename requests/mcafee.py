from sulley import *

from struct import *

# stupid one byte XOR
def mcafee_epo_xor(buf, poly=0xAA):
    l = len(buf)
    new_buf = ""

    for char in buf:
        new_buf += chr(ord(char) ^ poly)

    return new_buf

########################################################################################################################
s_initialize("mcafee_epo_framework_tcp")
"""
    McAfee FrameworkService.exe TCP port 8081
"""

s_static("POST", name="post_verb")
s_delim(" ")
s_group("paths", ["/spipe/pkg", "/spipe/file", "default.htm"])
s_delim("?")
s_string("URL")
s_delim("=")
s_string("TESTFILE")
s_delim("\r\n")

s_static("Content-Length:")
s_delim(" ")
s_size("payload", format="ascii")
s_delim("\r\n\r\n")

if s_block_start("payload"):
    s_string("TESTCONTENTS")
    s_delim("\r\n")
s_block_end()


########################################################################################################################
s_initialize("mcafee_epo_framework_udp")
"""
    McAfee FrameworkService.exe UDP port 8082
"""

s_static('Type=\"AgentWakeup\"', name="agent_wakeup")
s_static('\"DataSize=\"')
s_size("data", format="ascii") # must be over 234

if s_block_start("data", encoder=mcafee_epo_xor):
    s_static("\x50\x4f", name="signature")
    s_group(values=[pack('<L', 0x40000001), pack('<L', 0x30000001), pack('<L', 0x20000001)], name="opcode")
    s_size("data", length=4) #XXX: needs to be size of data - 1 !!!

    s_string("size", size=210)
    s_static("EPO\x00")
    s_dword(1, name="other_opcode")

s_block_end()