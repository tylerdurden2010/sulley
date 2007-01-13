#!c:\\python\\python.exe

'''
todo:
    - expand mutate with flag to toggle between smart, full and random.
    - make sizers fuzzable
    - add dependencies (conditionals)
    - expand parameter types from white board
    - address TODOs
    - text sizers? ie: content-length from http
'''

from sulley import *

import base64
import sys

s_initialize("packet 1")

s_qword(0xdeadbeefdeadbeef)
s_static(">>>")
s_dword(0xdeadbeef, endian=BIG_ENDIAN)
s_static(">>>")
s_short(0xdead, name="i'm a short")
s_static(">>>")
s_byte(0xde)
s_static(">>>")

s_sizer("header")
s_static(">>>")
if s_block_start("header", encoder=base64.b64encode):
    s_static("pedram amini")
    s_static(" is the coolest")
    s_short(0xdead)
    s_byte(0xde)
    s_string("pedram")
    s_block_end()

s_static(">>>")
s_sizer("body")
s_static(">>>")
s_checksum("body")
s_static(">>>")
if s_block_start("body"):
    s_static(" weeee")
    s_static(">>>")
    s_qword(0xdeadbeefdeadbeef, name="changeme", endian=BIG_ENDIAN)
    s_static(">>>")
    s_dword(0xdeadbeef)
    s_static(">>>")
    s_short(0xdead)
    s_static(">>>")
    s_group("opcodes", values=["\x01", "\x02", "\x03"])
    if s_block_start("embedded", group="opcodes"):
        s_delim("@")
        s_static(">>>")
        s_random("random", 10, 200)
        s_static(">>>")
        s_string("pedram")
        s_static(">>>")
        s_block_end()
    s_block_end()

s_static(">>>")
s_checksum("body")
s_static(">>>")
s_static(" footer")    
s_static(">>>")
s_static(" final.")
s_static(">>>")

print blocks.CURRENT.num_mutations()

while 1:
    print "[%d of %d]\r" % (blocks.CURRENT.mutant_index, blocks.CURRENT.num_mutations()),
    data   = s_render()
    
    if not s_mutate():
        print
        break

print blocks.CURRENT.mutant_index

blocks.CURRENT.reset()

while 1:
    #print s_hex_dump(s_render())

    if not s_mutate():
        break
    
print blocks.CURRENT.mutant_index

#s_update("changeme", 0xaaaaaaaaaaaaaa)
#print s_render()
#s_mutate()
#print "." * 80
#print s_render()
