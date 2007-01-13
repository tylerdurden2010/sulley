#!/usr/bin/env python

import os, sys, time, struct, string

from Block import *

'''
"main" {
    0x41
    "child 1" {
        0x00005
        0x41 * 500
    }
    "child 2" {
        0x10101010
        "child 3" {
            0x1 || 0x1001
            "child 4" {
                "child 5" {
                }
                0x12345678
            }
        }
        0x7ffffffff
    }
}

fuzz 1, 4, 3, 2
'''

# Main block
main = ContainerBlock("main")

# Child block 1 (solo)
main.create_block("child 1")
main.add_number("magic", 4, comment="Looks like a magic value", values=[0x00005], fuzz="smart")
main.add_number("filename", 4, values=[0x41 * 500])
main.close_block("child 1")

# Child block 2 (contains child block 3)
main.create_block("child 2")
main.add_number("binary", 4, values=[0x10101010, 0x1234])

# Child block 3 (showing conditional field)
main.create_block("child 3")
data = 0x2
if data == 0x1:
    main.add_number("size", 1, values=0x01)
elif data == 0x2:
    main.add_number("size", 2, values=0x1001)

main.create_block("child 4")
main.create_block("child 5")
main.close_block("child 5")
main.add_number("test", 4, values=[0x12345678])
main.close_block("child 4")
main.close_block("child 3")

main.add_number("offset", 4, values=[0x7fffffff])
main.close_block("child 2")

# Closing main block
main.close_block("main")

# Demo getting just one block and print contents
block = main.get_block("child 1")

print "\n%s:" % (block.name)
#for bl in block.blocks:
#    if bl.content:
#        print "Name: %s\tData: 0x%x" % (bl.content["name"], bl.content["data"])
#

# Demo printing all data
#data = []
#main.dump_data(data)
#
#print "\n%s:" % (main.name)
#for d in data:
#    print "0x%x" % d

#
#fuzz_blocks = []
#b.get_fuzz_blocks(fuzz_blocks)
#for block in fuzz_blocks:
#    print "%s can be fuzzed" % (block.name)
#    
#fuzzer = Fuzz(b)