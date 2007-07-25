#!c:\python\python.exe
#
# Aaron Portnoy
# TippingPoint Security Research Team
# (C) 2007
#

import sys

constants     = []
start_address = SegByName(".text")

# loop heads
for head in Heads(start_address, SegEnd(start_address)):
    
    # if it's code, check for cmp instruction
    if isCode(GetFlags(head)):
        mnem = GetMnem(head)
        op1 = int(GetOperandValue(head, 1))
        
        # if it's a cmp and it's immediate value is unique, add it to the list
        if "cmp" in mnem and op1 not in constants:
            constants.append(op1)
             
print "Found %d constant values used in compares." % len(constants)
print "-----------------------------------------------------"
for i in xrange(0, len(constants), 20):
    print constants[i:i+20]