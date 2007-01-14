from sulley import *

def run ():
    tag()

def tag ():
    s_initialize("UNIT TEST 1")
    s_lego("tag", options={"tag":"pedram"})


    req = s_get("UNIT TEST 1")

    print "LEGO MUTATION COUNTS:"
    print "\ttag:    %d" % req.num_mutations()