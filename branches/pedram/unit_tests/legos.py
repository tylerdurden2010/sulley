from sulley import *

def run ():
    tag()
    ndr_string()

    # clear out the requests.
    blocks.REQUESTS = {}
    blocks.CURRENT  = None


########################################################################################################################
def tag ():
    s_initialize("UNIT TEST 1")
    s_lego("tag", value="pedram")

    req = s_get("UNIT TEST 1")

    print "LEGO MUTATION COUNTS:"
    print "\ttag:    %d" % req.num_mutations()


########################################################################################################################
def ndr_string ():
    s_initialize("UNIT TEST 2")
    s_lego("ndr_string", value="pedram")

    req = s_get("UNIT TEST 2")
    # XXX - unfinished!
    #print req.render()