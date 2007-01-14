from sulley import *

def run ():
    num_test_cases()
    blocks.REQUESTS = {}
    blocks.CURRENT  = None

def num_test_cases ():
    s_initialize("UNIT TEST 1")
    s_size("BLOCK", length=4, name="sizer")
    s_group("group", values=["\x01", "\x05", "\x0a", "\xff"])
    if s_block_start("BLOCK"):
        s_delim(">", name="delim")
        s_string("pedram", name="string")
        s_byte(0xde, name="byte")
        s_word(0xdead, name="word")
        s_dword(0xdeadbeef, name="dword")
        s_qword(0xdeadbeefdeadbeef, name="qword")
        s_random(0, 5, 10, 100, name="random")
        s_block_end()


    # count how many mutations we get per primitive type.
    req1 = s_get("UNIT TEST 1")
    print "PRIMITIVE MUTATION COUNTS:"
    print "\tdelim:  %d" % req1.names["delim"].num_mutations()
    print "\tstring: %d" % req1.names["string"].num_mutations()
    print "\tbyte:   %d" % req1.names["byte"].num_mutations()
    print "\tword:   %d" % req1.names["word"].num_mutations()
    print "\tdword:  %d" % req1.names["dword"].num_mutations()
    print "\tqword:  %d" % req1.names["qword"].num_mutations()
    print "\tsizer:  %d" % req1.names["sizer"].num_mutations()

    # we specify the number of mutations in a random field, so ensure that matches.
    assert(req1.names["random"].num_mutations() == 100)

    # we specify the number of values in a group field, so ensure that matches.
    assert(req1.names["group"].num_mutations() == 4)

    # assert that the number of block mutations equals the sum of the number of mutations of its components.
    assert(req1.names["BLOCK"].num_mutations() == req1.names["delim"].num_mutations()  + \
                                                  req1.names["string"].num_mutations() + \
                                                  req1.names["byte"].num_mutations()   + \
                                                  req1.names["word"].num_mutations()   + \
                                                  req1.names["dword"].num_mutations()  + \
                                                  req1.names["qword"].num_mutations()  + \
                                                  req1.names["random"].num_mutations())

    s_initialize("UNIT TEST 2")
    s_group("group", values=["\x01", "\x05", "\x0a", "\xff"])
    if s_block_start("BLOCK", group="group"):
        s_delim(">", name="delim")
        s_string("pedram", name="string")
        s_byte(0xde, name="byte")
        s_word(0xdead, name="word")
        s_dword(0xdeadbeef, name="dword")
        s_qword(0xdeadbeefdeadbeef, name="qword")
        s_random(0, 5, 10, 100, name="random")
        s_block_end()

    # assert that the number of block mutations in request 2 is len(group.values) (4) times that of request 1.
    req2 = s_get("UNIT TEST 2")
    assert(req2.names["BLOCK"].num_mutations() == req1.names["BLOCK"].num_mutations() * 4)
