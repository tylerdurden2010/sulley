from sulley import *

def run ():
    signed_tests()
    string_tests()

    # clear out the requests.
    blocks.REQUESTS = {}
    blocks.CURRENT  = None


########################################################################################################################
def signed_tests ():
    s_initialize("UNIT TEST 1")
    s_byte(0,        format="ascii", signed=True, name="byte_1")
    s_byte(0xff/2,   format="ascii", signed=True, name="byte_2")
    s_byte(0xff/2+1, format="ascii", signed=True, name="byte_3")
    s_byte(0xff,     format="ascii", signed=True, name="byte_4")

    s_word(0,          format="ascii", signed=True, name="word_1")
    s_word(0xffff/2,   format="ascii", signed=True, name="word_2")
    s_word(0xffff/2+1, format="ascii", signed=True, name="word_3")
    s_word(0xffff,     format="ascii", signed=True, name="word_4")

    s_dword(0,              format="ascii", signed=True, name="dword_1")
    s_dword(0xffffffff/2,   format="ascii", signed=True, name="dword_2")
    s_dword(0xffffffff/2+1, format="ascii", signed=True, name="dword_3")
    s_dword(0xffffffff,     format="ascii", signed=True, name="dword_4")

    s_qword(0,                      format="ascii", signed=True, name="qword_1")
    s_qword(0xffffffffffffffff/2,   format="ascii", signed=True, name="qword_2")
    s_qword(0xffffffffffffffff/2+1, format="ascii", signed=True, name="qword_3")
    s_qword(0xffffffffffffffff,     format="ascii", signed=True, name="qword_4")

    req = s_get("UNIT TEST 1")

    assert(req.names["byte_1"].render()  == "0")
    assert(req.names["byte_2"].render()  == "127")
    assert(req.names["byte_3"].render()  == "-128")
    assert(req.names["byte_4"].render()  == "-1")
    assert(req.names["word_1"].render()  == "0")
    assert(req.names["word_2"].render()  == "32767")
    assert(req.names["word_3"].render()  == "-32768")
    assert(req.names["word_4"].render()  == "-1")
    assert(req.names["dword_1"].render() == "0")
    assert(req.names["dword_2"].render() == "2147483647")
    assert(req.names["dword_3"].render() == "-2147483648")
    assert(req.names["dword_4"].render() == "-1")
    assert(req.names["qword_1"].render() == "0")
    assert(req.names["qword_2"].render() == "9223372036854775807")
    assert(req.names["qword_3"].render() == "-9223372036854775808")
    assert(req.names["qword_4"].render() == "-1")
    
    
########################################################################################################################
def string_tests ():

    s_initialize("STRING UNIT TEST 1")
    s_string("foo", size=200, name="sized_string")

    req = s_get("STRING UNIT TEST 1")

    assert(len(req.names["sized_string"].render()) == 3)

    # check that string padding and truncation are working correctly.
    for i in xrange(0, 50):
        s_mutate()
        assert(len(req.names["sized_string"].render()) == 200)
        
  