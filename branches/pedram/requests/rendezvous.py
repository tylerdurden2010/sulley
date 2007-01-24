from sulley import *

########################################################################################################################
s_initialize("announce")

# transaction ID
s_word(0x0000)                              

#
# flags
#

# 1: response, 0: query
s_bit_field(0, width=1, name="flags_response")                     

# opcode, 0, standard query
s_bit_field(0, width=4)

# authoritative flag, raise this for responses.
if s_block_start("authoritiative_yes", dep="flags_response", dep_value=1):
    s_bit_field(1, width=1, fuzzable=False)
    s_block_end()

if s_block_start("authoritiative_no", dep="flags_response", dep_value=0):
    s_bit_field(0, width=1, fuzzable=False)
    s_block_end()

s_bit_field(0, width=1, fuzzable=False)     # truncated
s_bit_field(0, width=1)                     # recursion desired
s_bit_field(0, width=1, fuzzable=False)     # recursion available
s_bit_field(0, width=1, fuzzable=False)     # reserved
s_bit_field(0, width=1, fuzzable=False)     # answer authenticated
s_bit_field(0, width=1, fuzzable=False)     # ???
s_bit_field(0, width=4, fuzzable=False)     # reply code, 0, no error

#
# question / response counts
#

s_word(0, name="questions")
s_word(0, name="answer_rrs")
s_word(0, name="authority_rrs")
s_word(0, name="additional_rrs")

#
# question / response tables
#

if s_block_start("answers"):
    # name
    s_sizer("name_part_1", length=1)
    if s_block_start("name_part_1"):
        s_string("pedfuzz")
        s_block_end()
        
    s_sizer("name_part_2", length=1)
    if s_block_start("name_part_2"):
        s_string("part2")
        s_block_end()

    s_sizer("name_part_3", length=1)
    if s_block_start("name_part_3"):
        s_string("local")
        s_block_end()

    # null terminator for name.
    s_static("\x00")

    # answer type.
    s_group("answer_type", values=["\x00\x01",      # A (host address)
                                   "\x00\x0c",      # PTR (domain name pointer)
                                   "\x00\x21",      # SRV (service location)
                                   "\x00\x10"])     # TXT (text strings)

    if s_block_start("answer_type_a", dep="answer_type", dep_value="\x00\x01"):
        s_word(0x8001)          # class, FLUSH
        s_dword(0x000000f0)     # TTL: 4 minutes
        s_sizer("answer_type_a_data", length=2)
        if s_block_start("answer_type_a_data"):
            s_string("\x0a\x0a\x14\x6f")        # ip address
            s_block_end()
        s_block_end()
    
    if s_block_start("answer_type_srv", dep="answer_type", dep_value="\x00\x21"):
        s_word(0x8001)          # class, FLUSH
        s_dword(0x000000f0)     # TTL: 4 minutes
        s_sizer("answer_type_srv_data", length=2)
        if s_block_start("answer_type_srv_data"):
            s_sizer("answer_type_srv_part_1", length=1)
            if s_block_start("answer_type_srv_part_1"):
                s_string("txtvers")
                s_delim("=")
                s_string("1")
                s_block_end()
            s_sizer("answer_type_srv_part_2", length=1)
            if s_block_start("answer_type_srv_part_2"):
                s_static("1st=")
                s_string("pedram")
                s_block_end()
            s_sizer("answer_type_srv_part_3", length=1)
            if s_block_start("answer_type_srv_part_3"):
                s_static("status=")
                s_string("avail")
                s_block_end()
            s_block_end()
        s_block_end()
    
    s_block_end()
