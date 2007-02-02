from sulley import *


########################################################################################################################
s_initialize("simple bind")

# all ldap messages start with this.
s_static("\x30")       

# length of entire envelope.
s_static("\x84")
s_sizer("envelope", endian=">")

if s_block_start("envelope"):
    s_static("\x02\x01\x01")        # message id (always one)
    s_static("\x60")                # bind request
    
    s_static("\x84")
    s_sizer("bind request", endian=">")

    if s_block_start("bind request"):
        s_static("\x02\x01\x02")    # version
        
        s_lego("ber_string", "anonymous")
        s_lego("ber_string", "foobar", options={"prefix":"\x80"})   # 0x80 is "simple" authentication
    s_block_end()
s_block_end()


########################################################################################################################
s_initialize("sasl bind")

# all ldap messages start with this.
s_static("\x30")       

# length of entire envelope.
s_static("\x84")
s_sizer("envelope", endian=">")

if s_block_start("envelope"):
    s_static("\x02\x01\x03")    # version
    
    s_static("\xa3\x84")
    s_sizer("sasl", endian=">")
    
    if s_block_start("sasl"):
        s_lego("ber_string", "GSS-SPNEGO")      # xxx - might want to swap this out with a group at some point.
        
    s_block_end("sasl")

s_block_end("envelope")