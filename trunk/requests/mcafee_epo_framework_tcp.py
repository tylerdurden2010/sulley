from sulley import *

    
########################################################################################################################
s_initialize("mcafee_epo_framework_tcp")
"""
    McAfee FrameworkService.exe TCP port 8081
"""

s_static("POST", name="post_verb")
s_delim(" ")
s_group(values=["/spipe/pkg", "/spipe/file", "default.htm"])
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
