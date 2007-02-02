#!c:\\python\\python.exe

from sulley   import *
from requests import trend

########################################################################################################################
sess = sessions.session("audits/trend_server_protect_20901.session", sleep_time=.25, log_level=10)
sess.add_target(sessions.target("192.168.181.2", 20901))

sess.connect(s_get("20901"))
sess.fuzz()
