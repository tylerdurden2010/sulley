#!c:\python\python.exe

########################################################################################################################
class ascii (object):
    '''
    String data.
    '''

    ####################################################################################################################
    def __init__ (self, value, length):
        self.value      = value
        self.defaultval = value
        self.maxlen     = length


    ####################################################################################################################
    def flatten (self):
        # XXX - when we go through and add exception raising, we should uncomment this.
        #if type(self.value) != str:
        #    raise Exception

        return self.value

    
    ####################################################################################################################
    def fuzz (self):
        return "A" * self.maxlen


    ####################################################################################################################
    def reset (self):
        pass