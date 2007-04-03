__all__ = \
[
    "numbers",
    "static",
]

from numbers import *
from static  import *
from ascii import *


def is_fuzzable (data):
    '''
    Determines if the given data is part of the numbers or static modules
    '''

    return isinstance(data, (numbers.bit_field, 
                             numbers.byte,   numbers.word,
                             numbers.dword,  numbers.qword))