# =============================================================================
# Basic TEST
# This file is part of the FuzzLabs Fuzzing Framework
# =============================================================================

from sulley import *

s_initialize("TEST")

s_byte(0x00, full_range=True)
s_byte(0x00, full_range=True)
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")
s_string("TEST")

