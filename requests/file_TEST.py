# =============================================================================
# Basic TEST
# This file is part of the FuzzLabs Fuzzing Framework
# =============================================================================

from sulley import *

s_initialize("TEST_1")
s_binary("FIRST-")
s_byte(0x00, full_range=True)
s_initialize("TEST_2")
s_binary("SECOND-")
s_byte(0x00, full_range=True)


