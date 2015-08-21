# =============================================================================
# Basic TEST
# This file is part of the FuzzLabs Fuzzing Framework
# =============================================================================

from sulley import *

s_initialize("TEST_1")
s_static("FIRST-")
s_byte(0x00, full_range=True)
s_initialize("TEST_2")
s_static("SECOND-")
s_byte(0x00, full_range=True)


