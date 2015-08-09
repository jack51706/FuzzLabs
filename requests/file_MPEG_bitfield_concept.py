# ================================================================================
# Basic MPEG-1 Descriptor
# This file is part of the FuzzLabs Fuzzing Framework
# Author: Zsolt Imre
#
# This was extremely useful: http://dvd.sourceforge.net/dvdinfo/mpeghdrs.html
# ================================================================================

from sulley import *

s_initialize("MPEG")

# --------------------------------------------------------------------------------
# offset: 0x00
# Concept s_bitfield() implementation for Pack Header:
# http://dvd.sourceforge.net/dvdinfo/packhdr.html
# --------------------------------------------------------------------------------

if s_block_start("SEQ_HDR_1"):
    s_bitfield(length=3, name="PACK_HDR_START_CODE", fields=[
                   {"start": 0, "end": 23, "value": 0b01, field="START_CODE"}
               ])
    s_byte(0xBA)				# Sream ID - Pack header
    s_bitfield(length=6, name="PACK_HDR_SCR", fields=[
                   {"start": 0, "end": 0, "value": 0b1},
                   {"start": 1, "end": 9, "value": 0b100101101, field="SCR_EXT"},
                   {"start": 10, "end": 10, "value": 0b1},
                   {"start": 11, "end": 25, "value": 0b101010101011010, field="SCR_EXT_1"},
                   {"start": 26, "end": 26, "value": 0b1},
                   {"start": 27, "end": 41, "value": 0b001010111010101, field="SCR_EXT_2"},
                   {"start": 42, "end": 42, "value": 0b1},
                   {"start": 43, "end": 45, "value": 0b011, field="SCR_EXT_2"},
                   {"start": 46, "end": 47, "value": 0b01}
               ])
    # ... TODO ...
s_block_end("SEQ_HDR_1")

# ... TODO ...

