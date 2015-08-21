# ================================================================================
# Basic MP2 Descriptor
# This file is part of the FuzzLabs Fuzzing Framework
# Author: FuzzLabs
# ================================================================================

from sulley import *

s_initialize("MP2")

if s_block_start("MP2_FILE"):

    # ----------------------------------------------------------------------------
    # MP2 DATA, FRAME
    # ----------------------------------------------------------------------------

    if s_block_start("MP2_FRAME"):

        # Frame header: 0xFF 0xFD 0x80 0x04
        # http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm

        s_bitfield(0xFFFD8004, length=4, fuzzable=True, fields=[
            {"start": 0,	"end": 11,	"name": "FRAME_SYNC"},
            {"start": 11,	"end": 13,	"name": "VERSION_ID",		"fuzzable": True},
            {"start": 13,	"end": 15,	"name": "LAYER_DESC",		"fuzzable": True},
            {"start": 15,	"end": 16,	"name": "PROTECTION"},
            {"start": 16,	"end": 20,	"name": "BITRATE_INDEX",	"fuzzable": True},
            {"start": 20,	"end": 22,	"name": "SAMPLING_RATE",	"fuzzable": True},
            {"start": 22,	"end": 23,	"name": "PADDING_BIT",		"fuzzable": True},
            {"start": 23,	"end": 24,	"name": "PRIVATE_BIT"},
            {"start": 24,	"end": 26,	"name": "CHANNEL_MODE",		"fuzzable": True},
            {"start": 26,	"end": 28,	"name": "MODE_EXTENSION",	"fuzzable": True},
            {"start": 28,	"end": 29,	"name": "COPYRIGHT"},
            {"start": 29,	"end": 30,	"name": "ORIGINAL"},
            {"start": 30,	"end": 32,	"name": "EMPHASIS"}
        ], name="MP2_FRAME_HEADER")

        if s_block_start("MPEG_DATA"):
            s_string("\x37" * 413)		# MPEG Audio Data
        s_block_end("MPEG_DATA")

    s_block_end("MP2_FRAME")
    s_repeat("MP2_FRAME", min_reps=10, max_reps=20, step=2)

s_block_end("MP2_FILE")

