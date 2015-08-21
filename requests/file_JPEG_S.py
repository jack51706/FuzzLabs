# =============================================================================
# JPEG Image Descriptor - SMALL
# This file is part of the FuzzLabs Fuzzing Framework
#
# Author: FuzzLabs
# Date: 21/07/2015
# 
# Original file MD5 sum:    4dde17f30fee6e6120a58d890a4ec572
# Original file SHA1 sum:   1e1d1c90b4b0dd9ad5719be96dcbfabf32ff9aee
#
# =============================================================================

from sulley import *

JPEG_SOI        = "\xFF\xD8"            # Start of Image Marker
JPEG_EOI        = "\xFF\xD9"            # End of Image Marker
JPEG_DQT        = "\xFF\xDB"            # Quantization Table
JPEG_DHT        = "\xFF\xC4"            # Huffman Table
JPEG_SOS        = "\xFF\xDA"            # Start of Scan
JPEG_COM        = "\xFF\xFE"            # Comment
JPEG_APP0       = "\xFF\xE0"            # Application Marker 0
JPEG_APP1       = "\xFF\xE1"            # Application Marker 1
JPEG_SOF0       = "\xFF\xC0"            # Start of Frame - Baseline DCT
JPEG_SOF2       = "\xFF\xC2"            # Start of Frame - Progressive DCT

s_initialize("JPEG")

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_SOI        ffd8            0               0x0             0x2
# -----------------------------------------------------------------------------

if s_block_start("JPEG_IMG_HDR"):
    s_static(JPEG_SOI)
s_block_end("JPEG_IMG_HDR")
s_repeat("JPEG_IMG_HDR", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_APP0       ffe0            16              0x2             0x14
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_HDR"):
    s_static(JPEG_APP0)
    s_size("JPEG_DATA_HDR", endian=">", inclusive=True, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_HDR"):
        s_string("JFIF")
        s_string("\x00")
        s_byte(0x1)                                        # Major Version
        s_byte(0x1)                                        # Minor Version
        s_byte(0x1)                                        # Density unit
        s_word(0x48, endian=">")                           # Xdensity
        s_word(0x48, endian=">")                           # Ydensity
        s_byte(0x0)                                        # Xthumbnail
        s_byte(0x0)                                        # Ythumbnail
    s_block_end("JPEG_DATA_HDR")
s_block_end("O_JPEG_DATA_HDR")
s_repeat("O_JPEG_DATA_HDR", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_COM        fffe            16              0x14            0x26
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_COM"):
    s_static(JPEG_COM)
    s_size("JPEG_DATA_COM", endian=">", inclusive=True, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_COM"):
        s_string("NCC_GROUP_TEST")
    s_block_end("JPEG_DATA_COM")
s_block_end("O_JPEG_DATA_COM")
s_repeat("O_JPEG_DATA_COM", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_DQT        ffdb            67              0x26            0x6b
# -----------------------------------------------------------------------------

s_static(JPEG_DQT)
s_size("JPEG_DATA_DQT_1", endian=">", inclusive=True, length=2, fuzzable=True)
if s_block_start("JPEG_DATA_DQT_1"):
    s_static("\x00\x03\x02\x02\x03\x02\x02\x03" +\
             "\x03\x03\x03\x04\x03\x03\x04\x05" +\
             "\x08\x05\x05\x04\x04\x05\x0A\x07" +\
             "\x07\x06\x08\x0C\x0A\x0C\x0C\x0B" +\
             "\x0A\x0B\x0B\x0D\x0E\x12\x10\x0D" +\
             "\x0E\x11\x0E\x0B\x0B\x10\x16\x10" +\
             "\x11\x13\x14\x15\x15\x15\x0C\x0F" +\
             "\x17\x18\x16\x14\x18\x12\x14\x15" +\
             "\x14")
s_block_end("JPEG_DATA_DQT_1")

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_DQT        ffdb            67              0x6b            0xb0
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_DQT_2"):
    s_static(JPEG_DQT)
    s_size("JPEG_DATA_DQT_2", endian=">", inclusive=True, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_DQT_2"):
        s_static("\x01\x03\x04\x04\x05\x04\x05\x09" +\
                 "\x05\x05\x09\x14\x0D\x0B\x0D\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14\x14\x14\x14\x14\x14\x14\x14" +\
                 "\x14")
    s_block_end("JPEG_DATA_DQT_2")
s_block_end("O_JPEG_DATA_DQT_2")
s_repeat("O_JPEG_DATA_DQT_2", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_SOF2       ffc2            17              0xb0            0xc3
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_SOF2_1"):
    s_static(JPEG_SOF2)
    s_size("JPEG_DATA_SOF2_1", endian=">", inclusive=True, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_SOF2_1"):
        s_static("\x08\x00\x01\x00\x01\x03\x01\x11" +\
                 "\x00\x02\x11\x01\x03\x11\x01")
    s_block_end("JPEG_DATA_SOF2_1")
s_block_end("O_JPEG_DATA_SOF2_1")
s_repeat("O_JPEG_DATA_SOF2_1", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_DHT        ffc4            20              0xc3            0xd9
# -----------------------------------------------------------------------------

s_static(JPEG_DHT)
s_size("JPEG_DATA_DHT_1", endian=">", inclusive=True, length=2, fuzzable=True)
if s_block_start("JPEG_DATA_DHT_1"):
    s_static("\x00\x01\x00\x00\x00\x00\x00\x00" +\
             "\x00\x00\x00\x00\x00\x00\x00\x00" +\
             "\x00\x08")
s_block_end("JPEG_DATA_DHT_1")

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_DHT        ffc4            20              0xd9            0xef
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_DHT_2"):
    s_static(JPEG_DHT)
    s_size("JPEG_DATA_DHT_2", endian=">", inclusive=True, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_DHT_2"):
        s_static("\x01\x01\x00\x00\x00\x00\x00\x00" +\
                 "\x00\x00\x00\x00\x00\x00\x00\x00" +\
                 "\x00\x00")
    s_block_end("JPEG_DATA_DHT_2")
s_block_end("O_JPEG_DATA_DHT_2")
s_repeat("O_JPEG_DATA_SOF2_1", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_SOS        ffda            12              0xef            0xff
# -----------------------------------------------------------------------------

if s_block_start("O_JPEG_DATA_SOS_1"):
    s_static(JPEG_SOS)
    s_size("JPEG_DATA_SOS_1", endian=">", inclusive=False, length=2,
           fuzzable=True)
    if s_block_start("JPEG_DATA_SOS_1"):
        s_static("\x03\x01\x00\x02\x10\x03\x10\x00" +\
                 "\x00\x01\x2A\x9F")
    s_block_end("JPEG_DATA_SOS_1")
s_block_end("O_JPEG_DATA_SOS_1")
s_repeat("O_JPEG_DATA_SOS_1", min_reps=0, max_reps=100, step=10)

# -----------------------------------------------------------------------------
# Section         Bin name        Size            Start offset    End offset
# JPEG_EOI        ffd9            0               0xff            0x101
# -----------------------------------------------------------------------------

s_string(JPEG_EOI)

