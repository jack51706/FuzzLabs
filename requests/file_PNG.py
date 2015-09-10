# =============================================================================
# Basic PNG Image Descriptor 
# This file is part of the FuzzLabs Fuzzing Framework
#
# Authors:
#  - Artur Gemes (NCC Group)
#  - FuzzLabs
#
# Date: 23/07/2015
# 
# =============================================================================

from sulley import *

PNG_SIGNATURE = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"

# Covered

PNG_IHDR = "IHDR"   # Must be first block after file signature. Specifies 
                    # width, height, bit depth and color type
PNG_PLTE = "PLTE"   # Palette for the image (1-256 entries). Each entry
                    # consists of RGB triplets, with each color as 1 byte.
PNG_PHYS = "pHYs"   # Physical pixel dimensions. Specifies the intended pixel
                    # size and aspect ratio
PNG_BKGD = "bKGD"   # Background color. Viewers may ignore this if they wish
                    # so probably not very useful
PNG_TRNS = "tRNS"   # Specifies that the image uses simple transparency
PNG_TIME = "tIME"   # Time of last image modification
PNG_ITXT = "iTXt"   # Text chunk using UTF-8 encoding
PNG_GAMA = "gAMA"   # The gamma stored as a 4 byte unsigned integer
PNG_IDAT = "IDAT"   # The actual image data. The image data is compressed.
                    # There can be multiple IDAT chunks, but they must be
                    # consecutive
PNG_IEND = "IEND"   # End of image marker. Must be the last chunk
PNG_TEXT = "tEXt"   # Text chunk using Latin-1 encoding. [Keyword][null][text]
                    # is the content layout
PNG_ZTXT = "zTXt"   # Compressed text chunk

# Not covered

PNG_CHRM = "cHRM"   # Specify RGB chromacities for device independed 
                    # implementation of color
PNG_HIST = "hIST"   # Histogram containing frequency of each color from 
                    # PLTE. PLTE must be present if hIST is present
PNG_ICCP = "iCCP"   # Contains the name of the profile (for convenience)
                    # a null terminator, compression method (only 0 is 
                    # defined) and the ICC profile in a compressed format 
                    # for the remainder
PNG_SBIT = "sBIT"   # sBIT specifies the number of significant bits in the 
                    # original sample so the original image can be recovered 
                    # despite predetermined bit depths by the standard
PNG_SPLT = "sPLT"   # Suggested palette. Sample depth must be 8 or 16. If it 
                    # is 8 then the length needs to be divisible by 6, and if 
                    # it is 16 it needs to be divisible by 10
PNG_SRGB = "sRGB"   # Contains the rendering intent as a single byte

s_initialize("PNG")

# -----------------------------------------------------------------------------
# File offset: 0x0
# -----------------------------------------------------------------------------

s_binary(PNG_SIGNATURE)

# -----------------------------------------------------------------------------
# IHDR Block
# File offset: 0x8
# -----------------------------------------------------------------------------

if s_block_start("IHDR_BLOCK"):
    s_size("IHDR_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("IHDR_BLOCK_I"):
        s_binary(PNG_IHDR)					# IHDR chunk identifier
        if s_block_start("IHDR_BLOCK_DATA"):
            s_dword(0x03, endian=">")				# Image width
            s_dword(0x03, endian=">")				# Image height
            s_byte(0x04)					# Bit depth (can be 1, 2, 4, 8, 16)
            s_byte(0x03)					# Color type (can be 0, 2, 3, 4, 6)
            s_byte(0x00)					# Compression method 
            s_byte(0x00)					# Filter method
            s_byte(0x00)					# Interlace type (can be 0 or 1)
        s_block_end("IHDR_BLOCK_DATA")
    s_block_end("IHDR_BLOCK_I")
    s_checksum("IHDR_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("IHDR_BLOCK")
s_repeat("IHDR_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# gAMA Block
# File offset: 0x21
# -----------------------------------------------------------------------------

if s_block_start("GAMA_BLOCK"):
    s_size("GAMA_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("GAMA_BLOCK_I"):
        s_binary(PNG_GAMA)					# gAMA chunk identifier
        if s_block_start("GAMA_BLOCK_DATA"):
            s_dword(0xB18F, endian=">")				# gamma value
        s_block_end("GAMA_BLOCK_DATA")
    s_block_end("GAMA_BLOCK_I")
    s_checksum("GAMA_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("GAMA_BLOCK")
s_repeat("GAMA_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# PLTE Block
# File offset: 0x31
# -----------------------------------------------------------------------------

if s_block_start("PLTE_BLOCK"):
    s_size("PLTE_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("PLTE_BLOCK_I"):
        s_binary(PNG_PLTE)                                      # PLTE chunk identifier
        if s_block_start("PLTE_BLOCK_DATA"):
            s_binary("0x63 0x6F 0x6C")
            s_binary("0x00 0x00 0x00")
            s_binary("0xC9 0x26 0x26")
            s_binary("0x26 0x91 0xC9")
            s_binary("0x26 0xC9 0x58")
            s_binary("0xF1 0xD6 0x1D")
        s_block_end("PLTE_BLOCK_DATA")
        s_repeat("PLTE_BLOCK_DATA", min_reps=0, max_reps=100, step=10)
    s_block_end("PLTE_BLOCK_I")
    s_checksum("PLTE_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("PLTE_BLOCK")
s_repeat("PLTE_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# tRNS Block
# File offset: 0x51
# -----------------------------------------------------------------------------

if s_block_start("TRNS_BLOCK"):
    s_size("TRNS_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("TRNS_BLOCK_I"):
        s_binary(PNG_TRNS)                                      # tRNS chunk identifier
        if s_block_start("TRNS_BLOCK_DATA"):
            s_byte(0x00)
        s_block_end("TRNS_BLOCK_DATA")
        s_repeat("TRNS_BLOCK_DATA", min_reps=0, max_reps=100, step=10)
    s_block_end("TRNS_BLOCK_I")
    s_checksum("TRNS_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("TRNS_BLOCK")
s_repeat("TRNS_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# bKGD Block
# File offset: 0x5C
# -----------------------------------------------------------------------------

if s_block_start("BKGD_BLOCK"):
    s_size("BKGD_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("BKGD_BLOCK_I"):
        s_binary(PNG_BKGD)                                      # bKGD chunk identifier
        if s_block_start("BKGD_BLOCK_DATA"):
            s_byte(0x00)
        s_block_end("BKGD_BLOCK_DATA")
        s_repeat("BKGD_BLOCK_DATA", min_reps=0, max_reps=100, step=10)
    s_block_end("BKGD_BLOCK_I")
    s_checksum("BKGD_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("BKGD_BLOCK")
s_repeat("BKGD_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# pHYs Block
# File offset: 0x69
# -----------------------------------------------------------------------------

if s_block_start("PHYS_BLOCK"):
    s_size("PHYS_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("PHYS_BLOCK_I"):
        s_binary(PNG_PHYS)                                      # pHYs chunk identifier
        if s_block_start("PHYS_BLOCK_DATA"):
            s_dword(0x0B13, endian=">")				# Pixels/unit - X 
            s_dword(0x0B13, endian=">")				# Pixels/unit - Y
            s_byte(0x01, endian=">")				# Unit specifier
        s_block_end("PHYS_BLOCK_DATA")
    s_block_end("PHYS_BLOCK_I")
    s_checksum("PHYS_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("PHYS_BLOCK")
s_repeat("PHYS_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# tIME Block
# File offset: 0x7E
# -----------------------------------------------------------------------------

if s_block_start("TIME_BLOCK"):
    s_size("TIME_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("TIME_BLOCK_I"):
        s_binary(PNG_TIME)                                      # tIME chunk identifier
        if s_block_start("TIME_BLOCK_DATA"):

            s_word(0x07DF, endian=">")				# Year
            s_byte(0x07, endian=">")				# Month
            s_byte(0x18, endian=">")				# Day
            s_byte(0x0F, endian=">")				# Hour
            s_byte(0x30, endian=">")				# Minute
            s_byte(0x20, endian=">")				# Second

        s_block_end("TIME_BLOCK_DATA")
    s_block_end("TIME_BLOCK_I")
    s_checksum("TIME_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("TIME_BLOCK")
s_repeat("TIME_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# From: http://www.w3.org/TR/PNG/#11IHDR
#  "PNG provides the tEXt, iTXt, and zTXt chunks for storing text strings
#  associated with the image, such as an image description or copyright notice.
#  Keywords are used to indicate what each text string represents. Any number
#  of such text chunks may appear, and more than one with the same keyword is
#  permitted."
#
# Rationale: Applications might process and/or display text chunks and as of
#            this, code working with these chunks might be vulnerable to 
#            buffer overflows or format string vulnerabilities. Because of
#            this, it is important to fuzz these fields.
#
#            tEXt, iTXt and zTXt serves the same purpose but allows the value
#            for a given keyword to be represented in different ways. Because
#            of this, it is important to test the different representations as
#            well for better code coverage.
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# iTXt / tEXt / zTXt Blocks
# NOTE: Probably these can be improved.
# File offset: 0x91
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_1"):
    s_size("TEXT_BLOCK_1_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_1_I"):
        s_group("TEXT_TYPE_1", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_1_DATA"):
            if s_block_start("TEXT_BLOCK_1_DATA_I", dep="TEXT_TYPE_1", dep_value=PNG_ITXT):
                # !!! iTXt
                s_string("Comment")                                 # Keyword
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)                                        # Compression method
                s_byte(0x00)                                        # Language tag
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("FuzzLabs PNG")                        # Text
                s_block_end("TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("Fuzzlabs PNG", compression="zlib")       # Text
                s_block_end("TEXT_BLOCK_1_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_1_DATA_I")

            if s_block_start("TEXT_BLOCK_1_DATA_T", dep="TEXT_TYPE_1", dep_value=PNG_TEXT):
                # !!! tEXt
                s_string("Comment")                                 # Keyword
                s_byte(0x00)
                s_binary("FuzzLabs PNG")                            # Text
            s_block_end("TEXT_BLOCK_1_DATA_T")

            if s_block_start("TEXT_BLOCK_1_DATA_Z", dep="TEXT_TYPE_1", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_string("Comment")                                 # Keyword
                s_byte(0x00)
                s_byte(0x00)                                        # Compression method
                s_string("Fuzzlabs PNG", compression="zlib")        # Text
            s_block_end("TEXT_BLOCK_1_DATA_Z")
        s_block_end("TEXT_BLOCK_1_DATA")
        s_checksum("TEXT_BLOCK_1_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_1_I")
s_block_end("TEXT_BLOCK_1")

# -----------------------------------------------------------------------------
# TEXT Block - 2
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_2"):
    s_size("TEXT_BLOCK_2_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_2_I"):
        s_group("TEXT_TYPE_2", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_2_DATA"):
            if s_block_start("TEXT_BLOCK_2_DATA_I", dep="TEXT_TYPE_2", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Title")                                   # Keyword
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)                                        # Compression method
                s_byte(0x00)                                        # Language tag
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("FuzzLabs PNG Image")                  # Text
                s_block_end("TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("FuzzLabs PNG Image", compression="zlib") # Text
                s_block_end("TEXT_BLOCK_2_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_2_DATA_I")

            if s_block_start("TEXT_BLOCK_2_DATA_T", dep="TEXT_TYPE_2", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Title")                                   # Keyword
                s_byte(0x00)
                s_binary("FuzzLabs PNG Image")                      # Text
            s_block_end("TEXT_BLOCK_2_DATA_T")

            if s_block_start("TEXT_BLOCK_2_DATA_Z", dep="TEXT_TYPE_2", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Title")                                   # Keyword
                s_byte(0x00)
                s_byte(0x00)                                        # Compression method
                s_string("Fuzzlabs PNG Image", compression="zlib")  # Text
            s_block_end("TEXT_BLOCK_2_DATA_Z")
        s_block_end("TEXT_BLOCK_2_DATA")
        s_checksum("TEXT_BLOCK_2_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_2_I")
s_block_end("TEXT_BLOCK_2")

# -----------------------------------------------------------------------------
# TEXT Block - 3
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_3"):
    s_size("TEXT_BLOCK_3_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_3_I"):
        s_group("TEXT_TYPE_3", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_3_DATA"):
            if s_block_start("TEXT_BLOCK_3_DATA_I", dep="TEXT_TYPE_3", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Author")                                  # Keyword
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("NCC Group")
                s_block_end("TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("NCC Group", compression="zlib")
                s_block_end("TEXT_BLOCK_3_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_3_DATA_I")

            if s_block_start("TEXT_BLOCK_3_DATA_T", dep="TEXT_TYPE_3", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Author")
                s_byte(0x00)
                s_binary("NCC Group")
            s_block_end("TEXT_BLOCK_3_DATA_T")

            if s_block_start("TEXT_BLOCK_3_DATA_Z", dep="TEXT_TYPE_3", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Author")
                s_byte(0x00)
                s_byte(0x00)
                s_string("NCC Group", compression="zlib")
            s_block_end("TEXT_BLOCK_3_DATA_Z")
        s_block_end("TEXT_BLOCK_3_DATA")
        s_checksum("TEXT_BLOCK_3_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_3_I")
s_block_end("TEXT_BLOCK_3")

# -----------------------------------------------------------------------------
# TEXT Block - 4
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_4"):
    s_size("TEXT_BLOCK_4_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_4_I"):
        s_group("TEXT_TYPE_4", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_4_DATA"):
            if s_block_start("TEXT_BLOCK_4_DATA_I", dep="TEXT_TYPE_4", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Description")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("NCC Group Description")
                s_block_end("TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("NCC Group Description", compression="zlib")
                s_block_end("TEXT_BLOCK_4_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_4_DATA_I")

            if s_block_start("TEXT_BLOCK_4_DATA_T", dep="TEXT_TYPE_4", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Description")
                s_byte(0x00)
                s_binary("NCC Group Description")
            s_block_end("TEXT_BLOCK_4_DATA_T")

            if s_block_start("TEXT_BLOCK_4_DATA_Z", dep="TEXT_TYPE_4", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Description")
                s_byte(0x00)
                s_byte(0x00)
                s_string("NCC Group Description", compression="zlib")
            s_block_end("TEXT_BLOCK_4_DATA_Z")
        s_block_end("TEXT_BLOCK_4_DATA")
        s_checksum("TEXT_BLOCK_4_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_4_I")
s_block_end("TEXT_BLOCK_4")

# -----------------------------------------------------------------------------
# TEXT Block - 5
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_5"):
    s_size("TEXT_BLOCK_5_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_5_I"):
        s_group("TEXT_TYPE_5", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_5_DATA"):
            if s_block_start("TEXT_BLOCK_5_DATA_I", dep="TEXT_TYPE_5", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Copyright")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("NCC Group Copyright")
                s_block_end("TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("NCC Group Copyright", compression="zlib")
                s_block_end("TEXT_BLOCK_5_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_5_DATA_I")

            if s_block_start("TEXT_BLOCK_5_DATA_T", dep="TEXT_TYPE_5", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Copyright")
                s_byte(0x00)
                s_binary("NCC Group Copyright`")
            s_block_end("TEXT_BLOCK_5_DATA_T")

            if s_block_start("TEXT_BLOCK_5_DATA_Z", dep="TEXT_TYPE_5", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Copyright")
                s_byte(0x00)
                s_byte(0x00)
                s_string("NCC Group Copyright", compression="zlib")
            s_block_end("TEXT_BLOCK_5_DATA_Z")
        s_block_end("TEXT_BLOCK_5_DATA")
        s_checksum("TEXT_BLOCK_5_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_5_I")
s_block_end("TEXT_BLOCK_5")

# -----------------------------------------------------------------------------
# TEXT Block - 6
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_6"):
    s_size("TEXT_BLOCK_6_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_6_I"):
        s_group("TEXT_TYPE_6", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_6_DATA"):
            if s_block_start("TEXT_BLOCK_6_DATA_I", dep="TEXT_TYPE_6", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Creation Time")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("23 July 2015")
                s_block_end("TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("23 July 2015", compression="zlib")
                s_block_end("TEXT_BLOCK_6_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_6_DATA_I")

            if s_block_start("TEXT_BLOCK_6_DATA_T", dep="TEXT_TYPE_6", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Creation Time")
                s_byte(0x00)
                s_binary("23 July 2015")
            s_block_end("TEXT_BLOCK_6_DATA_T")

            if s_block_start("TEXT_BLOCK_6_DATA_Z", dep="TEXT_TYPE_6", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Creation Time")
                s_byte(0x00)
                s_byte(0x00)
                s_string("23 July 2015", compression="zlib")
            s_block_end("TEXT_BLOCK_6_DATA_Z")
        s_block_end("TEXT_BLOCK_6_DATA")
        s_checksum("TEXT_BLOCK_6_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_6_I")
s_block_end("TEXT_BLOCK_6")

# -----------------------------------------------------------------------------
# TEXT Block - 7
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_7"):
    s_size("TEXT_BLOCK_7_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_7_I"):
        s_group("TEXT_TYPE_7", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_7_DATA"):
            if s_block_start("TEXT_BLOCK_7_DATA_I", dep="TEXT_TYPE_7", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Software")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("GIMP")
                s_block_end("TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("GIMP", compression="zlib")
                s_block_end("TEXT_BLOCK_7_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_7_DATA_I")

            if s_block_start("TEXT_BLOCK_7_DATA_T", dep="TEXT_TYPE_7", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Software")
                s_byte(0x00)
                s_binary("GIMP")
            s_block_end("TEXT_BLOCK_7_DATA_T")

            if s_block_start("TEXT_BLOCK_7_DATA_Z", dep="TEXT_TYPE_7", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Software")
                s_byte(0x00)
                s_byte(0x00)
                s_string("GIMP", compression="zlib")
            s_block_end("TEXT_BLOCK_7_DATA_Z")
        s_block_end("TEXT_BLOCK_7_DATA")
        s_checksum("TEXT_BLOCK_7_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_7_I")
s_block_end("TEXT_BLOCK_7")

# -----------------------------------------------------------------------------
# TEXT Block - 8
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_8"):
    s_size("TEXT_BLOCK_8_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_8_I"):
        s_group("TEXT_TYPE_8", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_8_DATA"):
            if s_block_start("TEXT_BLOCK_8_DATA_I", dep="TEXT_TYPE_8", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Disclaimer")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("None")
                s_block_end("TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("None", compression="zlib")
                s_block_end("TEXT_BLOCK_8_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_8_DATA_I")

            if s_block_start("TEXT_BLOCK_8_DATA_T", dep="TEXT_TYPE_8", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Disclaimer")
                s_byte(0x00)
                s_binary("None")
            s_block_end("TEXT_BLOCK_8_DATA_T")

            if s_block_start("TEXT_BLOCK_8_DATA_Z", dep="TEXT_TYPE_8", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Disclaimer")
                s_byte(0x00)
                s_byte(0x00)
                s_string("None", compression="zlib")
            s_block_end("TEXT_BLOCK_8_DATA_Z")
        s_block_end("TEXT_BLOCK_8_DATA")
        s_checksum("TEXT_BLOCK_8_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_8_I")
s_block_end("TEXT_BLOCK_8")

# -----------------------------------------------------------------------------
# TEXT Block - 9
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_9"):
    s_size("TEXT_BLOCK_9_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_9_I"):
        s_group("TEXT_TYPE_9", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_9_DATA"):
            if s_block_start("TEXT_BLOCK_9_DATA_I", dep="TEXT_TYPE_9", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Warning")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("None")
                s_block_end("TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("None", compression="zlib")
                s_block_end("TEXT_BLOCK_9_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_9_DATA_I")

            if s_block_start("TEXT_BLOCK_9_DATA_T", dep="TEXT_TYPE_9", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Warning")
                s_byte(0x00)
                s_binary("None")
            s_block_end("TEXT_BLOCK_9_DATA_T")

            if s_block_start("TEXT_BLOCK_9_DATA_Z", dep="TEXT_TYPE_9", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Warning")
                s_byte(0x00)
                s_byte(0x00)
                s_string("None", compression="zlib")
            s_block_end("TEXT_BLOCK_9_DATA_Z")
        s_block_end("TEXT_BLOCK_9_DATA")
        s_checksum("TEXT_BLOCK_9_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_9_I")
s_block_end("TEXT_BLOCK_9")

# -----------------------------------------------------------------------------
# TEXT Block - 10
# -----------------------------------------------------------------------------

if s_block_start("TEXT_BLOCK_10"):
    s_size("TEXT_BLOCK_10_DATA", length=4, endian=">", inclusive=False, fuzzable=False)
    if s_block_start("TEXT_BLOCK_10_I"):
        s_group("TEXT_TYPE_10", values=[PNG_ITXT, PNG_TEXT, PNG_ZTXT])

        if s_block_start("TEXT_BLOCK_10_DATA"):
            if s_block_start("TEXT_BLOCK_10_DATA_I", dep="TEXT_TYPE_10", dep_value=PNG_ITXT):
                # !!! iTXt
                s_binary("Source")
                s_byte(0x00)

                # Compression flag has to be full_range to make sure 0x00 and
                # 0x01 are covered.

                s_byte(0x00, full_range=True, name="TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_VAL")
                s_byte(0x00)
                s_byte(0x00)
                s_byte(0x00)
                if s_block_start("TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_N", dep="TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x00):
                    s_string("Raspberry PI")
                s_block_end("TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_N")
                if s_block_start("TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_Y", dep="TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_VAL", dep_value=0x01):
                    s_string("Raspberry PI", compression="zlib")
                s_block_end("TEXT_BLOCK_10_DATA_I_ITXT_BLOCK_DATA_COMP_Y")
            s_block_end("TEXT_BLOCK_10_DATA_I")

            if s_block_start("TEXT_BLOCK_10_DATA_T", dep="TEXT_TYPE_10", dep_value=PNG_TEXT):
                # !!! tEXt
                s_binary("Source")
                s_byte(0x00)
                s_binary("Raspberry PI")
            s_block_end("TEXT_BLOCK_10_DATA_T")

            if s_block_start("TEXT_BLOCK_10_DATA_Z", dep="TEXT_TYPE_10", dep_value=PNG_ZTXT):
                # !!! zTXt
                s_binary("Source")
                s_byte(0x00)
                s_byte(0x00)
                s_string("Raspberry PI", compression="zlib")
            s_block_end("TEXT_BLOCK_10_DATA_Z")
        s_block_end("TEXT_BLOCK_10_DATA")
        s_checksum("TEXT_BLOCK_10_DATA", algorithm="crc32", length=4, endian=">")
    s_block_end("TEXT_BLOCK_10_I")
s_block_end("TEXT_BLOCK_10")

# -----------------------------------------------------------------------------
# IDAT Block
#
# From http://www.w3.org/TR/PNG/#11IDAT
#  "The IDAT chunk contains the actual image data which is the output stream
#  of the compression algorithm."
#
# Rationale: Normally it would not be much useful to fuzz the image data
#            itself, however, as the data can be compressed it might happen
#            that the compression library used by the application or image 
#            library is vulnerable. Because of this, the IDAT data below is
#            being fuzzed.
# -----------------------------------------------------------------------------

if s_block_start("IDAT_BLOCK"):
    s_size("IDAT_BLOCK_DATA", length=4, endian=">", inclusive=False, fuzzable=True)
    if s_block_start("IDAT_BLOCK_I"):
        s_binary(PNG_IDAT)                                      # IDAT chunk identifier
        if s_block_start("IDAT_BLOCK_DATA"):

            s_string("\x08\xD7\x63\x50\x08\x60\x60\x64" +\
                     "\x60\x70\x30\x00\x00\x03\xEE\x00" +\
                     "\xE2")

        s_block_end("IDAT_BLOCK_DATA")
    s_block_end("IDAT_BLOCK_I")
    s_checksum("IDAT_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("IDAT_BLOCK")
s_repeat("IDAT_BLOCK", min_reps=0, max_reps=1000, step=100)

# -----------------------------------------------------------------------------
# IEND Block
# -----------------------------------------------------------------------------

if s_block_start("IEND_BLOCK"):
    s_dword(0x00, endian=">")
    if s_block_start("IEND_BLOCK_I"):
        s_string(PNG_IEND)                                      # IEND chunk identifier
    s_block_end("IEND_BLOCK_I")
    s_checksum("IEND_BLOCK_I", algorithm="crc32", length=4, endian=">")
s_block_end("IEND_BLOCK")
s_repeat("IEND_BLOCK", min_reps=0, max_reps=100, step=10)

