# =============================================================================
# ID3 Tag Fuzzer
# Only version 2.3.0 was covered. (Plus extended header of 2.4.0)
# TODO: implement version 2.4.0 specific changes as well, based on:
#       http://id3.org/id3v2.4.0-structure
#
# Author: Artur Gemes (NCC Group)
# =============================================================================

from sulley import *
import struct
import zlib

# -----------------------------------------------------------------------------
# This works out the size of the uncompressed data and appends it to the end
# of the frame header to get the following layout:
# 
# Frame ID       $xx xx xx xx       (four characters)
# Size           $xx xx xx xx       (this is the compressed size and is filled
#                                   in by Sulley sizers.
# Flags          $xx xx
# Uncompressed size $xx xx xx xx    (this is appended in this encoder)
# <COMPRESSED FRAME DATA>           (also done by this encoder)
# -----------------------------------------------------------------------------

def compress(data):
    uncompressed_length = len(data)
    rendered_length = struct.pack(">L", uncompressed_length)
    compressed_data = zlib.compress(data)
    return rendered_length + compressed_data


# -----------------------------------------------------------------------------
# These are all the values the two byte frame flag should take. The format is 
# the following:
#
#     0bABC00000 0bIJK00000
#
# A = Tag alter preservation. Should the frame be preserved if the ID3 tag is
#     altered and the frame is unknown? Decoder shouldn't care
# B = File alter preservation. Should the frame be preserved if the file is
#     altered and the frame is unknown? Decoder shoudln't care
# C = Read only. This frame is read only. Decoder shouldn't be altering frames
#     anyway
#
# I = Compression. Is this frame ZLIB compressed? 
# J = Encryption. Is this frame encrypted? 
# K = Grouping identity. If set the frame is extended by the gorup ID byte. 
#     Doesn't sound particularly useful
#
# Either no flags set or the ZLIB compression flag is set.
# -----------------------------------------------------------------------------

frame_flag_values = ["\x00\x00", "\x00\x80"]

# -----------------------------------------------------------------------------
# These are the text encoding flags used on a frame by frame basis.
#   0x00 - For Latin 1 (Basically standard ASCII plus extras)
#   0x01 - Unicode using UCS-2 (2 byte Universal Character Set)
# -----------------------------------------------------------------------------

text_encoding_flags = ["\x00", "\x01"]

# The cover image used in the APIC frame. It is a 1 pixel JPEG image

cover_image = [
	0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 
	0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 
	0x00, 0x60, 0x00, 0x00, 0xFF, 0xE1, 0x00, 0x5A, 
	0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x4D, 0x4D, 
	0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 
	0x01, 0x32, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 
	0x00, 0x00, 0x00, 0x3E, 0x51, 0x10, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 
	0x51, 0x11, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x0E, 0xC4, 0x51, 0x12, 0x00, 0x04, 
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0E, 0xC4, 
	0x00, 0x00, 0x00, 0x00, 0x32, 0x30, 0x31, 0x35, 
	0x3A, 0x30, 0x32, 0x3A, 0x31, 0x33, 0x20, 0x31, 
	0x31, 0x3A, 0x31, 0x32, 0x3A, 0x31, 0x38, 0x00, 
	0xFF, 0xDB, 0x00, 0x43, 0x00, 0x02, 0x01, 0x01,
	0x02, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x02, 0x02, 0x02, 0x03, 0x05, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x06, 0x04, 0x04, 0x03, 0x05, 0x07,
	0x06, 0x07, 0x07, 0x07, 0x06, 0x07, 0x07, 0x08,
	0x09, 0x0B, 0x09, 0x08, 0x08, 0x0A, 0x08, 0x07,
	0x07, 0x0A, 0x0D, 0x0A, 0x0A, 0x0B, 0x0C, 0x0C,
	0x0C, 0x0C, 0x07, 0x09, 0x0E, 0x0F, 0x0D, 0x0C,
	0x0E, 0x0B, 0x0C, 0x0C, 0x0C, 0xFF, 0xDB, 0x00,
	0x43, 0x01, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03,
	0x06, 0x03, 0x03, 0x06, 0x0C, 0x08, 0x07, 0x08,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
	0x0C, 0x0C, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00,
	0x01, 0x00, 0x01, 0x03, 0x01, 0x22, 0x00, 0x02,
	0x11, 0x01, 0x03, 0x11, 0x01, 0xFF, 0xC4, 0x00,
	0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4,
	0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03, 0x03,
	0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00,
	0x00, 0x01, 0x7D, 0x01, 0x02, 0x03, 0x00, 0x04,
	0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13,
	0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81,
	0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15,
	0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82,
	0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46,
	0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56,
	0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66,
	0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76,
	0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86,
	0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4,
	0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3,
	0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2,
	0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
	0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
	0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xC4, 0x00,
	0x1F, 0x01, 0x00, 0x03, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4,
	0x00, 0xB5, 0x11, 0x00, 0x02, 0x01, 0x02, 0x04,
	0x04, 0x03, 0x04, 0x07, 0x05, 0x04, 0x04, 0x00,
	0x01, 0x02, 0x77, 0x00, 0x01, 0x02, 0x03, 0x11,
	0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51,
	0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08,
	0x14, 0x42, 0x91, 0xA1, 0xB1, 0xC1, 0x09, 0x23,
	0x33, 0x52, 0xF0, 0x15, 0x62, 0x72, 0xD1, 0x0A,
	0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18,
	0x19, 0x1A, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x82, 0x83, 0x84,
	0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93,
	0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2,
	0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
	0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
	0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
	0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
	0xD8, 0xD9, 0xDA, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
	0xE7, 0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00,
	0x0C, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11,
	0x00, 0x3F, 0x00, 0xF4, 0x4A, 0x28, 0xA2, 0xBE,
	0x3C, 0xFE, 0xB0, 0x3F, 0xFF, 0xD9
    ]

# =============================================================================
#
# =============================================================================

s_initialize("ID3")

# This contains the whole of the ID3 tag data.
s_block_start("ID3_TAG")

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------

if s_block_start("ID3_HEADER"):
    s_static("ID3")                 # ID3 headers start with this signature
    s_byte(0x03, full_range=True, name="major_ver")				# Major version
    s_byte(0x00, full_range=True, name="minor_ver")				# Minor version

    s_group("ID3v2_flags", values=["\x00", "\x40", "\x80", "\xc0"])		# Flags to set extended header (or not to set it)

    s_size("ID3_FRAMES", length=4, endian=">", fuzzable=True, synchsafe=True)   # The size of the ID3 tag data
s_block_end("ID3_HEADER")

# -----------------------------------------------------------------------------
# General frame format is the following:
#
# Where $xx indicates one byte:
# Frame ID       $xx xx xx xx (four characters)
# Size           $xx xx xx xx (Not including header)
# Flags          $xx xx

# -----------------------------------------------------------------------------

s_block_start("ID3_FRAMES")

if s_block_start("EXTENDED_HEADER", dep="ID3v2_flags", dep_values=["\x40", "\xc0"]):

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    if s_block_start("ID3_V2.3_EXT_HDR_1", dep="major_ver", dep_value=0x03):
        if s_block_start("ID3_V2.3_EXT_HDR_2", dep="minor_ver", dep_value=0x00):
            s_size("EXTENDED_HEADER_DAT", length=4, endian=">", fuzzable=True)

            if s_block_start("EXTENDED_HEADER_DAT"):
                s_group("ext_header_flags", values=["\x00\x00", "\x80\x00"])   # CRC32 present or not?
                s_size("PADDING", length=4, endian=">", fuzzable=True)
            s_block_end("EXTENDED_HEADER_DAT")

            if s_block_start("EXTENDED_HEADER_CRC32", dep="ext_header_flags", dep_value="\x80\x00"):
                s_checksum("CRC_WRAPPER", algorithm="crc32", length=4, endian=">")
            s_block_end("EXTNEDED_HEADER_CRC32")
        s_block_end("ID3_V2.3_EXT_HDR_2")
    s_block_end("ID3_V2.3_EXT_HDR_1")

    # -------------------------------------------------------------------------
    #
    # -------------------------------------------------------------------------

    if s_block_start("ID3_V2.4_EXT_HDR_1", dep="major_ver", dep_value=0x04):
        if s_block_start("ID3_V2.4_EXT_HDR_2", dep="minor_ver", dep_value=0x00):
            s_size("EXTENDED_HEADER_DATA", length=4, endian=">", fuzzable=True, synchsafe=True)
            if s_block_start("EXTENDED_HEADER_DATA"):
                if s_block_start("EXT_HDR_FLAGS_FIELD"):
                    s_size("EXT_HDR_FLAGS", length=1, endian=">", fuzzable=True)

                    if s_block_start("EXT_HDR_FLAGS"):
                        s_bitfield(0x00, length=1, fuzzable=True, fields=[
                            {"start": 0,    "end": 1,   "name": "EH_DATA_FLG_1_ST_1"},
                            {"start": 1,    "end": 4,   "name": "EH_DATA_FLAGS",        "fuzzable": True},
                            {"start": 4,    "end": 8,   "name": "EH_DATA_FLG_1_ST_2"}
                        ], name="EH_DATA_FLG_1")

                        """
                         The present tag is an update of a tag found earlier in the present
                         file or stream. If frames defined as unique are found in the
                         present tag, they are to override any corresponding ones found in
                         in the earlier tag. This flag has no corresponding data.
                        """

                        if s_block_start("EXT_HDR_TAG_UPDATE", dep="EH_DATA_FLG_1", dep_values=[
                                0b01000000,
                                0b01100000,
                                0b01010000,
                                0b01110000]):
                            s_byte(0x00)                        # Flag data length
                        s_block_end("EXT_HDR_TAG_UPDATE")

                        """
                         For some applications it might be desired to restrict a tag in more
                         ways than imposed by the ID3v2 specification. Note that the
                         presence of these restrictions does not affect how the tag is
                         decoded, merely how it was restricted before encoding.
                        """

                        if s_block_start("EXT_HDR_TAG_RESTRICT", dep="EH_DATA_FLG_1", dep_values=[
                                0b00010000,
                                0b01010000,
                                0b00110000,
                                0b01110000]):
                            s_byte(0x01)                        # Flag data length
                            s_bitfield(0x00, length=1, fuzzable=True, fields=[
                                {"start": 0,    "end": 2,   "name": "EXT_HDR_TAG_SIZE_REST"},
                                {"start": 2,    "end": 3,   "name": "EXT_HDR_TAG_ENC_REST",        "fuzzable": True},
                                {"start": 3,    "end": 5,   "name": "EXT_HDR_TAG_FSIZE_REST",      "fuzzable": True},
                                {"start": 5,    "end": 6,   "name": "EXT_HDR_TAG_IENC_REST",       "fuzzable": True},
                                {"start": 6,    "end": 8,   "name": "EXT_HDR_TAG_ISIZE_REST",      "fuzzable": True}
                            ], name="EXT_HDR_TAG_RESTRICT_BITS")
                        s_block_end("EXT_HDR_TAG_RESTRICT")

                        """
                         CRC data case will be skipped because:
                           a) We have no synchsafe support of s_checksum()
                           b) Unlikely that there will be any significant issue related to CRC
                        """

                    s_block_end("EXT_HDR_FLAGS")

                s_block_end("EXT_HDR_FLAGS_FIELD")
                s_repeat("EXT_HDR_FLAGS_FIELD", min_reps=0, max_reps=2000, step=100)
            s_block_end("EXTENDED_HEADER_DATA")
        s_block_end("ID3_V2.4_EXT_HDR_2")
    s_block_end("ID3_V2.4_EXT_HDR_1")
s_block_end("EXTENDED_HEADER")

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------

# Yet another wrapper, this time for the CRC32 above. All frames except the 
# extended header should be inside

s_block_start("CRC_WRAPPER")

# -----------------------------------------------------------------------------
# Frame containing the album name
# -----------------------------------------------------------------------------

if s_block_start("TALB"):
    s_static("TALB")    # TALB frame ID
    s_size("TALB_DAT", length=4, endian=">", fuzzable=True)
    s_group("talb_flags", values=frame_flag_values)

    if s_block_start("TALB_DAT"):
        if s_block_start("TALB_UNCOMPRESSED", dep="talb_flags", dep_value="\x00\x00"):
            s_group("talb_text_encoding", values=text_encoding_flags)

            if s_block_start("ALBUM_LATIN", dep="talb_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Album", encoding="latin_1")
            s_block_end("ALBUM_LATIN")

            if s_block_start("ALBUM_UNICODE", dep="talb_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Album", encoding="utf16")
            s_block_end("ALBUM_UNICODE")
        s_block_end("TALB_UNCOMPRESSED")

        if s_block_start("TALB_COMPRESSED", dep="talb_flags", dep_value="\x00\x80", encoder=compress):
            s_group("talb_text_encoding_c", values=text_encoding_flags)

            if s_block_start("ALBUM_LATIN_C", dep="talb_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Album", encoding="latin_1")
            s_block_end("ALBUM_LATIN_C")

            if s_block_start("ALBUM_UNICODE_C", dep="talb_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Album", encoding="utf16")
            s_block_end("ALBUM_UNICODE_C")
        s_block_end("TALB_COMPRESSED")
    s_block_end("TALB_DAT")
s_block_end("TALB")

# -----------------------------------------------------------------------------
# Frame containing the lead performer/soloist
# -----------------------------------------------------------------------------

if s_block_start("TPE1"):
    s_static("TPE1")    # TPE1 frame ID
    s_size("TPE1_DAT", length=4, endian=">", fuzzable=True)
    s_group("tpe1_flags", values=frame_flag_values)

    if s_block_start("TPE1_DAT"):
        if s_block_start("TPE1_UNCOMPRESSED", dep="tpe1_flags", dep_value="\x00\x00"):
            s_group("tpe1_text_encoding", values=text_encoding_flags)

            if s_block_start("LEAD_LATIN", dep="tpe1_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Artist", encoding="latin_1")
            s_block_end("LEAD_LATIN")

            if s_block_start("LEAD_UNICODE", dep="tpe1_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Artist", encoding="utf16")
            s_block_end("LEAD_UNICODE")
        s_block_end("TPE1_UNCOMPRESSED")

        if s_block_start("TPE1_COMPRESSED", dep="tpe1_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tpe1_text_encoding_c", values=text_encoding_flags)

            if s_block_start("LEAD_LATIN_C", dep="tpe1_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Artist", encoding="latin_1")
            s_block_end("LEAD_LATIN_C")

            if s_block_start("LEAD_UNICODE_C", dep="tpe1_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Artist", encoding="utf16")
            s_block_end("LEAD_UNICODE_C")
        s_block_end("TPE1_COMPRESSED")
    s_block_end("TPE1_DAT")
s_block_end("TPE1")

# -----------------------------------------------------------------------------
# Frame containing the Band/Orchestra/Accompaniment
# -----------------------------------------------------------------------------

if s_block_start("TPE2"):
    s_static("TPE2")    # TPE2 frame ID
    s_size("TPE2_DAT", length=4, endian=">", fuzzable=True)
    s_group("tpe2_flags", values=frame_flag_values)

    if s_block_start("TPE2_DAT"):
        if s_block_start("TPE2_UNCOMPRESSED", dep="tpe2_flags", dep_value="\x00\x00"):
            s_group("tpe2_text_encoding", values=text_encoding_flags)

            if s_block_start("BAND_LATIN", dep="tpe2_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Artist", encoding="latin_1")
            s_block_end("BAND_LATIN")

            if s_block_start("BAND_UNICODE", dep="tpe2_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Artist", encoding="utf16")
            s_block_end("BAND_UNICODE")
        s_block_end("TPE2_UNCOMPRESSED")

        if s_block_start("TPE2_COMPRESSED", dep="tpe2_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tpe2_text_encoding_c", values=text_encoding_flags)

            if s_block_start("BAND_LATIN_C", dep="tpe2_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Artist", encoding="latin_1")
            s_block_end("BAND_LATIN_C")

            if s_block_start("BAND_UNICODE_C", dep="tpe2_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Artist", encoding="utf16")
            s_block_end("BAND_UNICODE_C")
        s_block_end("TPE2_COMPRESSED")
    s_block_end("TPE2_DAT")
s_block_end("TPE2")

# -----------------------------------------------------------------------------
# The Sulley calls below have been commented because those parts of the frame 
# are not present in the reference file. They are technically in the ID3 
# specification.
# -----------------------------------------------------------------------------

if s_block_start("COMM"):
    s_static("COMM")    # COMM frame ID
    s_size("COMM_DAT", length=4, endian=">", fuzzable=True)
    s_group("comm_flags", values=frame_flag_values)

    if s_block_start("COMM_DAT"):
        if s_block_start("COMM_UNCOMPRESSED", dep="comm_flags", dep_value="\x00\x00"):
            s_group("comm_text_encoding", values=text_encoding_flags)   # What character encoding to use
            s_static("eng")                                             # Language (English)

            if s_block_start("COMMENT_LATIN", dep="comm_text_encoding", dep_value="\x00"):
                s_string("Quite a fuzzy comment", encoding="latin_1")            # Content description
                s_delim("\x00")                                                                 # Null terminator
                s_string("A very very very fuzzy song", encoding="latin_1")      # The comment itself
            s_block_end("COMMENT_LATIN")

            if s_block_start("COMMENT_UNICODE", dep="comm_text_encoding", dep_value="\x01"):
                s_string("Quite a fuzzy comment", encoding="utf16")          # Content description
                s_delim("\x00\x00")                                                         # Null terminator
                s_string("A very very very fuzzy song", encoding="utf16")    # The comment itself
            s_block_end("COMMENT_UNICODE")
        s_block_end("COMM_UNCOMPRESSED")

        if s_block_start("COMM_COMPRESSED", dep="comm_flags", dep_value="\x00\x80", encoder=compress):
            s_group("comm_text_encoding_c", values=text_encoding_flags)     # What character encoding to use
            s_static("eng")                                                 # Language (English)

            if s_block_start("COMMENT_LATIN_C", dep="comm_text_encoding_c", dep_value="\x00"):
                s_string("Quite a fuzzy comment", encoding="latin_1")            # Content description
                s_delim("\x00")                                                                 # Null terminator
                s_string("A very very very fuzzy song", encoding="latin_1")      # The comment itself
            s_block_end("COMMENT_LATIN_C")

            if s_block_start("COMMENT_UNICODE_C", dep="comm_text_encoding_c", dep_value="\x01"):
                s_string("Quite a fuzzy comment", encoding="utf16")          # Content description
                s_delim("\x00\x00")                                                         # Null terminator
                s_string("A very very very fuzzy song", encoding="utf16")    # The comment itself
            s_block_end("COMMENT_UNICODE_C")
        s_block_end("COMM_COMPRESSED")
    s_block_end("COMM_DAT")
s_block_end("COMM")

# -----------------------------------------------------------------------------
# Composer
# -----------------------------------------------------------------------------

if s_block_start("TCOM"):
    s_static("TCOM")    # TCOM frame ID
    s_size("TCOM_DAT", length=4, endian=">", fuzzable=True)
    s_group("tcom_flags", values=frame_flag_values)

    if s_block_start("TCOM_DAT"):
        if s_block_start("TCOM_UNCOMPRESSED", dep="tcom_flags", dep_value="\x00\x00"):
            s_group("tcom_text_encoding", values=text_encoding_flags)

            if s_block_start("COMPOSER_LATIN", dep="tcom_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Composer", encoding="latin_1")
            s_block_end("COMPOSER_LATIN")

            if s_block_start("COMPOSER_UNICODE", dep="tcom_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Composer", encoding="utf16")
            s_block_end("COMPOSER_UNICODE")
        s_block_end("TCOM_UNCOMPRESSED")

        if s_block_start("TCOM_COMPRESSED", dep="tcom_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tcom_text_encoding_c", values=text_encoding_flags)

            if s_block_start("COMPOSER_LATIN_C", dep="tcom_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Composer", encoding="latin_1")
            s_block_end("COMPOSER_LATIN_C")

            if s_block_start("COMPOSER_UNICODE_C", dep="tcom_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Composer", encoding="utf16")
            s_block_end("COMPOSER_UNICODE_C")
        s_block_end("TCOM_COMPRESSED")
    s_block_end("TCOM_DAT")
s_block_end("TCOM")

# -----------------------------------------------------------------------------
# Conductor
# -----------------------------------------------------------------------------

if s_block_start("TPE3"):
    s_static("TPE3")    # TPE3 frame ID
    s_size("TPE3_DAT", length=4, endian=">", fuzzable=True)
    s_group("tpe3_flags", values=frame_flag_values)

    if s_block_start("TPE3_DAT"):
        if s_block_start("TPE3_UNCOMPRESSED", dep="tpe3_flags", dep_value="\x00\x00"):
            s_group("tpe3_text_encoding", values=text_encoding_flags)

            if s_block_start("CONDUCTOR_LATIN", dep="tpe3_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Conductor", encoding="latin_1")
            s_block_end("CONDUCTOR_LATIN")

            if s_block_start("CONDUCTOR_UNICODE", dep="tpe3_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Conductor", encoding="utf16")
            s_block_end("CONDUCTOR_UNICODE")
        s_block_end("TPE3_UNCOMPRESSED")

        if s_block_start("TPE3_COMPRESSED", dep="tpe3_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tpe3_text_encoding_c", values=text_encoding_flags)

            if s_block_start("CONDUCTOR_LATIN_C", dep="tpe3_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Conductor", encoding="latin_1")
            s_block_end("CONDUCTOR_LATIN_C")

            if s_block_start("CONDUCTOR_UNICODE_C", dep="tpe3_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Conductor", encoding="utf16")
            s_block_end("CONDUCTOR_UNICODE_C")
        s_block_end("TPE3_COMPRESSED")
    s_block_end("TPE3_DAT")
s_block_end("TPE3")

# -----------------------------------------------------------------------------
# Position in set. Eg Disc 1/2 etc.
# -----------------------------------------------------------------------------

if s_block_start("TPOS"):
    s_static("TPOS")    # TPOS frame ID
    s_size("TPOS_DAT", length=4, endian=">", fuzzable=True)
    s_group("tpos_flags", values=frame_flag_values)

    if s_block_start("TPOS_DAT"):
        if s_block_start("TPOS_UNCOMPRESSED", dep="tpos_flags", dep_value="\x00\x00"):
            s_group("tpos_text_encoding", values=text_encoding_flags)

            if s_block_start("POSITION_LATIN", dep="tpos_text_encoding", dep_value="\x00"):
                s_string("1/1", encoding="latin_1")    # Position in set
            s_block_end("POSITION_LATIN")

            if s_block_start("POSITION_UNICODE", dep="tpos_text_encoding", dep_value="\x01"):
                s_string("1/1", encoding="utf16")  # Position in set
            s_block_end("POSITION_UNICODE")
        s_block_end("TPOS_UNCOMPRESSED")

        if s_block_start("TPOS_COMPRESSED", dep="tpos_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tpos_text_encoding_c", values=text_encoding_flags)

            if s_block_start("POSITION_LATIN_C", dep="tpos_text_encoding_c", dep_value="\x00"):
                s_string("1/1", encoding="latin_1")    # Year of recording
            s_block_end("POSITION_LATIN_C")

            if s_block_start("POSITION_UNICODE_C", dep="tpos_text_encoding_c", dep_value="\x01"):
                s_string("1/1", encoding="utf16")  # Year of recording
            s_block_end("POSITION_UNICODE_C")
        s_block_end("TPOS_COMPRESSED")
    s_block_end("TPOS_DAT")
s_block_end("TPOS")

# -----------------------------------------------------------------------------
# Content type
# -----------------------------------------------------------------------------

if s_block_start("TCON"):
    s_static("TCON")    # TCON frame ID
    s_size("TCON_DAT", length=4, endian=">", fuzzable=True)
    s_group("tcon_flags", values=frame_flag_values)

    # See http://id3.org/id3v2.3.0 Appendix A for content values, although these don't seem to be used that often
    if s_block_start("TCON_DAT"):
        if s_block_start("TCON_UNCOMPRESSED", dep="tcon_flags", dep_value="\x00\x00"):
            s_group("tcon_text_encoding", values=text_encoding_flags)

            if s_block_start("CONTENT_LATIN", dep="tcon_text_encoding", dep_value="\x00"):
                s_string("Fuzzy", encoding="latin_1")    # (31) for Trance
            s_block_end("CONTENT_LATIN")

            if s_block_start("CONTENT_UNICODE", dep="tcon_text_encoding", dep_value="\x01"):
                s_string("Fuzzy", encoding="utf16")  # Trance
            s_block_end("CONTENT_UNICODE")
        s_block_end("TCON_UNCOMPRESSED")

        if s_block_start("TCON_COMPRESSED", dep="tcon_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tcon_text_encoding_c", values=text_encoding_flags)

            if s_block_start("CONTENT_LATIN_C", dep="tcon_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy", encoding="latin_1")
            s_block_end("CONTENT_LATIN_C")

            if s_block_start("CONTENT_UNICODE_C", dep="tcon_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy", encoding="utf16")
            s_block_end("CONTENT_UNICODE_C")
        s_block_end("TCON_COMPRESSED")
    s_block_end("TCON_DAT")
s_block_end("TCON")

# -----------------------------------------------------------------------------
# Publisher
# -----------------------------------------------------------------------------

if s_block_start("TPUB"):
    s_static("TPUB")    # TALB frame ID
    s_size("TPUB_DAT", length=4, endian=">", fuzzable=True)
    s_group("tpub_flags", values=frame_flag_values)

    if s_block_start("TPUB_DAT"):
        if s_block_start("TPUB_UNCOMPRESSED", dep="tpub_flags", dep_value="\x00\x00"):
            s_group("tpub_text_encoding", values=text_encoding_flags)

            if s_block_start("PUBLISHER_LATIN", dep="tpub_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Publisher", encoding="latin_1")
            s_block_end("PUBLISHER_LATIN")

            if s_block_start("PUBLISHER_UNICODE", dep="tpub_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Publisher", encoding="utf16")
            s_block_end("PUBLISHER_UNICODE")
        s_block_end("TPUB_UNCOMPRESSED")

        if s_block_start("TPUB_COMPRESSED", dep="trck_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tpub_text_encoding_c", values=text_encoding_flags)

            if s_block_start("PUBLISHER_LATIN_C", dep="tpub_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Publisher", encoding="latin_1")
            s_block_end("PUBLISHER_LATIN_C")

            if s_block_start("PUBLISHER_UNICODE_C", dep="tpub_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Publisher", encoding="utf16")
            s_block_end("PUBLISHER_UNICODE_C")
        s_block_end("TPUB_COMPRESSED")
    s_block_end("TPUB_DAT")
s_block_end("TPUB")

# -----------------------------------------------------------------------------
# Title
# -----------------------------------------------------------------------------

if s_block_start("TIT2"):
    s_static("TIT2")    # TIT2 frame ID
    s_size("TIT2_DAT", length=4, endian=">", fuzzable=True)
    s_group("tit2_flags", values=frame_flag_values)

    if s_block_start("TIT2_DAT"):
        if s_block_start("TIT2_UNCOMPRESSED", dep="tit2_flags", dep_value="\x00\x00"):
            s_group("tit2_text_encoding", values=text_encoding_flags)

            if s_block_start("TITLE_LATIN", dep="tit2_text_encoding", dep_value="\x00"):
                s_string("Fuzzy Title", encoding="latin_1")     # Song title
            s_block_end("TITLE_LATIN")

            if s_block_start("TITLE_UNICODE", dep="tit2_text_encoding", dep_value="\x01"):
                s_string("Fuzzy Title", encoding="utf16")       # Song title
            s_block_end("TITLE_UNICODE")
        s_block_end("TIT2_UNCOMPRESSED")

        if s_block_start("TIT2_COMPRESSED", dep="tit2_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tit2_text_encoding_c", values=text_encoding_flags)

            if s_block_start("TITLE_LATIN_C", dep="tit2_text_encoding_c", dep_value="\x00"):
                s_string("Fuzzy Title", encoding="latin_1")
            s_block_end("TITLE_LATIN_C")

            if s_block_start("TITLE_UNICODE_C", dep="tit2_text_encoding_c", dep_value="\x01"):
                s_string("Fuzzy Title", encoding="utf16")
            s_block_end("TITLE_UNICODE_C")
        s_block_end("TIT2_COMPRESSED")
    s_block_end("TIT2_DAT")
s_block_end("TIT2")

# -----------------------------------------------------------------------------
# Track number
# -----------------------------------------------------------------------------

if s_block_start("TRCK"):
    s_static("TRCK")    # TRCK frame ID
    s_size("TRCK_DAT", length=4, endian=">", fuzzable=True)
    s_group("trck_flags", values=frame_flag_values)

    if s_block_start("TRCK_DAT"):
        if s_block_start("TRCK_UNCOMPRESSED", dep="trck_flags", dep_value="\x00\x00"):
            s_group("trck_text_encoding", values=text_encoding_flags)

            if s_block_start("TRACK_LATIN", dep="trck_text_encoding", dep_value="\x00"):
                s_string("1", encoding="latin_1")
            s_block_end("TRACK_LATIN")

            if s_block_start("TRACK_UNICODE", dep="trck_text_encoding", dep_value="\x01"):
                s_string("1", encoding="utf16")
            s_block_end("TRACK_UNICODE")
        s_block_end("TRCK_UNCOMPRESSED")

        if s_block_start("TRKC_COMPRESSED", dep="trck_flags", dep_value="\x00\x80", encoder=compress):
            s_group("trck_text_encoding_c", values=text_encoding_flags)

            if s_block_start("TRACK_LATIN_C", dep="trck_text_encoding_c", dep_value="\x00"):
                s_string("1", encoding="latin_1")
            s_block_end("TRACK_LATIN_C")

            if s_block_start("TRACK_UNICODE_C", dep="trck_text_encoding_c", dep_value="\x01"):
                s_string("1", encoding="utf16")
            s_block_end("TRACK_UNICODE_C")
        s_block_end("TRCK_COMPRESSED")
    s_block_end("TRCK_DAT")
s_block_end("TRCK")

# -----------------------------------------------------------------------------
# Year of recording
# -----------------------------------------------------------------------------

if s_block_start("TYER"):
    s_static("TYER")    # TYER frame ID
    s_size("TYER_DAT", length=4, endian=">", fuzzable=True)
    s_group("tyer_flags", values=frame_flag_values)

    if s_block_start("TYER_DAT"):
        if s_block_start("TYER_UNCOMPRESSED", dep="tyer_flags", dep_value="\x00\x00"):
            s_group("tyer_text_encoding", values=text_encoding_flags)

            if s_block_start("YEAR_LATIN", dep="tyer_text_encoding", dep_value="\x00"):
                s_string("2015", encoding="latin_1")    # Year of recording
            s_block_end("YEAR_LATIN")

            if s_block_start("YEAR_UNICODE", dep="tyer_text_encoding", dep_value="\x01"):
                s_string("2015", encoding="utf16")  # Year of recording
            s_block_end("YEAR_UNICODE")
        s_block_end("TYER_UNCOMPRESSED")

        if s_block_start("TYER_COMPRESSED", dep="tyer_flags", dep_value="\x00\x80", encoder=compress):
            s_group("tyer_text_encoding_c", values=text_encoding_flags)

            if s_block_start("YEAR_LATIN_C", dep="tyer_text_encoding_c", dep_value="\x00"):
                s_string("2015", encoding="latin_1")
            s_block_end("YEAR_LATIN_C")

            if s_block_start("YEAR_UNICODE_C", dep="tyer_text_encoding_c", dep_value="\x01"):
                s_string("2015", encoding="utf16")
            s_block_end("YEAR_UNICODE_C")
        s_block_end("TYER_COMPRESSED")
    s_block_end("TYER_DAT")
s_block_end("TYER")

# -----------------------------------------------------------------------------
# Picture
#
# Commented Sulley calls are not in the reference file, but are technically 
# part of the ID3 specification
# -----------------------------------------------------------------------------

if s_block_start("APIC"):
    s_static("APIC")    # APIC frmae ID
    s_size("APIC_DAT", length=4, endian=">", fuzzable=True)
    s_group("apic_flags", values=frame_flag_values)

    if s_block_start("APIC_DAT"):
        if s_block_start("APIC_UNCOMPRESSED", dep="apic_flags", dep_value="\x00\x00"):
            s_group("apic_text_encoding", values=text_encoding_flags)   # What text encoding do we use?
            s_group("apic_mime_types", values=["image/jpeg", "-->"])    # '-->' allows for a URL to a file. Sounds fun

            s_delim("\x00")     # MIME type delimiter
            s_byte(0x03)        # Picture type. 0x03 for "Cover (front)"

            if s_block_start("DESCRIPTION_LATIN", dep="apic_text_encoding", dep_value="\x00"):
                s_string("Cover of the new Fuzzy Album", encoding="latin_1")
                s_delim("\x00")                                                             # erminator
            s_block_end("DESCRIPTION_LATIN")

            if s_block_start("DESCRIPTION_UNICODE", dep="apic_text_encoding", dep_value="\x01"):
                s_string("Cover of the new Fuzzy Album", encoding="utf16")   # Image description
                s_delim("\x00\x00")                                                         # Unicode terminator 
            s_block_end("DESCRIPTION_UNICODE")

            # If we aren't using a URL to the image include the image data
            if s_block_start("IMAGE_DATA", dep="apic_mime_types", dep_value="-->", dep_compare="!="):
                s_binary(cover_image)
            s_block_end("IMAGE_DATA")

            # Use an image URL
            if s_block_start("IMAGE_URL", dep="apic_mime_types", dep_value="-->"):
                s_string("./cover.jpg", encoding="latin_1")      # The URL to the image file
                s_delim("\x00")                                                 # Delimiter for the URL
            s_block_end("IMAGE_URL")
        s_block_end("APIC_UNCOMPRESSED")

        if s_block_start("APIC_COMPRESSED", dep="apic_flags", dep_value="\x00\x80", encoder=compress):
            s_group("apic_text_encoding_c", values=text_encoding_flags)   # What text encoding do we use?
            s_group("apic_mime_types_c", values=["image/jpg", "-->"])     # '-->' allows for a URL to a file. Sounds fun

            s_delim("\x00")     # MIME type delimiter
            s_byte(0x03)        # Picture type. 0x03 for "Cover (front)"

            if s_block_start("DESCRIPTION_LATIN_C", dep="apic_text_encoding_c", dep_value="\x00"):
                s_string("Cover of the new Fuzzy Album", encoding="latin_1")
                s_delim("\x00")                                                                 # Image description terminator
            s_block_end("DESCRIPTION_LATIN_C")

            if s_block_start("DESCRIPTION_UNICODE_C", dep="apic_text_encoding_c", dep_value="\x01"):
                s_string("Cover of the new Fuzzy Album", encoding="utf16")
                s_delim("\x00\x00")                                                         # Unicode terminator for description
            s_block_end("DESCRIPTION_UNICODE_C")

            # If we aren't using a URL to the image include the image data
            if s_block_start("IMAGE_DATA_C", dep="apic_mime_types_c", dep_value="-->", dep_compare="!="):
                s_binary(cover_image)   # 1 pixel JPEG image
            s_block_end("IMAGE_DATA_C")

            # Use an image URL
            if s_block_start("IMAGE_URL_C", dep="apic_mime_types_c", dep_value="-->"):
                s_string("http://", encoding="latin_1")
                s_string("127.0.0.1", encoding="latin_1")
                s_string("/", encoding="latin_1", fuzzable=False)
                s_string("cover.jpg", encoding="latin_1")
                s_delim("\x00")
            s_block_end("IMAGE_URL_C")
        s_block_end("APIC_COMPRESSED")
    s_block_end("APIC_DAT")
s_block_end("APIC")

s_block_end("CRC_WRAPPER")

# -----------------------------------------------------------------------------
# Padding to allow for extending the ID3 tag without rewriting the file. Each
# padding byte should have value 0x00
# -----------------------------------------------------------------------------

if s_block_start("PADDING"):
    s_static("\x00" * 80)   # Add 80 bytes of padding
s_block_end("PADDING")

s_block_end("ID3_FRAMES")

s_block_end("ID3_TAG")

