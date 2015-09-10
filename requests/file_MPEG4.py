# ================================================================================
# Basic MPEG-4 Descriptor
# This file is part of the FuzzLabs Fuzzing Framework
# Author: FuzzLabs
# ================================================================================

from sulley import *

s_initialize("MPEG4")

# --------------------------------------------------------------------------------
# offset: 0x00
# --------------------------------------------------------------------------------

if s_block_start("MPG4_FTYP"):
    s_size("MPG4_FTYP", endian=">", inclusive=False, length=4,
           fuzzable=True)			# Box size
    s_dword(0x66747970, endian=">")		# Box type (ftyp)
    s_dword(0x69736F6D, endian=">")		# Major brand (isom)
    s_dword(0x0200, endian=">")			# Minor version (512)

    if s_block_start("MPG4_FTYP_COMP_BRANDS"):
        s_dword(0x69736F6D, endian=">")		# isom
        s_dword(0x69736F32, endian=">")		# iso2
        s_dword(0x6D703431, endian=">")		# mp41
    s_block_end("MPG4_FTYP_COMP_BRANDS")
s_block_end("MPG4_FTYP")
s_repeat("MPG4_FTYP", min_reps=0, max_reps=1000, step=100)

# --------------------------------------------------------------------------------
# offset: 0x1C
# --------------------------------------------------------------------------------

if s_block_start("MPG4_FREE"):
    s_size("MPG4_FREE", endian=">", inclusive=False, length=4,
           fuzzable=True)			# Box size
    s_dword(0x66726565, endian=">")		# Box type
s_block_end("MPG4_FREE")
s_repeat("MPG4_FREE", min_reps=0, max_reps=1000, step=100)

# --------------------------------------------------------------------------------
# offset: 0x24
# --------------------------------------------------------------------------------

if s_block_start("MPG4_MDAT_1"):
    s_size("MPG4_MDAT_1", endian=">", inclusive=False, length=4,
           fuzzable=True)			# Box size
    s_dword(0x6D646174, endian=">")               # Box type

    if s_block_start("MPG4_MDAT_1_STBL_1"):
        s_dword(0x01B3, endian=">")
        s_binary("\x00\x10\x07\x00" +\
                 "\x00\x01\xB6\x10\x60\x56\x18\x15" +\
                 "\x82\x88\x76\xA9\x86\xFF\xA9\x87" +\
                 "\xF6\xA6\x61\x86\x53\x96\x17\x5F" +\
                 "\xB4\xAB\xC9\xF2\x7D\x57\xD9\x67" +\
                 "\xDF\xB3\x18\x6F\x37\x35\xA4\xFC" +\
                 "\x10\x1B\x9B\x97\xDB\x54\xB9\x00" +\
                 "\x51\x31\x3C\x5A\x39\x2D\x98\xD8" +\
                 "\x1A\xDD\xB9\x33\x6C\xC2\xD5\x72" +\
                 "\xD6\x83\xDE\x7E\xF2\x22\xB7\xC5" +\
                 "\x65\x57\x84\x67\x53\x88\x6C\xF8" +\
                 "\x47\x64\x7A\x99\x86\x44\x72\xF1" +\
                 "\x20\x74\x3E\x05\x30\xFF\xEC\x40" +\
                 "\x68\xA8\x7C\xC2\x64\xC5\x91\x40" +\
                 "\x1E\x06\xC6\xDA\xCF\x2B\x54\xDC" +\
                 "\xA1\xF5\x06\x1C\x8E\x2C\x4C\x0E" +\
                 "\x4A\x93\xFD\xDF\x38\xF3\x3A\x21" +\
                 "\x88\x6C\x97\x84\x15\x6C\x2B\xFE" +\
                 "\xB7\xB1\x5A\x55\x7E\x11\xB1\x32" +\
                 "\x40\x32\xDF\xC3\xD0\x62\xA9\x8A" +\
                 "\x95\x4E\x95\x4E\x7A\x66\xEF\x44" +\
                 "\x53\xFF\x62\xB2\xF1\x22\xB4\x25" +\
                 "\x83\x28\x2E\x1C\x97\xDD\xC4\xDA" +\
                 "\xC0\x18\x50\xDF\xC0\xDA\x46\x92" +\
                 "\xC9\x7D\x9B\xFE\x5C\x8D\xF2\x95" +\
                 "\xD8\x55\x6F\x4F\x30\x70\x1E\x1E" +\
                 "\x9A\x48\x0F\x13\xFF\x28\x90\x0F" +\
                 "\x9B\xFF\x89\x76\x87\x85\xFB\xAC" +\
                 "\x25\x04\x44\xBE\x54\xC8\xE5\x30" +\
                 "\x7E\xCA\x4D\x89\x07\x3E\x4D\xB3" +\
                 "\xF9\xE6\x6C\xBE\xFF\xE2\x8D\x03" +\
                 "\x0B\x51\x12\xA1\x7A\xC3\x9F\x07" +\
                 "\x20\xF1\x50\x0C\xA4\x06\x09\x7E" +\
                 "\xC5\x22\x40\x1F\x04\x25\x49\x81" +\
                 "\xB9\xA0\xF0\x30\x1D\xD6\x44\xA1" +\
                 "\x1C\x4B\x11\xFC\x21\x88\x63\xE0" +\
                 "\x6D\x2C\x12\xD5\x27\x1D\x04\x25" +\
                 "\x43\xCA\xC6\x81\xEF\x34\x5F\xF6" +\
                 "\x13\x27\x1F\x0F\xFE\x06\x84\x74" +\
                 "\x9E\xB2\x0E\xEE\xA6\x99\xF6\xCB" +\
                 "\xCC\x38\x08\x20\x84\x5C\x91\x23" +\
                 "\x0C\x2B\x4C\xC3\x5A\x01\xC0\xCC" +\
                 "\xA4\x65\x52\xA4\xC2\x5A\xEC\x88" +\
                 "\xE3\xE0\x61\x2D\xA1\x2B\x12\xE3" +\
                 "\x7E\xA5\xBF\x6C\x18\x41\x08\x19" +\
                 "\x3F\x25\x69\x56\xD9\x47\x39\xE4" +\
                 "\xC0\xF8\x50\x05\x8F\x99\x40\x0F" +\
                 "\x0F\x00\xDE\x06\x62\xCB\xD0\x78" +\
                 "\x3F\xF9\xC1\xE2\x3F\xF3\xC0\x72" +\
                 "\x97\x7C\xC9\x81\xF0\x64\xA2\x53" +\
                 "\x3F\x65\x2A\xA6\xC0\x33\xC9\x19" +\
                 "\x03\x82\x40\x40\xF8\xF1\xB0\x78" +\
                 "\x1F\xEE\xC1\x84\x1A\x0C\x58\x98" +\
                 "\x78\xD7\xD4\x24\x61\x9A\x0A\x2F" +\
                 "\x08\x23\xF2\xE0\x62\xD8\xDD\xC6" +\
                 "\x3E\xA1\x9F\xB7\xFC\xC1\x27\x7E" +\
                 "\x7C\x7E\x0E\x00\xFC\x07\x85\x80" +\
                 "\xA4\x0E\x03\xC4\xC0\x23\xA0\xF9" +\
                 "\xBF\xFC\xAB\xA3\x7D\x0D\x68\x53" +\
                 "\xFD")
    s_block_end("MPG4_MDAT_1_STBL_1")

    # ----------------------------------------------------------------------------
    # offset: 0x205
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_MDAT_1_STBL_2"):
        s_dword(0x01B6, endian=">")
        s_dword(0x50F023EF, endian=">")
    s_block_end("MPG4_MDAT_1_STBL_2")

    # ----------------------------------------------------------------------------
    # offset: 0x20D
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_MDAT_1_STBL_3"):
        s_dword(0x01B6, endian=">")
        s_dword(0x516023EF, endian=">")
    s_block_end("MPG4_MDAT_1_STBL_3")

s_block_end("MPG4_MDAT_1")
s_repeat("MPG4_MDAT_1", min_reps=0, max_reps=1000, step=100)

# --------------------------------------------------------------------------------
# offset: 0x215
# --------------------------------------------------------------------------------

if s_block_start("MPG4_MDAT_2"):
    s_size("MPG4_MDAT_2", endian=">", inclusive=False, length=4,
           fuzzable=True)                       # Box size
    s_dword(0x6D646174, endian=">")               # Box type (mdat)

    # ----------------------------------------------------------------------------
    # offset: 0x21D
    # ----------------------------------------------------------------------------

    s_size("MPG4_MDAT_2_STR_FIELD_1", endian=">", inclusive=False, length=2,
               fuzzable=True)                   # Text field size
    if s_block_start("MPG4_MDAT_2_STR_FIELD_1"):
        s_string("Chapter 1")
    s_block_end("MPG4_MDAT_2_STR_FIELD_1")

    # ----------------------------------------------------------------------------
    # offset: 0x228
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_MDAT_2_ENCD"):
        s_size("MPG4_MDAT_2_ENCD", endian=">", inclusive=False, length=4,
               fuzzable=True)                   # Box size
        s_dword(0x656E6364, endian=">")           # Box type (encd)

        s_dword(0x00000100, endian=">")           # ???

    s_block_end("MPG4_MDAT_2_ENCD")
    s_repeat("MPG4_MDAT_2_ENCD", min_reps=0, max_reps=1000, step=100)

s_block_end("MPG4_MDAT_2")
s_repeat("MPG4_MDAT_2", min_reps=0, max_reps=1000, step=100)

# --------------------------------------------------------------------------------
# offset: 0x234
# --------------------------------------------------------------------------------

if s_block_start("MPG4_MOOV"):
    s_size("MPG4_MOOV", endian=">", inclusive=False, length=4,
           fuzzable=True)                       # Box size
    s_dword(0x6D6F6F76, endian=">")               # Box type (moov)

    # ----------------------------------------------------------------------------
    # offset: 0x23C
    # https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/QTFFChap2/qtff2.html
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_MVHD"):
        s_size("MPG4_MVHD", endian=">", inclusive=False, length=4,
               fuzzable=True)                   # Box size
        s_dword(0x6D766864, endian=">")           # Box type (mvhd)

        s_byte(0x00, endian=">")		# Version
        s_byte(0x00, endian=">")		# Flags (3 bytes)
        s_byte(0x00, endian=">")		# Flags (3 bytes)
        s_byte(0x00, endian=">")		# Flags (3 bytes)
        s_dword(0x00, endian=">")			# Creation time
        s_dword(0xD1D2AC97, endian=">")		# Modification time
        s_dword(0x03E8, endian=">")		# Timescale 
        s_dword(0x7D, endian=">")			# Duration
        s_dword(0x010000, endian=">")		# Preferred rate
        s_word(0x0100, endian=">")		# Preferred volume

        s_binary("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        # Matrix structure START

        s_dword(0x00010000, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x010000, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x00, endian=">")
        s_dword(0x40000000, endian=">")

        # Matrix structure END

        s_dword(0x00, endian=">")			# Preview time
        s_dword(0x00, endian=">")			# Preview duration
        s_dword(0x00, endian=">")			# Poster time
        s_dword(0x00, endian=">")			# Selection time
        s_dword(0x00, endian=">")			# Selection duration
        s_dword(0x00, endian=">")			# Current time
        s_dword(0x03, endian=">")			# Next track ID
    s_block_end("MPG4_MVHD")
    s_repeat("MPG4_MVHD", min_reps=0, max_reps=1000, step=100)

    # ----------------------------------------------------------------------------
    # offset: 0x2A8
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_TRAK_1"):
        s_size("MPG4_TRAK_1", endian=">", inclusive=False, length=4,
               fuzzable=True)                   # Box size
        s_dword(0x7472616B, endian=">")           # Box type (trak)

        # ------------------------------------------------------------------------
        # offset: 0x2B0
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_1_TKHD_1"):
            s_size("MPG4_TRAK_1_TKHD_1", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x746B6864, endian=">")       # Box type (tkhd)

            s_byte(0x00, endian=">")		# Version
            s_byte(0x00, endian=">")		# Flags (3 bytes)
            s_byte(0x00, endian=">")		# Flags (3 bytes)
            s_byte(0x03, endian=">")		# Flags (3 bytes)

            s_dword(0x00, endian=">")		# Creation time
            s_dword(0x00, endian=">")		# Modification time
            s_dword(0x01, endian=">")		# Track ID
            s_dword(0x00, endian=">")		# Reserved
            s_dword(0x7D, endian=">")		# Duration

            s_binary("\x00\x00\x00\x00\x00\x00\x00\x00")

            s_word(0x00, endian=">")		# Layer
            s_word(0x00, endian=">")		# Alternate group
            s_word(0x00, endian=">")		# Volume
            s_word(0x00, endian=">")		# Reserved

            # Matrix structure START

            s_dword(0x010000, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            # Matrix structure START
            s_dword(0x010000, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x40000000, endian=">")

            # Matrix structure END

            s_dword(0x190000, endian=">")		# Track width
            s_dword(0x190000, endian=">")		# Track height

        s_block_end("MPG4_TRAK_1_TKHD_1")
        s_repeat("MPG4_TRAK_1_TKHD_1", min_reps=0, max_reps=1000, step=100)

        # ------------------------------------------------------------------------
        # offset: 0x30C
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_1_EDTS_1"):
            s_size("MPG4_TRAK_1_EDTS_1", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x65647473, endian=">")       # Box type (edts)

            # --------------------------------------------------------------------
            # offset: 0x314
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_1_EDTS_1_ELST_1"):
                s_size("MPG4_TRAK_1_EDTS_1_ELST_1", endian=">", inclusive=False, length=4,
                       fuzzable=True)           # Box size
                s_dword(0x656C7374, endian=">")   # Box type (elst)

                s_byte(0x00, endian=">")	# Version
                s_byte(0x00, endian=">")	# Flags (3 bytes)
                s_byte(0x00, endian=">")	# Flags (3 bytes)
                s_byte(0x00, endian=">")	# Flags (3 bytes)

                s_dword(0x01, endian=">")		# Number of entries

                s_dword(0x7D, endian=">")		# Track duration
                s_dword(0x00, endian=">")		# Media time
                s_dword(0x010000, endian=">")	# Media rate
            s_block_end("MPG4_TRAK_1_EDTS_1_ELST_1")
            s_repeat("MPG4_TRAK_1_EDTS_1_ELST_1", min_reps=0, max_reps=1000, step=100)

        s_block_end("MPG4_TRAK_1_EDTS_1")
        s_repeat("MPG4_TRAK_1_EDTS_1", min_reps=0, max_reps=1000, step=100)

        # ------------------------------------------------------------------------
        # offset: 0x330
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_1_MDIA_1"):
            s_size("MPG4_TRAK_1_MDIA_1", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x6D646961, endian=">")       # Box type (mdia)

            # --------------------------------------------------------------------
            # offset: 0x338
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_1_MDIA_1_MDHD_1"):
                s_size("MPG4_TRAK_1_MDIA_1_MDHD_1", endian=">", inclusive=False, length=4,
                       fuzzable=True)				# Box size
                s_dword(0x6D646864, endian=">")			# Box type (mdhd)

                s_byte(0x00, endian=">")			# Version
                s_byte(0x00, endian=">")			# Flags (3 bytes)
                s_byte(0x00, endian=">")			# Flags (3 bytes)
                s_byte(0x00, endian=">")			# Flags (3 bytes)

                s_dword(0x00, endian=">", fuzzable=False)		# Creation time
                s_dword(0x00, endian=">", fuzzable=False)		# Modification time

                s_dword(0x3000, endian=">", fuzzable=False)	# Time scale
                s_dword(0x0600, endian=">", fuzzable=False)	# Duration

                s_word(0x55C4, endian=">")			# Language
                s_word(0x00, endian=">")			# Quality
            s_block_end("MPG4_TRAK_1_MDIA_1_MDHD_1")
            s_repeat("MPG4_TRAK_1_MDIA_1_MDHD_1", min_reps=0, max_reps=1000, step=100)

            # --------------------------------------------------------------------
            # offset: 0x358
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_1_MDIA_1_HDLR_1"):
                s_size("MPG4_TRAK_1_MDIA_1_HDLR_1", endian=">", inclusive=False, length=4,
                       fuzzable=True)				# Box size
                s_dword(0x68646C72, endian=">")			# Box type (hdlr)

                s_byte(0x00, endian=">")                        # Version
                s_byte(0x00, endian=">")                        # Flags (3 bytes)
                s_byte(0x00, endian=">")                        # Flags (3 bytes)
                s_byte(0x00, endian=">")                        # Flags (3 bytes)

                s_dword(0x00, endian=">", fuzzable=False)		# Component type
                s_dword(0x76696465, endian=">", fuzzable=False)	# Component subtype
                s_dword(0x00, endian=">", fuzzable=False)		# Component manufacturer
                s_dword(0x00, endian=">", fuzzable=False)		# Component flags
                s_dword(0x00, endian=">", fuzzable=False)		# Component flags mask

                s_string("VideoHandler")
                s_byte(0x00)

            s_block_end("MPG4_TRAK_1_MDIA_1_HDLR_1")
            s_repeat("MPG4_TRAK_1_MDIA_1_HDLR_1", min_reps=0, max_reps=1000, step=100)

            # --------------------------------------------------------------------
            # offset: 0x385
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1"):
                s_size("MPG4_TRAK_1_MDIA_1_MINF_1", endian=">", inclusive=False, length=4,
                       fuzzable=True)				# Box size
                s_dword(0x6D696E66, endian=">")			# Box type (minf)
                
                # ----------------------------------------------------------------
                # offset: 0x38D
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_VMHD_1"):
                    s_size("MPG4_TRAK_1_MDIA_1_MINF_1_VMHD_1", endian=">", inclusive=False, length=4,
                           fuzzable=True)			# Box size
                    s_dword(0x766D6864, endian=">")		# Box type (vmhd)

                    s_byte(0x00, endian=">")			# Version
                    s_byte(0x00, endian=">")			# Flags (3 bytes)
                    s_byte(0x00, endian=">")			# Flags (3 bytes)
                    s_byte(0x01, endian=">")			# Flags (3 bytes)

                    s_word(0x00, endian=">")			# Graphics mode
                    s_word(0x00, endian=">")			# R
                    s_word(0x00, endian=">")			# G
                    s_word(0x00, endian=">")			# B
                    
                s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_VMHD_1")
                s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_VMHD_1", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x3A1
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1"):
                    s_size("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1", endian=">", inclusive=False, length=4,
                           fuzzable=True)			# Box size
                    s_dword(0x64696E66, endian=">")		# Box type (dinf)

                    # ------------------------------------------------------------
                    # offset: 0x3A9
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x64726566, endian=">")	# Box type (dref)

                        s_byte(0x00, endian=">")         # Version
                        s_byte(0x00, endian=">")         # Flags (3 bytes)
                        s_byte(0x00, endian=">")         # Flags (3 bytes)
                        s_byte(0x00, endian=">")         # Flags (3 bytes)

                        s_dword(0x01, endian=">")		# Entry count

                        if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1_URL"):
                            s_size("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1_URL", endian=">", inclusive=False, length=4,
                                   fuzzable=True)		# Box size
                            s_dword(0x75726c20, endian=">")	# Box type (url)

                            s_byte(0x00, endian=">")	# Version
                            s_byte(0x00, endian=">")	# Flags (3 bytes)
                            s_byte(0x00, endian=">")	# Flags (3 bytes)
                            s_byte(0x01, endian=">")	# Flags (3 bytes)

                        s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1_URL")
                        s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1_URL", min_reps=0, max_reps=1000, step=100)

                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1_DREF_1", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1")
                s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_DINF_1", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x3C5
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1"):
                    s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1", endian=">", inclusive=False, length=4,
                           fuzzable=True)			# Box size
                    s_dword(0x7374626C, endian=">")		# Box type (stbl)

                    # ------------------------------------------------------------
                    # offset: 0x3CD
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x73747364, endian=">")		# Box type (stsd)

                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /

                        s_dword(0x01, endian=">")			# Entry count

                        # --------------------------------------------------------
                        # offset: 0x3DD
                        # --------------------------------------------------------

                        if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V"):
                            s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V", endian=">", inclusive=False, length=4,
                                   fuzzable=True)			# Box size
                            s_dword(0x6D703476, endian=">")		# Box type (mp4v)

                            s_binary("\x00\x00\x00\x00\x00\x00\x00\x01" + \
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x19\x00\x19\x00\x48\x00\x00" + \
                                     "\x00\x48\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x01\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                                     "\x00\x00\x00\x18\xff\xff")

                            # ----------------------------------------------------
                            # offset: 0x433
                            # ----------------------------------------------------

                            if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V_ESDS"):
                                s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V_ESDS", endian=">", inclusive=False, length=4,
                                       fuzzable=True)			# Box size
                                s_dword(0x65736473, endian=">")		# Box type (esds)

                                s_byte(0x00, endian=">")                # Version
                                s_byte(0x00, endian=">")                # Flags (3 bytes) \
                                s_byte(0x00, endian=">")                # Flags (3 bytes) |
                                s_byte(0x00, endian=">")                # Flags (3 bytes) /

                                # Not much on this... The definition might be 
                                # incorrect but should be ok. We fuzz what we
                                # have to.

                                s_byte(0x03, endian=">")		# Tag
                                s_byte(0x80, endian=">")		# unknown
                                s_byte(0x80, endian=">")		# unknown
                                s_byte(0x80, endian=">")		# unknown
                                s_byte(0x4F, endian=">")		# Tag size
                                s_word(0x0001, endian=">")		# ES_ID
                                s_byte(0x00, endian=">")		# ???

                                s_binary("\x04")			# Tag
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x41, endian=">")                # Tag size
                                s_word(0x2011, endian=">")              # ES_ID
                                s_byte(0x00, endian=">")                # ???

                                s_string("\x01\xD9\x00\x31\xAA\xD8\x00\x00" +\
                                         "\x7A\x40")

                                s_binary("\x05")			# Tag
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x80, endian=">")                # unknown
                                s_byte(0x2F, endian=">")                # Tag size
                                s_word(0x0000, endian=">")              # ES_ID
                                s_byte(0x01, endian=">")                # ???

                                # Dunno this. Will leave it as static.

                                s_binary("\xB0\x01\x00\x00\x01\xB5\x89\x13" +\
                                         "\x00\x00\x01\x00\x00\x00\x01\x20" +\
                                         "\x00\xC4\x8D\x88\x00\xC5\x00\xCC" +\
                                         "\x03\x34\x63\x00\x00\x01\xB2\x4C" +\
                                         "\x61\x76\x63\x35\x35\x2E\x33\x39" +\
                                         "\x2E\x31\x30\x31")

                                s_binary("\x06\x80\x80\x80\x01\x02")	# Tag - no need to fuzz

                            s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V_ESDS")
                            s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V_ESDS", min_reps=0, max_reps=1000, step=100)

                        s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V")
                        s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1_MP4V", min_reps=0, max_reps=1000, step=100)

                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSD_1", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x493
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STTS"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STTS", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x73747473, endian=">")		# Box type (stts)
                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /
                        s_dword(0x01, endian=">")			# Entry count
                        s_dword(0x03, endian=">")			# Sample count
                        s_dword(0x0200, endian=">")		# Sample delta
                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STTS")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STTS", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x4AB
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSS"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSS", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x73747373, endian=">")		# Box type (stss)
                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /
                        s_dword(0x01, endian=">")			# Entry count
                        s_dword(0x01, endian=">")			# Sample number
                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSS")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSS", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x4BF
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSC"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSC", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x73747363, endian=">")		# Box type (stsc)
                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /
                        s_dword(0x01, endian=">")			# Entry count
                        s_dword(0x01, endian=">")			# First chunk
                        s_dword(0x03, endian=">")			# Samples per chunk
                        s_dword(0x01, endian=">")			# Samples description index
                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSC")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSC", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x4DB
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSZ"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSZ", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x7374737A, endian=">")		# Box type (stsz)
                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /
                        s_dword(0x0, endian=">")			# Sample size
                        s_dword(0x3, endian=">")			# Sample count
                        s_dword(0x01D9, endian=">")		# Sample size
                        s_dword(0x08, endian=">")			# Sample size
                        s_dword(0x08, endian=">")			# Sample size
                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSZ")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STSZ", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x4FB
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STCO"):
                        s_size("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STCO", endian=">", inclusive=False, length=4,
                               fuzzable=True)			# Box size
                        s_dword(0x7374636F, endian=">")		# Box type (stco)
                        s_byte(0x00, endian=">")		# Version
                        s_byte(0x00, endian=">")		# Flags (3 bytes) \
                        s_byte(0x00, endian=">")		# Flags (3 bytes) |
                        s_byte(0x00, endian=">")		# Flags (3 bytes) /
                        s_dword(0x01, endian=">")			# Entry count
                        s_dword(0x2C, endian=">")			# Chunk offset
                    s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STCO")
                    s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1_STCO", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1")
                s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1_STBL_1", min_reps=0, max_reps=1000, step=100)

            s_block_end("MPG4_TRAK_1_MDIA_1_MINF_1")
            s_repeat("MPG4_TRAK_1_MDIA_1_MINF_1", min_reps=0, max_reps=1000, step=100)

        s_block_end("MPG4_TRAK_1_MDIA_1")
        s_repeat("MPG4_TRAK_1_MDIA_1", min_reps=0, max_reps=1000, step=100)

        # ------------------------------------------------------------------------
        # offset: 0x50F
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_1_TREF_1"):
            s_size("MPG4_TRAK_1_TREF_1", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x74726566, endian=">")       # Box type (tref)

            # --------------------------------------------------------------------
            # offset: 0x517
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_1_TREF_1_CHAP"):
                s_size("MPG4_TRAK_1_TREF_1_CHAP", endian=">", inclusive=False, length=4,
                       fuzzable=True)		# Box size
                s_dword(0x63686170, endian=">")	# Box type (chap)

                s_dword(0x02, endian=">")		# ???
            s_block_end("MPG4_TRAK_1_TREF_1_CHAP")
        s_block_end("MPG4_TRAK_1_TREF_1")

    s_block_end("MPG4_TRAK_1")
    s_repeat("MPG4_TRAK_1", min_reps=0, max_reps=1000, step=100)

    # ----------------------------------------------------------------------------
    # offset: 0x523
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_UDTA"):
        s_size("MPG4_UDTA", endian=">", inclusive=False, length=4,
               fuzzable=True)			# Box size
        s_dword(0x75647461, endian=">")		# Box type (udta)

        # ------------------------------------------------------------------------
        # offset: 0x52B
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_UDTA_META"):
            s_size("MPG4_UDTA_META", endian=">", inclusive=False, length=4,
                   fuzzable=True)			# Box size
            s_dword(0x6D657461, endian=">")		# Box type (meta)

            s_byte(0x00, endian=">")			# Version
            s_byte(0x00, endian=">")			# Flags (3 bytes) \
            s_byte(0x00, endian=">")			# Flags (3 bytes) |
            s_byte(0x00, endian=">")			# Flags (3 bytes) /

            # --------------------------------------------------------------------
            # offset: 0x537
            # --------------------------------------------------------------------

            if s_block_start("MPG4_UDTA_META_HDLR"):
                s_size("MPG4_UDTA_META_HDLR", endian=">", inclusive=False, length=4,
                       fuzzable=True)			# Box size
                s_dword(0x68646C72, endian=">")		# Box type (hdlr)

                s_byte(0x00, endian=">")		# Version
                s_byte(0x00, endian=">")		# Flags (3 bytes) \
                s_byte(0x00, endian=">")		# Flags (3 bytes) |
                s_byte(0x00, endian=">")		# Flags (3 bytes) /

                s_dword(0x00, endian=">")			# ???
                s_string("mdir")
                s_string("appl")

                s_dword(0x00, endian=">")			# ???
                s_dword(0x00, endian=">")			# ???
                s_byte(0x00)				# ???

            s_block_end("MPG4_UDTA_META_HDLR")
            s_repeat("MPG4_UDTA_META_HDLR", min_reps=0, max_reps=1000, step=100)

            # --------------------------------------------------------------------
            # offset: 0x558
            # --------------------------------------------------------------------

            if s_block_start("MPG4_UDTA_META_ILST"):
                s_size("MPG4_UDTA_META_ILST", endian=">", inclusive=False, length=4,
                       fuzzable=True)			# Box size
                s_dword(0x696C7374, endian=">")		# Box type (ilst)

                s_dword(0x57, endian=">")			# ???
                s_dword(0x2D2D2D2D, endian=">")		# ???

                # ----------------------------------------------------------------
                # offset: 0x568
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_MEAN"):
                    s_size("MPG4_UDTA_META_ILST_MEAN", endian=">", inclusive=False, length=4,
                           fuzzable=True)			# Box size
                    s_dword(0x6D65616E, endian=">")		# Box type (mean)

                    s_dword(0x00, endian=">")

                    s_string("com.apple.iTunes")		# Payload
                s_block_end("MPG4_UDTA_META_ILST_MEAN")
                s_repeat("MPG4_UDTA_META_ILST_MEAN", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x584
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_NAME"):
                    s_size("MPG4_UDTA_META_ILST_NAME", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x6E616D65, endian=">")               # Box type (name)

                    s_dword(0x00, endian=">")

                    s_string("iTunEXTC")			# Payload
                s_block_end("MPG4_UDTA_META_ILST_NAME")
                s_repeat("MPG4_UDTA_META_ILST_NAME", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x598
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_DATA_1"):
                    s_size("MPG4_UDTA_META_ILST_DATA_1", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x64617461, endian=">")               # Box type (data)

                    s_dword(0x01, endian=">")			# Data type
                    s_dword(0x00, endian=">")			# Reserved

                    s_string("mpaa")				# Payload
                    s_delim("|")
                    s_string("PG-13")
                    s_delim("|")
                    s_string("300")
                    s_delim("|")
                s_block_end("MPG4_UDTA_META_ILST_DATA_1")
                s_repeat("MPG4_UDTA_META_ILST_DATA_1", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x5B7
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CNAM"):
                    s_size("MPG4_UDTA_META_ILST_CNAM", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0xA96E616D, endian=">")               # Box type (data)

                    if s_block_start("MPG4_UDTA_META_ILST_CNAM_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CNAM_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("NCC MP4 FUZZING")                 # Payload
                    s_block_end("MPG4_UDTA_META_ILST_CNAM_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CNAM_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CNAM")
                s_repeat("MPG4_UDTA_META_ILST_CNAM", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x5DE
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CART"):
                    s_size("MPG4_UDTA_META_ILST_CART", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0xA9415254, endian=">")               # Box type (cart)

                    # offset: 0x5E6

                    if s_block_start("MPG4_UDTA_META_ILST_CART_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CART_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("Zsolt Imre")
                    s_block_end("MPG4_UDTA_META_ILST_CART_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CART_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CART")
                s_repeat("MPG4_UDTA_META_ILST_CART", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x600
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CGEN"):
                    s_size("MPG4_UDTA_META_ILST_CGEN", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0xA967656E, endian=">")               # Box type (cgen)

                    # offset: 0x608

                    if s_block_start("MPG4_UDTA_META_ILST_CGEN_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CGEN_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("Action")
                    s_block_end("MPG4_UDTA_META_ILST_CGEN_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CGEN_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CGEN")
                s_repeat("MPG4_UDTA_META_ILST_CGEN", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x61E
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CDAY"):
                    s_size("MPG4_UDTA_META_ILST_CDAY", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0xA9646179, endian=">")               # Box type (cday)

                    # offset: 0x626

                    if s_block_start("MPG4_UDTA_META_ILST_CDAY_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CDAY_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("2015")
                        s_delim("-")
                        s_string("07")
                        s_delim("-")
                        s_string("20")
                    s_block_end("MPG4_UDTA_META_ILST_CDAY_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CDAY_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CDAY")
                s_repeat("MPG4_UDTA_META_ILST_CDAY", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x640
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_TRKN"):
                    s_size("MPG4_UDTA_META_ILST_TRKN", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x74726B6E, endian=">")               # Box type (trkn)

                    # offset: 0x648

                    if s_block_start("MPG4_UDTA_META_ILST_TRKN_DATA"):
                        s_size("MPG4_UDTA_META_ILST_TRKN_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x00, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("\x00\x00\x00\x00\x00\x00\x00\x00")
                    s_block_end("MPG4_UDTA_META_ILST_TRKN_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_TRKN_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_TRKN")
                s_repeat("MPG4_UDTA_META_ILST_TRKN", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x660
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_DISK"):
                    s_size("MPG4_UDTA_META_ILST_DISK", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x6469736B, endian=">")               # Box type (disk)

                    # offset: 0x668

                    if s_block_start("MPG4_UDTA_META_ILST_DISK_DATA"):
                        s_size("MPG4_UDTA_META_ILST_DISK_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x00, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("\x00\x00\x00\x00\x00\x00")
                    s_block_end("MPG4_UDTA_META_ILST_DISK_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_DISK_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_DISK")
                s_repeat("MPG4_UDTA_META_ILST_DISK", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x67E
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_TVSN"):
                    s_size("MPG4_UDTA_META_ILST_TVSN", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x7476736E, endian=">")               # Box type (tvsn)

                    # offset: 0x686

                    if s_block_start("MPG4_UDTA_META_ILST_TVSN_DATA"):
                        s_size("MPG4_UDTA_META_ILST_TVSN_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x15, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_dword(0x00, endian=">")                     # ??? payload
                    s_block_end("MPG4_UDTA_META_ILST_TVSN_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_TVSN_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_TVSN")
                s_repeat("MPG4_UDTA_META_ILST_TVSN", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x69A
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_TVES"):
                    s_size("MPG4_UDTA_META_ILST_TVES", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x74766573, endian=">")               # Box type (tves)

                    # offset: 0x6A2

                    if s_block_start("MPG4_UDTA_META_ILST_TVES_DATA"):
                        s_size("MPG4_UDTA_META_ILST_TVES_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x15, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_dword(0x00, endian=">")                     # ??? payload
                    s_block_end("MPG4_UDTA_META_ILST_TVES_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_TVES_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_TVES")
                s_repeat("MPG4_UDTA_META_ILST_TVES", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x6B6
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_DESC"):
                    s_size("MPG4_UDTA_META_ILST_DESC", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x64657363, endian=">")               # Box type (desc)

                    # offset: 0x6BE

                    if s_block_start("MPG4_UDTA_META_ILST_DESC_DATA"):
                        s_size("MPG4_UDTA_META_ILST_DESC_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("MP4 File created for fuzzing")    # Payload
                        s_byte(0x2E)                                # Payload
                    s_block_end("MPG4_UDTA_META_ILST_DESC_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_DESC_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_DESC")
                s_repeat("MPG4_UDTA_META_ILST_DESC", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x6EB
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_LDES"):
                    s_size("MPG4_UDTA_META_ILST_LDES", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x6C646573, endian=">")               # Box type (ldes)

                    # offset: 0x6F3

                    if s_block_start("MPG4_UDTA_META_ILST_LDES_DATA"):
                        s_size("MPG4_UDTA_META_ILST_LDES_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("MP4 File created by NCC Group for fuzzing purposes")
                        s_byte(0x2E)
                    s_block_end("MPG4_UDTA_META_ILST_LDES_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_LDES_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_LDES")
                s_repeat("MPG4_UDTA_META_ILST_LDES", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x736
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CTOO"):
                    s_size("MPG4_UDTA_META_ILST_CTOO", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0xA9746F6F, endian=">")               # Box type (ctoo)

                    # offset: 0x73E

                    if s_block_start("MPG4_UDTA_META_ILST_CTOO_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CTOO_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x01, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_string("Lavf55.19.104")
                    s_block_end("MPG4_UDTA_META_ILST_CTOO_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CTOO_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CTOO")
                s_repeat("MPG4_UDTA_META_ILST_CTOO", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x75B
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_HDVD"):
                    s_size("MPG4_UDTA_META_ILST_HDVD", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x68647664, endian=">")               # Box type (hdvd)

                    # offset: 0x763

                    if s_block_start("MPG4_UDTA_META_ILST_HDVD_DATA"):
                        s_size("MPG4_UDTA_META_ILST_HDVD_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x15, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_byte(0x00)
                    s_block_end("MPG4_UDTA_META_ILST_HDVD_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_HDVD_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_HDVD")
                s_repeat("MPG4_UDTA_META_ILST_HDVD", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x774
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_STIK"):
                    s_size("MPG4_UDTA_META_ILST_STIK", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x7374696B, endian=">")               # Box type (stik)

                    # offset: 0x77C

                    if s_block_start("MPG4_UDTA_META_ILST_STIK_DATA"):
                        s_size("MPG4_UDTA_META_ILST_STIK_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x15, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_byte(0x09)
                    s_block_end("MPG4_UDTA_META_ILST_STIK_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_STIK_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_STIK")
                s_repeat("MPG4_UDTA_META_ILST_STIK", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x78D
                # ----------------------------------------------------------------

                if s_block_start("MPG4_UDTA_META_ILST_CNID"):
                    s_size("MPG4_UDTA_META_ILST_CNID", endian=">", inclusive=False, length=4,
                           fuzzable=True)                       # Box size
                    s_dword(0x636E4944, endian=">")               # Box type (cnid)

                    # offset: 0x795

                    if s_block_start("MPG4_UDTA_META_ILST_CNID_DATA"):
                        s_size("MPG4_UDTA_META_ILST_CNID_DATA", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x64617461, endian=">")               # Box type (data)
                        s_dword(0x15, endian=">")                     # Data type
                        s_dword(0x00, endian=">")                     # Reserved
                        s_dword(0x00, endian=">")
                    s_block_end("MPG4_UDTA_META_ILST_CNID_DATA")
                    s_repeat("MPG4_UDTA_META_ILST_CNID_DATA", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_UDTA_META_ILST_CNID")
                s_repeat("MPG4_UDTA_META_ILST_CNID", min_reps=0, max_reps=1000, step=100)

            s_block_end("MPG4_UDTA_META_ILST")
            s_repeat("MPG4_UDTA_META_ILST", min_reps=0, max_reps=1000, step=100)

        s_block_end("MPG4_UDTA_META")
        s_repeat("MPG4_UDTA_META", min_reps=0, max_reps=1000, step=100)

    s_block_end("MPG4_UDTA")
    s_repeat("MPG4_UDTA", min_reps=0, max_reps=1000, step=100)

    # ----------------------------------------------------------------------------
    # offset: 0x7A9
    # ----------------------------------------------------------------------------

    if s_block_start("MPG4_TRAK_2"):
        s_size("MPG4_TRAK_2", endian=">", inclusive=False, length=4,
               fuzzable=True)                   # Box size
        s_dword(0x7472616B, endian=">")           # Box type (trak)

        # ------------------------------------------------------------------------
        # offset: 0x7B1
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_2_TKHD"):
            s_size("MPG4_TRAK_2_TKHD", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x746B6864, endian=">")       # Box type (tkhd)

            s_byte(0x00, endian=">")            # Version
            s_byte(0x00, endian=">")            # Flags (3 bytes) \
            s_byte(0x00, endian=">")            # Flags (3 bytes) |
            s_byte(0x0E, endian=">")            # Flags (3 bytes) /

            s_dword(0xD1D2AC97, endian=">")       # Creation date
            s_dword(0xD1D2AC97, endian=">")       # Modification date
            s_dword(0x02, endian=">")             # Track ID

            s_dword(0x00, endian=">")             # Reserved

            s_dword(0x01, endian=">")             # Duration
            s_dword(0x00, endian=">")             # Width
            s_dword(0x00, endian=">")             # Height

            s_binary("\x00\x00\x00\x00\x00\x00\x00\x00")

            s_word(0x01, endian=">")            # Layer
            s_word(0x00, endian=">")            # Alternate group
            s_word(0x00, endian=">")            # Volume
            s_word(0x00, endian=">")            # Reserved

            # Matrix structure START

            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x00010000, endian=">")
            s_dword(0x00, endian=">")

            # Matrix structure START

            s_dword(0x00, endian=">")
            s_dword(0x00, endian=">")
            s_dword(0x40000000, endian=">")

            # Matrix structure END

            s_dword(0x00, endian=">")             # Track width
            s_dword(0x00, endian=">")             # Track height

        s_block_end("MPG4_TRAK_2_TKHD")
        s_repeat("MPG4_TRAK_2_TKHD", min_reps=0, max_reps=1000, step=100)

        # ------------------------------------------------------------------------
        # offset: 0x80D
        # ------------------------------------------------------------------------

        if s_block_start("MPG4_TRAK_2_MDIA"):
            s_size("MPG4_TRAK_2_MDIA", endian=">", inclusive=False, length=4,
                   fuzzable=True)               # Box size
            s_dword(0x6D646961, endian=">")       # Box type (mdia)

            # --------------------------------------------------------------------
            # offset: 0x815
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_2_MDIA_MDHD"):
                s_size("MPG4_TRAK_2_MDIA_MDHD", endian=">", inclusive=False, length=4,
                       fuzzable=True)               # Box size
                s_dword(0x6D646864, endian=">")       # Box type (mdhd)

            s_byte(0x00, endian=">")            # Version
            s_byte(0x00, endian=">")            # Flags (3 bytes) \
            s_byte(0x00, endian=">")            # Flags (3 bytes) |
            s_byte(0x00, endian=">")            # Flags (3 bytes) /

            s_dword(0xD1D2AC97, endian=">")       # Creation date
            s_dword(0xD1D2AC97, endian=">")       # Modification date

            s_dword(0x03E8, endian=">")           # Time scale
            s_dword(0x01, endian=">")             # Duration
            s_dword(0x55C40000, endian=">")       # Language

            s_block_end("MPG4_TRAK_2_MDIA_MDHD")
            s_repeat("MPG4_TRAK_2_MDIA_MDHD", min_reps=0, max_reps=1000, step=100)

            # --------------------------------------------------------------------
            # offset: 0x835
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_2_MDIA_HDLR"):
                s_size("MPG4_TRAK_2_MDIA_HDLR", endian=">", inclusive=False, length=4,
                       fuzzable=True)               # Box size
                s_dword(0x68646C72, endian=">")       # Box type (hdlr)

            s_byte(0x00, endian=">")            # Version
            s_byte(0x00, endian=">")            # Flags (3 bytes) \
            s_byte(0x00, endian=">")            # Flags (3 bytes) |
            s_byte(0x00, endian=">")            # Flags (3 bytes) /

            s_dword(0x00, endian=">")             # ???

            s_string("text")

            s_string("\x00\x00\x00\x00\x00\x00\x00\x00" +\
                     "\x00\x00\x00\x00\x00")

            s_block_end("MPG4_TRAK_2_MDIA_HDLR")
            s_repeat("MPG4_TRAK_2_MDIA_HDLR", min_reps=0, max_reps=1000, step=100)

            # --------------------------------------------------------------------
            # offset: 0x856
            # --------------------------------------------------------------------

            if s_block_start("MPG4_TRAK_2_MDIA_MINF"):
                s_size("MPG4_TRAK_2_MDIA_MINF", endian=">", inclusive=False, length=4,
                       fuzzable=True)                           # Box size
                s_dword(0x6D696E66, endian=">")                   # Box type (minf)

                # ----------------------------------------------------------------
                # offset: 0x85E
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_2_MDIA_MINF_GMHD"):
                    s_size("MPG4_TRAK_2_MDIA_MINF_GMHD", endian=">", inclusive=False, length=4,
                           fuzzable=True)                           # Box size
                    s_dword(0x676D6864, endian=">")                   # Box type (gmhd)

                    # ------------------------------------------------------------
                    # offset: 0x866
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_GMHD_GMIN"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_GMHD_GMIN", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x676D696E, endian=">")               # Box type (gmin)

                        s_dword(0x00, endian=">")

                        s_word(0x40, endian=">")
                        s_word(0x8000, endian=">")
                        s_word(0x8000, endian=">")
                        s_word(0x8000, endian=">")

                        s_dword(0x00, endian=">")

                    s_block_end("MPG4_TRAK_2_MDIA_MINF_GMHD_GMIN")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_GMHD_GMIN", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x87E
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_GMHD_TEXT"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_GMHD_TEXT", endian=">", inclusive=False, length=4,
                               fuzzable=True)                       # Box size
                        s_dword(0x74657874, endian=">")               # Box type (text)

                        s_dword(0x00010000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x00010000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x00000000, endian=">")
                        s_dword(0x40000000, endian=">")

                    s_block_end("MPG4_TRAK_2_MDIA_MINF_GMHD_TEXT")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_GMHD_TEXT", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_TRAK_2_MDIA_MINF_GMHD")
                s_repeat("MPG4_TRAK_2_MDIA_MINF_GMHD", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x8AA
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_2_MDIA_MINF_DINF"):
                    s_size("MPG4_TRAK_2_MDIA_MINF_DINF", endian=">", inclusive=False, length=4,
                           fuzzable=True)                           # Box size
                    s_dword(0x64696E66, endian=">")                   # Box type (dinf)

                    # ------------------------------------------------------------
                    # offset: 0x8B2
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_DINF_DREF"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_DINF_DREF", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x64726566, endian=">")       # Box type (dref)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x01, endian=">")             # Entry count

                        # --------------------------------------------------------
                        # offset: 0x8C2
                        # --------------------------------------------------------
                        if s_block_start("MPG4_TRAK_2_MDIA_MINF_DINF_DREF_URL"):
                            s_size("MPG4_TRAK_2_MDIA_MINF_DINF_DREF_URL", endian=">", inclusive=False, length=4,
                                   fuzzable=True)               # Box size
                            s_string("url ")

                            s_byte(0x00, endian=">")            # Version
                            s_byte(0x00, endian=">")            # Flags (3 bytes) \
                            s_byte(0x00, endian=">")            # Flags (3 bytes) |
                            s_byte(0x01, endian=">")            # Flags (3 bytes) /

                        s_block_end("MPG4_TRAK_2_MDIA_MINF_DINF_DREF_URL")
                        s_repeat("MPG4_TRAK_2_MDIA_MINF_DINF_DREF_URL", min_reps=0, max_reps=1000, step=100)

                    s_block_end("MPG4_TRAK_2_MDIA_MINF_DINF_DREF")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_DINF_DREF", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_TRAK_2_MDIA_MINF_DINF")
                s_repeat("MPG4_TRAK_2_MDIA_MINF_DINF", min_reps=0, max_reps=1000, step=100)

                # ----------------------------------------------------------------
                # offset: 0x8CE
                # ----------------------------------------------------------------

                if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL"):
                    s_size("MPG4_TRAK_2_MDIA_MINF_STBL", endian=">", inclusive=False, length=4,
                           fuzzable=True)               # Box size
                    s_dword(0x7374626C, endian=">")       # Box type (stbl)

                    # ------------------------------------------------------------
                    # offset: 0x8D6
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STSD"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STSD", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x73747364, endian=">")       # Box type (stsd)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x01, endian=">")             # Num entries

                        if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STSD_TEXT"):
                            s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STSD_TEXT", endian=">", inclusive=False, length=4,
                                   fuzzable=True)               # Box size
                            s_dword(0x74657874, endian=">")       # Box type (text)

                            # This is probably not the correct structure
                            # but does not really matter.

                            s_binary("\x00\x00\x00\x00\x00\x00")
                            s_word(0x01, endian=">")
                            s_dword(0x01, endian=">")
                            s_dword(0x01, endian=">")

                            s_string("\x00\x00\x00\x00\x00\x00\x00\x00" +\
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" +\
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" +\
                                     "\x00\x00\x00\x00\x00\x00\x00\x00" +\
                                     "\x00\x00\x00")

                        s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STSD_TEXT")
                        s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STSD_TEXT", min_reps=0, max_reps=1000, step=100)

                    s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STSD")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STSD", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x921
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STTS"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STTS", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x73747473, endian=">")       # Box type (stts)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x01, endian=">")             # Num entries

                        s_dword(0x01, endian=">")             # Sample count
                        s_dword(0x01, endian=">")             # Sample delta
                    s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STTS")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STTS", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x939
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STSZ"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STSZ", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x7374737A, endian=">")       # Box type (stsz)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x17, endian=">")             # Sample size
                        s_dword(0x01, endian=">")             # Sample count
                    s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STSZ")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STSZ", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x94D
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STSC"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STSC", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x73747363, endian=">")       # Box type (stsc)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x01, endian=">")             # Num entries

                        s_dword(0x01, endian=">")             # First chunk
                        s_dword(0x01, endian=">")             # Samples per chunk
                        s_dword(0x01, endian=">")             # Samples description index
                    s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STSC")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STSC", min_reps=0, max_reps=1000, step=100)

                    # ------------------------------------------------------------
                    # offset: 0x969
                    # ------------------------------------------------------------

                    if s_block_start("MPG4_TRAK_2_MDIA_MINF_STBL_STCO"):
                        s_size("MPG4_TRAK_2_MDIA_MINF_STBL_STCO", endian=">", inclusive=False, length=4,
                               fuzzable=True)               # Box size
                        s_dword(0x7374636F, endian=">")       # Box type (stco)

                        s_byte(0x00, endian=">")            # Version
                        s_byte(0x00, endian=">")            # Flags (3 bytes) \
                        s_byte(0x00, endian=">")            # Flags (3 bytes) |
                        s_byte(0x00, endian=">")            # Flags (3 bytes) /

                        s_dword(0x01, endian=">")             # Num entries

                        s_dword(0x021D, endian=">")           # Chunk offset 
                    s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL_STCO")
                    s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL_STCO", min_reps=0, max_reps=1000, step=100)

                s_block_end("MPG4_TRAK_2_MDIA_MINF_STBL")
                s_repeat("MPG4_TRAK_2_MDIA_MINF_STBL", min_reps=0, max_reps=1000, step=100)

            s_block_end("MPG4_TRAK_2_MDIA_MINF")
            s_repeat("MPG4_TRAK_2_MDIA_MINF", min_reps=0, max_reps=1000, step=100)

        s_block_end("MPG4_TRAK_2_MDIA")
        s_repeat("MPG4_TRAK_2_MDIA", min_reps=0, max_reps=1000, step=100)

    s_block_end("MPG4_TRAK_2")
    s_repeat("MPG4_TRAK_2", min_reps=0, max_reps=1000, step=100)

s_block_end("MPG4_MOOV")
s_repeat("MPG4_MOOV", min_reps=0, max_reps=1000, step=100)

