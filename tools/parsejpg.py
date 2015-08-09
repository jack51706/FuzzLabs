#!/usr/bin/python
# ============================================================================
# Please note that some size values for SOS might have to be updated in the
# resulting sulley descriptor/grammar.
#
# Check the differences between the original and first generated file with:
# cmp -l <original> <generated> | gawk '{printf "%08X %02X %02X\n", $1, strtonum(0$2), strtonum(0$3)}'
# ============================================================================

import os
import re
import sys
import cgi
import struct
import binascii
from array import array
from lxml import etree

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

SECTIONS = [
    JPEG_SOI, 
    JPEG_EOI,
    JPEG_DQT,
    JPEG_DHT,
    JPEG_SOS,
    JPEG_COM,
    JPEG_APP0,
    JPEG_APP1,
    JPEG_SOF0,
    JPEG_SOF2
    ]

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_s_name(value):
    if value == JPEG_SOI: return "JPEG_SOI"
    if value == JPEG_EOI: return "JPEG_EOI"
    if value == JPEG_DQT: return "JPEG_DQT"
    if value == JPEG_DHT: return "JPEG_DHT"
    if value == JPEG_SOS: return "JPEG_SOS"
    if value == JPEG_COM: return "JPEG_COM"
    if value == JPEG_APP0: return "JPEG_APP0"
    if value == JPEG_APP1: return "JPEG_APP1"
    if value == JPEG_SOF0: return "JPEG_SOF0"
    if value == JPEG_SOF2: return "JPEG_SOF2"
    return "???"

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_xml_lines(data):
    lines = data.split("\x0A")
    for line in lines[:len(lines) - 1]:
        if len(line) != 0: print '        s_string("%s")' % line
        print '        s_static("\\x0A")'

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_size(f_data, bname, offset):
    if (bname == JPEG_SOI) or (bname == JPEG_EOI):
        return 0
    ss = offset + 2
    return struct.unpack(">H", f_data[ss:ss+2])[0]

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_e_offset(bname, s_offset, size):
    # outer: SOS
    if bname == JPEG_SOS: 
        return s_offset + 4 + size - 1
    return s_offset + 2 + size

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_section(data, base):
    m = re.search("\xFF[\xA0-\xFE]{1}", data)
    if not m: return None
    s_nbin = data[m.start():m.end()]
    if s_nbin not in SECTIONS: return None
    s_size = get_size(data, s_nbin, m.start())

    section = {
        "name": get_s_name(s_nbin),
        "bname": s_nbin,
        "s_offset": base + m.start(),
        "e_offset": base + get_e_offset(s_nbin, m.start(), s_size),
        "size": s_size
    }

    return section
    
# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_sections(data):
    sections = []
    next = 0
    s = get_section(data, next)
    if not s: return []
    sections.append(s)
    next = s["e_offset"]
    if not s: return sections

    while s:
        s = get_section(data[next:], next)
        if not s: return sections
        next = s["e_offset"]
        sections.append(s)

    return sections

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def print_section(s, IDENT):
    print
    print "%s# %s" % ((" " * (IDENT * 4)), ("-" * (78 - (IDENT * 4))))
    print "%s# %-10s\t%-10s\t%-7s\t%-8s\t%-10s" % (
            (" " * (IDENT * 4)),
            "Section",
            "Bin name",
            "Size",
            "Start offset",
            "End offset")
    print "%s# %-10s\t%-10s\t%-7s\t%-8s\t%-10s" % (
            (" " * (IDENT * 4)),
            s["name"],
            binascii.hexlify(s["bname"]),
            hex(s["size"]),
            hex(s["s_offset"]),
            hex(s["e_offset"]))
    print "%s# %s" % ((" " * (IDENT * 4)), ("-" * (78 - (IDENT * 4))))
    print

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def get_bytes(data):
    lines = []
    line = []
    a_data = array("B", data)
    h_data = map(hex, a_data)

    for h_byte in h_data:
        if len(line) == 8:
            lines.append(line)
            line = []
        t = h_byte.split("0x")[1]
        if len(t) == 1: t = "0" + t
        t = "\\x" + t
        line.append(t)

    lines.append(line)

    C=0
    for line in lines:
        if len(lines) == 1:
            print '        s_static("%s")' % "".join(line)
        elif C == 0:
            print '        s_static("%s" + \\' % "".join(line)
        elif C == len(lines) - 1:
            print "                 \"" + "".join(line) + "\")"
        else:
            print "                 \"" + "".join(line) + "\" + \\"
        C += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_SOI():
    print 's_static(JPEG_SOI)'

def handle_EOI():
    print 's_string(JPEG_EOI)'

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_DQT(s, data, counters):
    block_name = "DQT_" + str(counters["DQT"])
    fuzzable = "True"
    if counters["DQT"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_DQT)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    get_bytes(data[s["s_offset"] + 4:s["e_offset"]])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["DQT"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_DHT(s, data, counters):
    block_name = "DHT_" + str(counters["DHT"])
    fuzzable = "True"
    if counters["DHT"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_DHT)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    get_bytes(data[s["s_offset"] + 4:s["e_offset"]])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["DHT"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_COM(s, data, counters):
    block_name = "COM_" + str(counters["COM"])
    fuzzable = "True"
    if counters["COM"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_COM)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    print '        s_string("%s")' % data[s["s_offset"] + 4:s["e_offset"]]
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["COM"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_SOS(s, data, counters):
    block_name = "SOS_" + str(counters["SOS"])
    fuzzable = "True"
    if counters["SOS"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_SOS)'
    print '    s_size("I_%s", endian=">", inclusive=False, math=lambda x: x+1, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    get_bytes(data[s["s_offset"] + 4:s["e_offset"]])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["SOS"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_SOF0(s, data, counters):
    block_name = "SOF0_" + str(counters["SOF0"])
    fuzzable = "True"
    if counters["SOF0"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_SOF0)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    get_bytes(data[s["s_offset"] + 4:s["e_offset"]])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["SOF0"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_SOF2(s, data, counters):
    block_name = "SOF2_" + str(counters["SOF2"])
    fuzzable = "True"
    if counters["SOF2"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_SOF2)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    get_bytes(data[s["s_offset"] + 4:s["e_offset"]])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["SOF2"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_APP0(s, data, counters):
    block_name = "APP0_" + str(counters["APP0"])
    fuzzable = "True"
    if counters["APP0"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_APP0)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name
    print '        s_string("JFIF")'
    print '        s_string("\\x00")'
    d_start = s["s_offset"] + 9
    print '        s_byte(%s)\t\t\t\t# Major version' % hex(struct.unpack("B", data[d_start:d_start + 1])[0])
    print '        s_byte(%s)\t\t\t\t# Minor version' % hex(struct.unpack("B", data[d_start + 1:d_start + 2])[0])
    print '        s_byte(%s)\t\t\t\t# Density unit' % hex(struct.unpack("B", data[d_start + 2:d_start + 3])[0])
    d_start = s["s_offset"] + 12
    print '        s_word(%s, endian=">")\t\t# Xdensity' % hex(struct.unpack(">H", data[d_start:d_start + 2])[0])
    print '        s_word(%s, endian=">")\t\t# Ydensity' % hex(struct.unpack(">H", data[d_start + 2:d_start + 4])[0])
    d_start = s["s_offset"] + 16
    print '        s_byte(%s)\t\t\t\t# Xthumbnail' % hex(struct.unpack("B", data[d_start:d_start + 1])[0])
    print '        s_byte(%s)\t\t\t\t# Ythumbnail' % hex(struct.unpack("B", data[d_start + 1:d_start + 2])[0])
    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["APP0"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

def handle_APP1(s, data, counters):
    block_name = "APP1_" + str(counters["APP1"])
    fuzzable = "True"
    if counters["APP1"] > 0: fuzzable = "False"

    print 'if s_block_start("O_%s"):' % block_name
    print '    s_static(JPEG_APP1)'
    print '    s_size("I_%s", endian=">", inclusive=True, length=2, fuzzable=%s)' % (block_name, fuzzable)
    print '    if s_block_start("I_%s"):' % block_name

    data_start = s["s_offset"] + 4
    data = data[data_start:s["e_offset"]]

    print '        # IMAGE DATA'
    get_bytes(data)

    print '    s_block_end("I_%s")' % block_name
    print 's_block_end("O_%s")' % block_name

    if fuzzable == "True":
        print 's_repeat("O_%s", min_reps=0, max_reps=100, step=10)' % block_name

    counters["APP1"] += 1

# ----------------------------------------------------------------------------
#
# ----------------------------------------------------------------------------

try:
    f = open(sys.argv[1], 'rb')
    data = f.read()
except Exception, ex:
    print "[e] failed to open file"
    sys.exit(1)

sections = get_sections(data)
counters = {
    "SOI": 0,
    "EOI": 0,
    "DQT": 0,
    "DHT": 0,
    "SOS": 0,
    "COM": 0,
    "SOF0": 0,
    "SOF2": 0,
    "APP0": 0,
    "APP1": 0
}

for s in sections:
    print_section(s, 0)

    if s["bname"] == JPEG_SOI: handle_SOI()
    if s["bname"] == JPEG_EOI: handle_EOI()
    if s["bname"] == JPEG_DQT: handle_DQT(s, data, counters)
    if s["bname"] == JPEG_DHT: handle_DHT(s, data, counters)
    if s["bname"] == JPEG_SOS: handle_SOS(s, data, counters)
    if s["bname"] == JPEG_COM: handle_COM(s, data, counters)
    if s["bname"] == JPEG_SOF0: handle_SOF0(s, data, counters)
    if s["bname"] == JPEG_SOF2: handle_SOF2(s, data, counters)
    if s["bname"] == JPEG_APP0: handle_APP0(s, data, counters)
    if s["bname"] == JPEG_APP1: handle_APP1(s, data, counters)

