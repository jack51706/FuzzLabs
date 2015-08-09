#!/usr/bin/python
# ===================================================================
# Basic XML to Sulley converter
# ===================================================================

import re
import cgi
import sys
from lxml import etree

# ===================================================================
#
# ===================================================================

def process_attributes(attrs):
    fs = ""
    for key, value in attrs.iteritems():
        fs += "s_static(\" \")\n"
        fs += "s_static(\"" + key.encode('ascii') + "\")\n"
        fs += "s_static(\"=\\\"\")\n"
        fs += "s_string(\"" + value.encode('ascii') + "\")\n"
        fs += "s_static(\"\\\"\")\n"
    return fs

# ===================================================================
#
# ===================================================================

def process_tag(elem):
    fs = ""

    if elem.tag: fs += "s_static(\"<" + str(elem.tag) + "\")\n"
    if elem.attrib: fs += process_attributes(elem.attrib)
    fs += "s_static(\">\")\n"

    return fs

# ===================================================================
#
# ===================================================================

def process_text(text):
    fs = ""
    text = text.replace("\\", "\\\\")
    text = text.split("\n")
    if len(text) <= 1:
        data = cgi.escape(text[0]).encode('ascii', 'xmlcharrefreplace')
        fs += "s_string(\"" + data.strip() + "\")\n"
    else:
        for line in text:
            data = cgi.escape(line).encode('ascii', 'xmlcharrefreplace')
            fs += "s_string(\"" + data.strip() + "\")\n"
            fs += "s_static(\"\\n\")\n"
    return fs

# ===================================================================
#
# ===================================================================

def process_childs(elem):
    fs = process_tag(elem)

    if elem.text and len(elem.text) > 0 and elem.text.strip() != "": 
        fs += process_text(elem.text.strip())
    if len(elem) > 0:
        for child in elem:
            fs += process_childs(child)

    if elem.tag: fs += "s_static(\"</" + str(elem.tag) + ">\")\n"
    return fs

# ===================================================================
#
# ===================================================================

FILE = sys.argv[1]
N_FILE = FILE[:FILE.rfind(".")] + ".py"

i_file = open(FILE, 'r')
lines = []

with open(FILE) as f:
    lines = f.readlines()

o_file = open(N_FILE, 'wb')

parser = etree.XMLParser(resolve_entities=False, ns_clean=True)
xre = etree.fromstring("".join(lines), parser)

result = process_childs(xre)
o_file.write(result)
o_file.close()

