#!/usr/bin/python
# ====================================================================================
# apt-get install python-mutagen
# ====================================================================================

# Mutagen has same issues with the save() function or, I just could not figure out
# how to do "save as" properly. As of this:
#   1. a backup copy of the Base MP3 File is created.
#   2. mutagen will update the Base MP3 File
#   3. this tool will copy the updated file to the destination
#   4. the Base MP3 File will be overwritten, with the original, backup one
#   5. repeat from 1)

# This tool ONLY works with MP3 files which has an APIC tag in the ID3 section.
# So, if you want to use your custom MP3 use Mp3tag for example to embed a default
# image. After, you can use this tool.

import os
import sys
import shutil
import argparse
from glob import glob
from mutagen.mp3 import MP3

# ------------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------------

def process(src_dir, dest_dir, base_file, image_type, ext):
    shutil.copy2(base_file + ".orig", base_file)
    print "Status:"
    print "  %-40s%s" % ("Source directory:", src_dir)
    print "  %-40s%s" % ("Destination directory:", dest_dir)
    print "  %-40s%s" % ("Base MP3:", base_file)
    print "  %-40s%s" % ("Image type:", image_type)
    print "  %-40s%s" % ("Image extension:", ext)

    files = [y for x in os.walk(src_dir) for y in glob(os.path.join(x[0], '*.' + ext))]
    counter = 0
    for image_file in files:
        print "  %-40s%s" % ("Image:", image_file)
        dd = dest_dir + "/" + str(counter / 1000) 
        df = dd + "/test." + str(counter) + ".mp3"
        print "  %-40s%s" % ("File destination:", df)

        if not os.path.exists(dd): 
            try:
                os.makedirs(dd)
            except Exception, ex:
                print "Could not create destination directory: %s" % str(ex)
                sys.exit(6)

        image_data = None
        with open(image_file, 'r') as f:
            image_data = f.read()
        if image_data == None:
            print "Could not read image data, exiting..."
            sys.exit(7)

        print "  %-40s%s" % ("Image size:", len(image_data))

        audio = MP3(base_file)
        picturetag = audio.tags['APIC:']
        picturetag.desc = "Mutation #%d" % counter
        picturetag.mime = image_type
        picturetag.data = image_data
        audio.tags['APIC:'] = picturetag
        audio.save()
        shutil.copy2(base_file, df)

        counter += 1

# ------------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------------

def validate_path(t_path, is_source = True):
    exists = os.path.isdir(t_path)
    if exists or is_source: return exists
    os.makedirs(t_path)
    exists = os.path.isdir(t_path)
    return exists

# ------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------

parser = argparse.ArgumentParser(description='Embed image (JPEG or PNG) into MP3 as cover image')
parser.add_argument('-sd', metavar='<path>', required = True,
                   help='Source directory containing the image files')
parser.add_argument('-dd', metavar='<path>', required = True,
                   help='Destination directory to store the MP3 files to')
parser.add_argument('-it', metavar='<type>', required = True,
                   help='Media type (jpeg/png)')
parser.add_argument('-bf', metavar='<path>', required = True,
                   help='MP3 file to use as base')

args = parser.parse_args()

if args.sd == None or not validate_path(args.sd):
    print "Source directory does not exist, exiting."
    sys.exit(1)

if args.dd == None:
    print "No destination directory specified, exiting."
    sys.exit(2)

if not validate_path(args.dd, False):
    print "Could not set up destination directory, exiting."
    sys.exit(3)

if not os.path.isfile(args.bf):
    print "Could not find base MP3 file, exiting."
    sys.exit(4)
if not os.path.isfile(args.bf + ".orig"):
    shutil.copy2(args.bf, args.bf + ".orig")

if args.it != "jpeg" and args.it != "png":
    print "Unsupported image type, exiting."
    sys.exit(5)

extension = ""
if args.it == "jpeg": extension = "jpg"
if args.it == "png": extension = "png"

process(args.sd, args.dd, args.bf, u"image/" + args.it, extension)

