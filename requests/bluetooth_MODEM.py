# =============================================================================
# Basic AT Modem Fuzzer
# This file is part of the FuzzLabs Fuzzing Framework
# Author: Zsolt Imre
# =============================================================================

from sulley import *

s_initialize("MODEM")
s_static("AT")
# will not touch S3, S4, S5 commands
s_group("commands", values=["A/",	# Repeat last command
                            #
                            # ITU-T V.25ter generic DCE control commands
                            #
                            "Z",        # Reset to default configuration
                            "&F",       # Set to factory-defined configuration
                            "I",        # Requests identification information
                            "+GMI",     # Request manufacturer ident
                            "+GMM",     # Request model ident
                            "+GMR",     # Request firmware revision ident
                            "+GSN",     # Request product serial number ident
                            "+GCAP",    # Request complete capabilities list
                            "+WS46",    # Select wireless network
                            #
                            # DTE-TA/DCE interface commands
                            #
                            "E",	# Command echo
                            "Q",	# Result code supression
                            "V",	# DCE response format
                            "X",	# Result code selection and call progress monitoring control
                            "&C",	# Circuit 109 DCE RLSD (DCD) behavior
                            "&D",	# Circuit 108 DTE DTR behavior
                            "+IPR",     # Fixed DTE rate (data rate at which DCE will accept commands)
                            "+ICF",     # DTE-DCE character framing
                            "+IFC",     # DTE-DCE local flow control
                            #
                            # WCDMA general commands
                            #
                            "+CGMI",	# Request manufacturer identification
                            "+CGMM",	# Request model identification
                            "+CGMR",	# Request firmware revision identification
                            "+CGSN",	# Request product serial number identification
                            "+CSCS",	# Select TE character set
                            "+CIMI",	# Request international mobile subscriber identity
                            #
                            # WCDMA call control commands
                            #
                            "+CSTA",	# Select type of address
                            "+CMOD",	# Call mode
                            "+CHUP",	# Hang up voice call
                            "+CBST",	# Select circuit-switched bearer service
                            "+CRLP",	# Alters the RLP parameters used
                            "+CR",	# Service reporting control
                            "+CEER",	# Extended error report
                            "+CRC",	# Cellular result codes
                            "+CHSN",	# HSCSD non-transparent call configuration
                            "+CV120",	# V.120 rate adaption protocol
                            #
                            # ITU-T V.25ter call control commands
                            #
                            "D",	# Dial circuit-switched data call
                            "T",	# Select tone dialing
                            "P",	# Select pulse dialing
                            "H",	# Hook control command to terminate call in progress
                            "O",	# Returns to Online Data state from Online Command state
                            "S6",	# Pause before blind dialing
                            "S7",	# Number of sec to establish end-to-end data conn
                            "S8",	# Number of sec to pause when "," is encountered in dial str
                            "S10",	# Number of tenths of a second from carrier loss to disconn
                            #
                            # ITU-T V.25ter data compression commands
                            #
                            "+DR",	# Reports use of V.32bis using intermediate result code
                            "+DS",	# Controls V.42bis data compression
                            #
                            # Network service related commands
                            #
                            "+CNUM",	# Subscriber number
                            "+CREG",	# Network registration
                            "+CLCK",	# Lock, unlock or interrogate an ME or a network facility
                            "+CPWD",	# Sets new password for a facility lock function
                            "+COLP",	# Connected line identification presentation
                            "+CDIP",	# Called line identification presentation
                            "+CCUG",	# Controls closed user group supplementary service
                            "+CUSD",	# Controls unstructured supplementary service data
                            "+CSSN",	# Supplementary service notifications
                            "+CPOL",	# Preferred operator list
                            "+CHLD",	# Call-related supplementary services
                            "+COPS",	# Operator selection
                            "+CAOC",	# Advice of charge
                            "+CLIP",	# Calling line identification presentation
                            "+CLCC",	# List current calls
                            "+CPLS",	# Selection of preferred PLMN list
                            "+CTFR",	# Call deflection supplementary service
                            "+COPN",	# Read operator names
                            #
                            # Mobile equipment commands
                            #
                            "+CPAS",	# Reports phone activity status
                            "+CFUN",	# Set phone functionality
                            "+CPIN",	# Enters PIN
                            "+CSQ",	# Reports signal quality
                            "+CPBS",	# Select phonebook memory storage
                            "+CPBR",	# Reads phonebook entries
                            "+CPBF",	# Finds phonebook entries
                            "+CPBW",	# Writes phonebook entries
                            "+CTZR",	# Time zone reporting
                            "+CSIM",	# Generic SIM access
                            "+CRSM",	# Restricted SIM access
                            "+CACM",	# Accumulated call meter
                            "+CAMM",	# Accumulated call meter maximum
                            "+CPUC",	# Price per unit and currency table
                            "+CLAC",	# Lists all available AT commands
                            "+CTZU",	# Automatic timezone update
                            "+CMEE",	# Reports mobile equipment error
                            #
                            # WCDMA packet domain commands
                            #
                            "+CGDCONT",	# Sets PDP context parameter values for a PDP CI by CI
                            "+CGDSCONT",# Defines secondary PDP context
                            "+CGTFT",	# Traffic flow template
                            "+CGQREQ",	# Sets the QoS profile
                            "+CGQMIN",	# Sets minimum acceptable profile against negotiated profile
                            "+CGEQREQ",	# Sets the WCDMA QoS profile
                            "+CGEQMIN",	# Sets the WCDMA QoS profile
                            "+CGATT",	# Attaches or detashes from the packet domain service
                            "+CGACT",	# Activates or deactivates the specified PDP context(s)
                            "+CGCMOD",	# PDP context modify
                            "+CGDATA",	# Enters Data state
                            "+CGPADDR",	# Shows PDP address
                            "+CGCLASS",	# Sets the GPRS mobile class
                            "+CGEREP",	# Controls sending of unsolicited result codes
                            "+CGREQ",	# Controls the presentation of unsolicited gPRS network...
                            "+D",	# Dial
                            "+CGSMS",	# Service preference that will be used to send SMS
                            #
                            # SMS commands
                            #
                            "+CSMS",	# Selects message service
                            "+CPMS",	# Preferred message store
                            "+CMGF",	# Message format
                            "+CSCA",	# Service center address
                            "+CSMP",	# Sets Text mode parameters
                            "+CSDH",	# Shows Text mode parameters
                            "+CSCB",	# Selects cell broadcast message types
                            "+CNMI",	# New message indications to TE
                            "+CMGL",	# Lists message
                            "+CMGR",	# Reads message
                            "+CNMA",	# Acknowledges new message
                            "+CMGS",	# Sends message
                            "+CMGW",	# Writes to message memory
                            "+CMGD",	# Deletes message
                            "+CMSS",	# Sends message from store
                            "+CMGC",	# Sends command
                            "+CMMS"	# More messages to send
                           ])

# Many commands do not accept parameters, we will fuzz them anyway

if s_block_start("CMD_FRMT_E", dep="commands", dep_value="E"):
    s_string("0")
s_block_end("CMD_FRMT_E")

if s_block_start("CMD_FRMT_Q", dep="commands", dep_value="Q"):
    s_string("0")
s_block_end("CMD_FRMT_Q")

if s_block_start("CMD_FRMT_V", dep="commands", dep_value="V"):
    s_string("0")
s_block_end("CMD_FRMT_V")

if s_block_start("CMD_FRMT_X", dep="commands", dep_value="X"):
    s_string("0")
s_block_end("CMD_FRMT_X")

if s_block_start("CMD_FRMT_I", dep="commands", dep_value="I"):
    s_string("0")
s_block_end("CMD_FRMT_I")

if s_block_start("CMD_FRMT_Z", dep="commands", dep_value="Z"):
    s_string("0")
s_block_end("CMD_FRMT_Z")

if s_block_start("CMD_FRMT_&C", dep="commands", dep_value="&C"):
    s_string("0")
s_block_end("CMD_FRMT_&C")

if s_block_start("CMD_FRMT_&D", dep="commands", dep_value="&D"):
    s_string("0")
s_block_end("CMD_FRMT_&D")

if s_block_start("CMD_FRMT_&F", dep="commands", dep_value="&F"):
    s_string("0")
s_block_end("CMD_FRMT_&F")

if s_block_start("CMD_FRMT_+EB", dep="commands", dep_value="+EB"):
    s_string("0")
s_block_end("CMD_FRMT_+EB")

if s_block_start("CMD_FRMT_+EFCS", dep="commands", dep_value="+EFCS"):
    s_string("0")
s_block_end("CMD_FRMT_+EFCS")

if s_block_start("CMD_FRMT_+ER", dep="commands", dep_value="+ER"):
    s_string("0")
s_block_end("CMD_FRMT_+ER")

if s_block_start("CMD_FRMT_+ES", dep="commands", dep_value="+ES"):
    s_string("0")
s_block_end("CMD_FRMT_+ES")

if s_block_start("CMD_FRMT_+ESR", dep="commands", dep_value="+ESR"):
    s_string("0")
s_block_end("CMD_FRMT_+ESR")

if s_block_start("CMD_FRMT_+GMI", dep="commands", dep_value="+GMI"):
    s_string("0")
s_block_end("CMD_FRMT_+GMI")

if s_block_start("CMD_FRMT_+GOI", dep="commands", dep_value="+GOI"):
    s_string("0")
s_block_end("CMD_FRMT_+GOI")

if s_block_start("CMD_FRMT_+ICF", dep="commands", dep_value="+ICF"):
    s_static("=")
    s_string("0")
    if s_block_start("RB-1"):
        s_static(",")
        s_string("0")
    s_block_end("RB-1")
    s_repeat("RB-1", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+ICF")

if s_block_start("CMD_FRMT_+IFC", dep="commands", dep_value="+IFC"):
    s_static("=")
    s_string("0")
    if s_block_start("RB-2"):
        s_static(",")
        s_string("0")
    s_block_end("RB-2")
    s_repeat("RB-2", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+IFC")

if s_block_start("CMD_FRMT_+ILRR", dep="commands", dep_value="+ILRR"):
    s_string("0")
s_block_end("CMD_FRMT_+ILRR")

if s_block_start("CMD_FRMT_+IPR", dep="commands", dep_value="+IPR"):
    s_static("=")
    s_string("115200")
s_block_end("CMD_FRMT_+IPR")

if s_block_start("CMD_FRMT_+MA", dep="commands", dep_value="+MA"):
    s_string("0")
s_block_end("CMD_FRMT_+MA")

if s_block_start("CMD_FRMT_+MR", dep="commands", dep_value="+MR"):
    s_string("0")
s_block_end("CMD_FRMT_+MR")

if s_block_start("CMD_FRMT_+MS", dep="commands", dep_value="+DR"):
    s_string("0")
s_block_end("CMD_FRMT_+MS")

if s_block_start("CMD_FRMT_+CGMI", dep="commands", dep_value="+CGMI"):
    s_string("0")
s_block_end("CMD_FRMT_+CGMI")

if s_block_start("CMD_FRMT_+CGMM", dep="commands", dep_value="+CGMM"):
    s_string("0")
s_block_end("CMD_FRMT_+CGMM")

if s_block_start("CMD_FRMT_+CGMR", dep="commands", dep_value="+CGMR"):
    s_string("0")
s_block_end("CMD_FRMT_+CGMR")

if s_block_start("CMD_FRMT_+CGSN", dep="commands", dep_value="+CGSN"):
    s_string("0")
s_block_end("CMD_FRMT_+CGSN")

if s_block_start("CMD_FRMT_+CSCS", dep="commands", dep_value="+CSCS"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+CSCS")

if s_block_start("CMD_FRMT_+CIGMI", dep="commands", dep_value="+CIMI"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+CIMI")

if s_block_start("CMD_FRMT_+GMM", dep="commands", dep_value="+GMM"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+GMM")

if s_block_start("CMD_FRMT_+GMR", dep="commands", dep_value="+GMR"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+GMR")

if s_block_start("CMD_FRMT_+GSN", dep="commands", dep_value="+GSN"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+GSN")

if s_block_start("CMD_FRMT_+GCAP", dep="commands", dep_value="+GCAP"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+GCAP")

if s_block_start("CMD_FRMT_+WS46", dep="commands", dep_value="+WS46"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+WS46")

if s_block_start("CMD_FRMT_+CSTA", dep="commands", dep_value="+CSTA"):
    s_string("0")
s_block_end("CMD_FRMT_+CSTA")

if s_block_start("CMD_FRMT_+CMOD", dep="commands", dep_value="+CMOD"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+CMOD")

if s_block_start("CMD_FRMT_+CHUP", dep="commands", dep_value="+CHUP"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+CHUP")

if s_block_start("CMD_FRMT_+CBST", dep="commands", dep_value="+CBST"):
    s_static("=")
    s_string("56000")
    s_static(",")
    s_string("0")
    if s_block_start("RB-3"):
        s_static(",")
        s_string("0")
    s_block_end("RB-3")
    s_repeat("RB-3", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CBST")

if s_block_start("CMD_FRMT_+CRLP", dep="commands", dep_value="+CRLP"):
    s_static("=")
    s_string("56000")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    if s_block_start("RB-4"):
        s_static(",")
        s_string("0")
    s_block_end("RB-4")
    s_repeat("RB-4", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CRLP")

if s_block_start("CMD_FRMT_+CR", dep="commands", dep_value="+CR"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CR")

if s_block_start("CMD_FRMT_+CEER", dep="commands", dep_value="+CEER"):
    s_string("0")
s_block_end("CMD_FRMT_+CEER")

if s_block_start("CMD_FRMT_+CRC", dep="commands", dep_value="+CRC"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CRC")

if s_block_start("CMD_FRMT_+CHSN", dep="commands", dep_value="+CHSN"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    if s_block_start("RB-5"):
        s_static(",")
        s_string("0")
    s_block_end("RB-5")
    s_repeat("RB-5", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CHSN")

if s_block_start("CMD_FRMT_+CV120", dep="commands", dep_value="+CV120"):
    s_string("0")
s_block_end("CMD_FRMT_+CV120")

if s_block_start("CMD_FRMT_D", dep="commands", dep_value="D"):
    s_static(" ")
    s_string("9")
    s_static(" ")
    s_string("W")
    s_static(" ")
    s_string("1")
    s_static(" ")
    s_string("45434560")
s_block_end("CMD_FRMT_D")

if s_block_start("CMD_FRMT_T", dep="commands", dep_value="T"):
    s_string("0")
s_block_end("CMD_FRMT_T")

if s_block_start("CMD_FRMT_P", dep="commands", dep_value="P"):
    s_string("0")
s_block_end("CMD_FRMT_P")

if s_block_start("CMD_FRMT_H", dep="commands", dep_value="H"):
    s_string("0")
s_block_end("CMD_FRMT_H")

if s_block_start("CMD_FRMT_O", dep="commands", dep_value="O"):
    s_string("0")
s_block_end("CMD_FRMT_O")

if s_block_start("CMD_FRMT_+DR", dep="commands", dep_value="+DR"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+DR")

if s_block_start("CMD_FRMT_+DS", dep="commands", dep_value="+DS"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("512")
    if s_block_start("RB-6"):
        s_static(",")
        s_string("6")
    s_block_end("RB-6")
    s_repeat("RB-6", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+DS")

if s_block_start("CMD_FRMT_+CNUM", dep="commands", dep_value="+CNUM"):
    s_string("0")
s_block_end("CMD_FRMT_+CNUM")

if s_block_start("CMD_FRMT_+CREG", dep="commands", dep_value="+CREG"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CREG")

if s_block_start("CMD_FRMT_+CLCK", dep="commands", dep_value="+CLCK"):
    s_static("=")
    s_string("AB")
    s_group("clck_values", values=["AB", "AC", "AG", "AI", "AO", "IR", "OI", 
                                   "OX", "SC", "FD", "PN", "PU", "PP", "PC", "PF",
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
    s_static(",")
    s_string("0")
    s_static(",\"")
    s_string("password")
    s_static("\",")
    s_string("1")
s_block_end("CMD_FRMT_+CLCK")

if s_block_start("CMD_FRMT_+CPWD", dep="commands", dep_value="+CPWD"):
    s_static("=")
    s_string("AB")
    s_group("cpwd_values", values=["AB", "AC", "AG", "AI", "AO", "IR", "OI", 
                                   "OX", "SC", "FD", "PN", "PU", "PP", "PC", "PF",
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
    s_static(",\"")
    s_string("oldpassword")
    s_static("\",\"")
    s_string("newpassword")
    s_static("\"")
s_block_end("CMD_FRMT_+CPWD")

if s_block_start("CMD_FRMT_+COLP", dep="commands", dep_value="+COLP"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+COLP")

if s_block_start("CMD_FRMT_+CCUG", dep="commands", dep_value="+CCUG"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
s_block_end("CMD_FRMT_+CCUG")

if s_block_start("CMD_FRMT_+CUSD", dep="commands", dep_value="+CUSD"):
    s_static("=")
    s_string("0")
    s_static(",\"")
    s_string("0")
    s_static("\",")
    s_string("0")
s_block_end("CMD_FRMT_+CUSD")

if s_block_start("CMD_FRMT_+CSSN", dep="commands", dep_value="+CSSN"):
    s_static("=")
    s_string("0")
    if s_block_start("RB-7"):
        s_static(",")
        s_string("0")
    s_block_end("RB-7")
    s_repeat("RB-7", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CSSN")

if s_block_start("CMD_FRMT_+CPOL", dep="commands", dep_value="+CPOL"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    if s_block_start("RB-8"):
        s_static(",")
        s_string("0")
    s_block_end("RB-8")
    s_repeat("RB-8", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CPOL")

if s_block_start("CMD_FRMT_+CHLD", dep="commands", dep_value="+CHLD"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CHLD")

if s_block_start("CMD_FRMT_+COPS", dep="commands", dep_value="+COPS"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("2")
    if s_block_start("RB-9"):
        s_static(",")
        s_string("0")
    s_block_end("RB-9")
    s_repeat("RB-9", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+COPS")

if s_block_start("CMD_FRMT_+CAOC", dep="commands", dep_value="+CAOC"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CAOC")

if s_block_start("CMD_FRMT_+CLIP", dep="commands", dep_value="+CLIP"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CLIP")

if s_block_start("CMD_FRMT_+CLCC", dep="commands", dep_value="+CLCC"):
    s_string("=0")
s_block_end("CMD_FRMT_+CLCC")

if s_block_start("CMD_FRMT_+CPLS", dep="commands", dep_value="+CPLS"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CPLS")

if s_block_start("CMD_FRMT_+CTFR", dep="commands", dep_value="+CTFR"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    if s_block_start("RB-10"):
        s_static(",")
        s_string("0")
    s_block_end("RB-10")
    s_repeat("RB-10", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CTFR")

if s_block_start("CMD_FRMT_+COPN", dep="commands", dep_value="+COPN"):
    s_string("=0")
s_block_end("CMD_FRMT_+COPN")

if s_block_start("CMD_FRMT_+CPAS", dep="commands", dep_value="+CPAS"):
    s_string("=0")
s_block_end("CMD_FRMT_+CPAS")

if s_block_start("CMD_FRMT_+CFUN", dep="commands", dep_value="+CFUN"):
    s_static("=")
    s_string("0")
    if s_block_start("RB-11"):
        s_static(",")
        s_string("0")
    s_block_end("RB-11")
    s_repeat("RB-11", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CFUN")

if s_block_start("CMD_FRMT_+CPIN", dep="commands", dep_value="+CPIN"):
    s_static("=")
    s_string("5656")
    if s_block_start("RB-12"):
        s_static(",")
        s_string("6565")
    s_block_end("RB-12")
    s_repeat("RB-12", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CPIN")

if s_block_start("CMD_FRMT_+CSQ", dep="commands", dep_value="+CSQ"):
    s_string("=0")
s_block_end("CMD_FRMT_+CSQ")

if s_block_start("CMD_FRMT_+CPBS", dep="commands", dep_value="+CPBS"):
    s_static("=")
    s_group("cpbs_storage", values=["SM", "LD", "DC", "FD", 
                                    "MC", "ME", "RC", "EN", "ON",
                                    "AAAAAAAAAAAAAAAAAAAAAAAAAA"])
    s_static(",\"")
    s_string("password")
    s_static("\"")
s_block_end("CMD_FRMT_+CPBS")

if s_block_start("CMD_FRMT_+CPBR", dep="commands", dep_value="+CPBR"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
s_block_end("CMD_FRMT_+CPBR")

if s_block_start("CMD_FRMT_+CPBF", dep="commands", dep_value="+CPBF"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CPBF")

if s_block_start("CMD_FRMT_+CPBW", dep="commands", dep_value="+CPBW"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",\"")
    s_string("text")
    s_static("\"")
s_block_end("CMD_FRMT_+CPBW")

if s_block_start("CMD_FRMT_+CTZR", dep="commands", dep_value="+CTZR"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CTZR")

if s_block_start("CMD_FRMT_+CSIM", dep="commands", dep_value="+CSIM"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("command")
s_block_end("CMD_FRMT_+CSIM")

if s_block_start("CMD_FRMT_+CRSM", dep="commands", dep_value="+CRSM"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
s_block_end("CMD_FRMT_+CRSM")

if s_block_start("CMD_FRMT_+CACM", dep="commands", dep_value="+CACM"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CACM")

if s_block_start("CMD_FRMT_+CAMM", dep="commands", dep_value="+CAMM"):
    s_static("=")
    s_string("1")
    s_static(",\"")
    s_string("password")
    s_static("\"")
s_block_end("CMD_FRMT_+CAMM")

if s_block_start("CMD_FRMT_+CPUC", dep="commands", dep_value="+CPUC"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",\"")
    s_string("password")
    s_static("\"")
s_block_end("CMD_FRMT_+CPUC")

if s_block_start("CMD_FRMT_+CLAC", dep="commands", dep_value="+CLAC"):
    s_string("=")
    s_string("0")
s_block_end("CMD_FRMT_+CLAC")

if s_block_start("CMD_FRMT_+CTZU", dep="commands", dep_value="+CTZU"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CTZU")

if s_block_start("CMD_FRMT_+CMEE", dep="commands", dep_value="+CMEE"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CMEE")

if s_block_start("CMD_FRMT_+CGDCONT", dep="commands", dep_value="+CGDCONT"):
    s_static("=")
    s_string("0")
    s_static(",")
    s_group("cgdcont_pdp", values=["IP", "PDP-IP", "PPP", "PDP-PPP",
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
s_block_end("CMD_FRMT_+CGDCONT")

if s_block_start("CMD_FRMT_+CGDSCONT", dep="commands", dep_value="+CGDSCONT"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("0")
    s_static(",")
    s_string("0")
s_block_end("CMD_FRMT_+CGDSCONT")

if s_block_start("CMD_FRMT_+CGTFT", dep="commands", dep_value="+CGTFT"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("0")
    s_static(",\"")
    s_string("8.8")
    s_static(".")
    s_string("8.8")
    s_static(".")
    s_string("255.255.255.255")
    s_static("\",")
    s_string("1")
    s_static(",\"")
    s_string("0.0")
    s_static(".")
    s_string("65535.65535")
    s_static("\",\"")
    s_string("0.0")
    s_static(".")
    s_string("65535")
    s_static(".")
    s_string("65535")
    s_static("\",")
    s_string("0")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CGTFT")

if s_block_start("CMD_FRMT_+CGQREQ", dep="commands", dep_value="+CGQREQ"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CGQREQ")

if s_block_start("CMD_FRMT_+CGQMIN", dep="commands", dep_value="+CGQMIN"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CGQMIN")

if s_block_start("CMD_FRMT_+CGEQREQ", dep="commands", dep_value="+CGEQREQ"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    if s_block_start("RB-13"):
        s_static(",")
        s_string("1")
    s_block_end("RB-13")
    s_repeat("RB-13", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGEQREQ")

if s_block_start("CMD_FRMT_+CGEQMIN", dep="commands", dep_value="+CGEQMIN"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    if s_block_start("RB-14"):
        s_static(",")
        s_string("1")
    s_block_end("RB-14")
    s_repeat("RB-14", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGEQMIN")

if s_block_start("CMD_FRMT_+CGATT", dep="commands", dep_value="+CGATT"):
    s_static("=")
    s_string("0")
s_block_end("CMD_FRMT_+CGATT")

if s_block_start("CMD_FRMT_+CGACT", dep="commands", dep_value="+CGACT"):
    s_static("=")
    s_string("0")
    if s_block_start("RB-15"):
        s_static(",")
        s_string("1")
    s_block_end("RB-15")
    s_repeat("RB-15", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGACT")

if s_block_start("CMD_FRMT_+CGCMOD", dep="commands", dep_value="+CGCMOD"):
    s_static("=")
    s_string("1")
    if s_block_start("RB-16"):
        s_static(",")
        s_string("1")
    s_block_end("RB-16")
    s_repeat("RB-16", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGCMOD")

if s_block_start("CMD_FRMT_+CGDATA", dep="commands", dep_value="+CGDATA"):
    s_static("=")
    s_string("1")
    if s_block_start("RB-17"):
        s_static(",")
        s_string("1")
    s_block_end("RB-17")
    s_repeat("RB-17", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGDATA")

if s_block_start("CMD_FRMT_+CGPADDR", dep="commands", dep_value="+CGPADDR"):
    s_static("=")
    s_string("1")
    if s_block_start("RB-18"):
        s_static(",")
        s_string("1")
    s_block_end("RB-18")
    s_repeat("RB-18", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGPADDR")

if s_block_start("CMD_FRMT_+CGCLASS", dep="commands", dep_value="+CGCLASS"):
    s_static("=")
    s_string("A")
s_block_end("CMD_FRMT_+CGCLASS")

if s_block_start("CMD_FRMT_+CGEREP", dep="commands", dep_value="+CGEREP"):
    s_static("=")
    s_string("1")
    if s_block_start("RB-19"):
        s_static(",")
        s_string("1")
    s_block_end("RB-19")
    s_repeat("RB-19", min_reps=0, max_reps=10000, step=100)
s_block_end("CMD_FRMT_+CGEREP")

if s_block_start("CMD_FRMT_+CGSMS", dep="commands", dep_value="+CGSMS"):
    s_static("=")
    s_string("2")
s_block_end("CMD_FRMT_+CGSMS")

if s_block_start("CMD_FRMT_+CSMS", dep="commands", dep_value="+CSMS"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CSMS")

if s_block_start("CMD_FRMT_+CPMS", dep="commands", dep_value="+CPMS"):
    s_static("=")
    s_string("SM")
    s_static(",")
    s_string("ME")
    s_static(",")
    s_string("SR")
s_block_end("CMD_FRMT_+CPMS")

if s_block_start("CMD_FRMT_+CMGF", dep="commands", dep_value="+CMGF"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CMGF")

if s_block_start("CMD_FRMT_+CSCA", dep="commands", dep_value="+CSCA"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CSCA")

if s_block_start("CMD_FRMT_+CSMP", dep="commands", dep_value="+CSMP"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CSMP")

if s_block_start("CMD_FRMT_+CSDH", dep="commands", dep_value="+CSDH"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CSDH")

if s_block_start("CMD_FRMT_+CSCB", dep="commands", dep_value="+CSCB"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CSCB")

if s_block_start("CMD_FRMT_+CNMI", dep="commands", dep_value="+CNMI"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CNMI")

if s_block_start("CMD_FRMT_+CMGL", dep="commands", dep_value="+CMGL"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CMGL")

if s_block_start("CMD_FRMT_+CMGR", dep="commands", dep_value="+CMGR"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CMGR")

if s_block_start("CMD_FRMT_+CNMA", dep="commands", dep_value="+CNMA"):
    s_string("=1")
s_block_end("CMD_FRMT_+CNMA")

if s_block_start("CMD_FRMT_+CMGS", dep="commands", dep_value="+CMGS"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CMGS")

if s_block_start("CMD_FRMT_+CMGW", dep="commands", dep_value="+CMGW"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CMGW")

if s_block_start("CMD_FRMT_+CMGD", dep="commands", dep_value="+CMGD"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CMGD")

if s_block_start("CMD_FRMT_+CMSS", dep="commands", dep_value="+CMSS"):
    s_static("=")
    s_string("1")
    s_static(",")
    s_string("1")
    s_static(",")
    s_string("1")
s_block_end("CMD_FRMT_+CMSS")

if s_block_start("CMD_FRMT_+CMGC", dep="commands", dep_value="+CMGC"):
    s_string("=1")
s_block_end("CMD_FRMT_+CMGC")

if s_block_start("CMD_FRMT_+CMMS", dep="commands", dep_value="+CMMS"):
    s_static("=")
    s_string("1")
s_block_end("CMD_FRMT_+CMMS")

s_static("\r\n")
