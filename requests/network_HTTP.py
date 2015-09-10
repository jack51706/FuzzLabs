# =============================================================================
# (Very) Basic HTTP Fuzzer
# - used only for testing, a better implementation is required. -
# This file is part of the FuzzLabs Fuzzing Framework
# Author: FuzzLabs
# =============================================================================

from sulley import *

s_initialize("HTTP")

if s_block_start("HTTP_REQUEST_URL_LINE"):
    s_string("GET")
    s_binary(" /")
    s_string("index")
    s_binary(".")
    s_string("html")
    s_binary("?")
    s_string("name")
    s_binary("=")
    s_string("value")

    if s_block_start("HTTP_REQUEST_URL_LINE_PARAMS"):
        s_binary("&")
        s_string("a_name")
        s_binary("=")
        s_string("value")
    s_block_end("HTTP_REQUEST_URL_LINE_PARAMS")
    s_repeat("HTTP_REQUEST_URL_LINE_PARAMS", min_reps=0, max_reps=10000, step=100)

    s_binary(" ")
    s_string("HTTP")
    s_binary("/")
    s_string("1")
    s_binary(".")
    s_string("1")
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_URL_LINE")
s_repeat("HTTP_REQUEST_URL_LINE", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_HOST"):
    s_binary("Host: ")
    s_string("127")
    s_binary(".0.0")

    if s_block_start("HTTP_REQUEST_HOST_HEADER_IP_ADDRESS"):
        s_binary(".")
        s_string("1")
    s_block_end("HTTP_REQUEST_HOST_HEADER_IP_ADDRESS")
    s_repeat("HTTP_REQUEST_HOST_HEADER_IP_ADDRESS", min_reps=0, max_reps=10000, step=100)

    s_binary(":")
    s_string("80")
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_HEADER_HOST")
s_repeat("HTTP_REQUEST_HEADER_HOST", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_AGENT"):
    s_binary("User-Agent: ")
    s_string("Mozilla/5.0 (")
    s_string("Windows NT 6.1; WOW64; rv:38.0")
    s_string(") Gecko/20100101 Firefox/38.0")
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_HEADER_AGENT")
s_repeat("HTTP_REQUEST_HEADER_AGENT", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_ACCEPT"):
    s_binary("Accept: ")
    s_string("*")
    s_binary("/")
    s_string("*")
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_HEADER_ACCEPT")
s_repeat("HTTP_REQUEST_HEADER_ACCEPT", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_ACCEPT_LANG"):
    s_binary("Accept-Language: ")
    if s_block_start("HTTP_REQUEST_HEADER_ACCEPT_LANGS"):
        s_string("en")
        s_binary("-")
        s_string("US")
        s_binary(",")
    s_block_end("HTTP_REQUEST_HEADER_ACCEPT_LANGS")
    s_repeat("HTTP_REQUEST_HEADER_ACCEPT_LANGS", min_reps=0, max_reps=10000, step=100)
    s_string("en")
    s_binary(";q=")
    s_string("0.5")
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_HEADER_ACCEPT_LANG")
s_repeat("HTTP_REQUEST_HEADER_ACCEPT_LANG", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_ACCEPT_ENC"):
    s_binary("Accept-Encoding: ")
    s_string("gzip")
    if s_block_start("HTTP_REQUEST_HEADER_ACCEPT_ENCS"):
        s_binary(",")
        s_string("deflate")
    s_block_end("HTTP_REQUEST_HEADER_ACCEPT_ENCS")
    s_repeat("HTTP_REQUEST_HEADER_ACCEPT_ENCS", min_reps=0, max_reps=10000, step=100)
    s_binary("\r\n")
s_block_end("HTTP_REQUEST_HEADER_ACCEPT_ENC")
s_repeat("HTTP_REQUEST_HEADER_ACCEPT_ENC", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_REFERER"):
    s_binary("Referer: ")
    s_string("http://127.0.0.1/")
s_block_end("HTTP_REQUEST_HEADER_REFERER")
s_repeat("HTTP_REQUEST_HEADER_REFERER", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_ORIGIN"):
    s_binary("Origin: ")
    s_string("http")
    s_binary("://")
    s_string("127.0.0.1")
    s_binary("/")
s_block_end("HTTP_REQUEST_HEADER_ORIGIN")
s_repeat("HTTP_REQUEST_HEADER_ORIGIN", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_CONNECTION"):
    s_binary("connection: ")
    s_string("close")
s_block_end("HTTP_REQUEST_HEADER_CONNECTION")
s_repeat("HTTP_REQUEST_HEADER_CONNECTION", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_RANGE"):
    s_binary("Range: ")
    s_string("bytes")
    s_binary("=")
    s_byte("0", format="ascii", signed=False, fuzzable=True)
    s_binary("-")
    s_byte("5", format="ascii", signed=False, fuzzable=True)
    if s_block_start("HTTP_REQUEST_HEADER_RANGES"):
        s_binary(",")
        s_qword("00000100", format="ascii", signed=False, fuzzable=True)
        s_binary("-")
        s_qword("00000200", format="ascii", signed=False, fuzzable=True)
    s_block_end("HTTP_REQUEST_HEADER_RANGES")
s_block_end("HTTP_REQUEST_HEADER_RANGE")
s_repeat("HTTP_REQUEST_HEADER_RANGE", min_reps=0, max_reps=10000, step=100)

if s_block_start("HTTP_REQUEST_HEADER_COOKIE"):
    s_binary("Cookie: ")
    s_string("SESSIONID")
    s_binary("=")
    s_string("value")
    if s_block_start("HTTP_REQUEST_HEADER_COOKIES"):
        s_binary("; ")
        s_string("cookiekey")
        s_binary("=")
        s_string("value")
    s_block_end("HTTP_REQUEST_HEADER_COOKIES")
    s_repeat("HTTP_REQUEST_HEADER_COOKIES", min_reps=0, max_reps=10000, step=100)
s_block_end("HTTP_REQUEST_HEADER_COOKIE")
s_repeat("HTTP_REQUEST_HEADER_COOKIE", min_reps=0, max_reps=10000, step=100)

s_binary("\r\n\r\n")

