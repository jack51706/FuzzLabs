# =============================================================================
# Basic MongoDB Fuzzer
# This file is part of the FuzzLabs Fuzzing Framework
# Author: Zsolt Imre
# =============================================================================

from sulley import *
import struct

# MongoDB Request Opcodes

OP_REPLY	= struct.pack("<i", 1)		# Clients can't send OP_REPLY ... we will do anyway :)
OP_MSG		= struct.pack("<i", 1000)
OP_UPDATE	= struct.pack("<i", 2001)
OP_INSERT	= struct.pack("<i", 2002)
OP_RESERVED	= struct.pack("<i", 2003)	# Reserved for us to play with :)
OP_QUERY	= struct.pack("<i", 2004)
OP_GET_MORE	= struct.pack("<i", 2005)
OP_DELETE	= struct.pack("<i", 2006)
OP_KILL_CURSOR	= struct.pack("<i", 2007)

s_initialize("MONGODB")

s_size("MsgComplete", endian="<", format="binary", inclusive=True, fuzzable=False, name="REQ_SIZE")
if s_block_start("MsgComplete"):
    if s_block_start("MsgHeader"):
        s_int(1, endian="<", signed=False, fuzzable=True, name="requestID")
        s_int(1, endian="<", signed=False, fuzzable=True, name="responseTo")
        s_group("opcodes", values=[OP_REPLY, OP_MSG, OP_UPDATE, OP_INSERT, OP_RESERVED, OP_QUERY, OP_GET_MORE, OP_DELETE, OP_KILL_CURSOR])
    s_block_end("MsgHeader")

    if s_block_start("REPLY", dep="opcodes", dep_value=OP_REPLY):
        s_string("message")
    s_block_end("REPLY")

    if s_block_start("MSG", dep="opcodes", dep_value=OP_MSG):
        s_string("message")
    s_block_end("MSG")

    """
    struct OP_UPDATE {
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     flags;              // bit vector. see below
        document  selector;           // the query to select the document
        document  update;             // specification of the update to perform
    }
    """
    if s_block_start("UPDATE", dep="opcodes", dep_value=OP_UPDATE):
        s_int(0, endian="<", signed=False, fuzzable=True, name="op_update_reserved_int")
        s_string("dbname")
        s_static(".")
        s_string("collectionname")
        s_int(0, endian="<", signed=False, fuzzable=True, name="op_update_flags")
        if s_block_start("SELECTOR_BSON"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("SELECTOR_BSON")
        if s_block_start("UPDATE_BSON"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("UPDATE_BSON")
    s_block_end("UPDATE")

    """
    struct {
        int32     flags;              // bit vector - see below
        cstring   fullCollectionName; // "dbname.collectionname"
        document* documents;          // one or more documents to insert into the collection
    }
    """
    if s_block_start("INSERT", dep="opcodes", dep_value=OP_INSERT):
        s_int(0, endian="<", signed=False, fuzzable=True, name="op_insert_flags")
        s_string("dbname")
        s_static(".")
        s_string("collectionname")
        if s_block_start("INSERT_DOCUMENT"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("INSERT_DOCUMENT")
    s_block_end("INSERT")

    if s_block_start("RESERVED", dep="opcodes", dep_value=OP_RESERVED):
        s_string("message")
    s_block_end("RESERVED")

    """
    struct OP_QUERY {
        int32     flags;                  // bit vector of query options.  See below for details.
        cstring   fullCollectionName ;    // "dbname.collectionname"
        int32     numberToSkip;           // number of documents to skip
        int32     numberToReturn;         // number of documents to return
                                          //  in the first OP_REPLY batch
        document  query;                  // query object.  See below for details.
      [ document  returnFieldsSelector; ] // Optional. Selector indicating the fields
                                          //  to return.  See below for details.
    }
    """
    if s_block_start("QUERY", dep="opcodes", dep_value=OP_QUERY):
        s_int(0, endian="<", signed=False, fuzzable=True, name="op_query_flags")
        s_string("dbname")
        s_static(".")
        s_string("collectionname")
        s_int(0, endian="<", signed=False, fuzzable=True)
        s_int(1, endian="<", signed=False, fuzzable=True)
        # These are not really OK here, but at least they are BSON
        if s_block_start("QUERY_DOCUMENT"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("QUERY_DOCUMENT")
        if s_block_start("QUERY_SELECTOR"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("QUERY_SELECTOR")
    s_block_end("QUERY")

    """
    struct {
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     numberToReturn;     // number of documents to return
        int64     cursorID;           // cursorID from the OP_REPLY
    }
    """
    if s_block_start("GET_MORE", dep="opcodes", dep_value=OP_GET_MORE):
        s_int(0, endian="<", signed=False, fuzzable=True)
        s_string("dbname")
        s_static(".")
        s_string("collectionname")
        s_int(1, endian="<", signed=False, fuzzable=True)
        s_double(1, endian="<", signed=False, fuzzable=True)
    s_block_end("GET_MORE")

    """
    struct {
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     flags;              // bit vector - see below for details.
        document  selector;           // query object.  See below for details.
    }
    """
    if s_block_start("DELETE", dep="opcodes", dep_value=OP_DELETE):
        s_int(0, endian="<", signed=False, fuzzable=True)
        s_string("dbname")
        s_static(".")
        s_string("collectionname")
        s_int(0, endian="<", signed=False, fuzzable=True)
        if s_block_start("DELETE_SELECTOR"):
            s_int(22, endian="<", signed=False, fuzzable=True)
            s_string("\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00")
            s_string("\x00")
        s_block_end("DELETE_SELECTOR")
    s_block_end("DELETE")

    """
    struct {
        int32     ZERO;              // 0 - reserved for future use
        int32     numberOfCursorIDs; // number of cursorIDs in message
        int64*    cursorIDs;         // sequence of cursorIDs to close
    }
    """
    if s_block_start("KILL_CURSOR", dep="opcodes", dep_value=OP_KILL_CURSOR):
        s_int(0, endian="<", signed=False, fuzzable=True)
        s_int(1, endian="<", signed=False, fuzzable=True)
        if s_block_start("CURSORIDS"):
            s_double(1, endian="<", signed=False, fuzzable=True)
        s_block_end("CURSORIDS")
        s_repeat("CURSORIDS", min_reps=0, max_reps=10000, step=10)
    s_block_end("KILL_CURSOR")
s_block_end("MsgComplete")

