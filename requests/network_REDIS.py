# =============================================================================
# Basic Redis (http://redis.io) Fuzzer
# WORK IN PROGRESS
# Author: FuzzLabs
# =============================================================================

from sulley import *

# -----------------------------------------------------------------------------
# http://redis.io/commands/auth
# -----------------------------------------------------------------------------

s_initialize("AUTH")
s_string("AUTH")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/set
# -----------------------------------------------------------------------------

s_initialize("SET")
s_static("SET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("xx")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/exists
# -----------------------------------------------------------------------------

s_initialize("EXISTS")
s_static("EXISTS")
if s_block_start("EXISTS_KEYS"):
    s_delim(" ")
    s_string("test")
s_block_end("EXISTS_KEYS")
s_repeat("EXISTS_KEYS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/del
# -----------------------------------------------------------------------------

s_initialize("DEL")
s_static("DEL")
if s_block_start("DEL_KEYS"):
    s_delim(" ")
    s_string("test")
s_block_end("DEL_KEYS")
s_repeat("DEL_KEYS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/append
# -----------------------------------------------------------------------------

s_initialize("APPEND")
s_static("APPEND")
s_delim(" ")
s_string("test")
s_delim(" ")
s_static("\"")
s_string("test")
s_static("\"")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/get
# -----------------------------------------------------------------------------

s_initialize("GET")
s_static("GET")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitcount
# -----------------------------------------------------------------------------

s_initialize("BITCOUNT")
s_static("BITCOUNT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitop
# -----------------------------------------------------------------------------

s_initialize("BITOP")
s_static("BITOP")
s_delim(" ")
s_group("BITOP_OP", values=["AND", "OR", "XOR", "NOT"])
s_delim(" ")
if s_block_start("BITOP_ANDORXOR", dep="BITOP_OP", dep_values=["AND", "OR", "XOR"]):
    s_string("test")
    if s_block_start("BITOP_ANDORXOR_SRCKEY"):
        s_delim(" ")
        s_string("test")
    s_block_end("BITOP_ANDORXOR_SRCKEY")
    s_repeat("BITOP_ANDORXOR_SRCKEY", min_reps=0, max_reps=100000, step=1000)
s_block_end("BITOP_ANDORXOR")
if s_block_start("BITOP_NOT", dep="BITOP_OP", dep_values=["NOT"]):
    s_string("test")
    s_delim(" ")
    s_string("test")
s_block_end("BITOP_NOT")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitpos
# -----------------------------------------------------------------------------

s_initialize("BITPOS")
s_static("BITPOS")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/client-kill
# -----------------------------------------------------------------------------

s_initialize("CLIENTKILL")
s_static("CLIENT KILL")
s_delim(" ")
s_group("KILL_OP", values=["ADDR", "ID", "TYPE"])
s_delim(" ")
if s_block_start("KILLOP_ADDR", dep="KILL_OP", dep_values=["ADDR"]):
    s_string("192")
    s_delim(".")
    s_string("168")
    s_delim(".")
    s_string("1")
    s_delim(".")
    s_string("233")
    s_delim(":")
    s_string("45443")
s_block_end("KILLOP_ADDR")
if s_block_start("KILLOP_ID", dep="KILL_OP", dep_values=["ID"]):
    s_string("fake-client-id")
s_block_end("KILLOP_ID")
if s_block_start("KILLOP_TYPE", dep="KILL_OP", dep_values=["TYPE"]):
    s_string("slave")
s_block_end("KILLOP_TYPE")
s_delim(" ")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/client-setname
# -----------------------------------------------------------------------------

s_initialize("CLIENTSETNAME")
s_static("CLIENT SETNAME")
s_delim(" ")
s_string("FuzzLabs")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-addslots
# -----------------------------------------------------------------------------

s_initialize("CLUSTERADDSLOTS")
s_static("CLUSTER ADDSLOTS")
if s_block_start("CLUST_ADD_SLOTS"):
    s_delim(" ")
    s_string("1")
s_block_end("CLUST_ADD_SLOTS")
s_repeat("CLUST_ADD_SLOTS", min_reps=0, max_reps=100000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-count-failure-reports
# -----------------------------------------------------------------------------

s_initialize("CLUSTERCFR")
s_static("CLUSTER COUNT-FAILURE-REPORTS")
s_delim(" ")
s_string("FuzzLabs")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-countkeysinslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERCKIS")
s_static("CLUSTER COUNTKEYSINSLOT")
s_delim(" ")
s_string("7000")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-delslots
# -----------------------------------------------------------------------------

s_initialize("CLUSTERDELSLOTS")
s_static("CLUSTER DELSLOTS")
if s_block_start("CLUST_DEL_SLOTS"):
    s_delim(" ")
    s_string("1")
s_block_end("CLUST_DEL_SLOTS")
s_repeat("CLUST_DEL_SLOTS", min_reps=0, max_reps=100000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-forget
# -----------------------------------------------------------------------------

s_initialize("CLUSTERFORGET")
s_static("CLUSTER FORGET")
s_delim(" ")
s_string("FuzzLabs")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-getkeysinslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERGKIS")
s_static("CLUSTER GETKEYSINSLOT")
s_delim(" ")
s_int(7000, format="ascii")
s_delim(" ")
s_int(3, format="ascii")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-keyslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERKEYSLOT")
s_static("CLUSTER KEYSLOT")
s_delim(" ")
s_string("test")
s_static("{")
s_string("test")
s_static("}")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-meet
# -----------------------------------------------------------------------------

s_initialize("CLUSTERMEET")
s_static("CLUSTER MEET")
s_delim(" ")
s_string("127.0.0.1")
s_delim(" ")
s_int(6666, format="ascii")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-replicate
# -----------------------------------------------------------------------------

s_initialize("CLUSTERREPLICATE")
s_static("CLUSTER REPLICATE")
s_delim(" ")
s_string("FuzzLabs")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/command-getkeys
# -----------------------------------------------------------------------------

s_initialize("COMMANDGETKEYS")
s_static("COMMAND GETKEYS")
s_delim(" ")
s_string("SET")
s_delim(" ")
s_string("a")
s_delim(" ")
s_string("b")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/command-info
# -----------------------------------------------------------------------------

s_initialize("COMMANDINFO")
s_static("COMMAND INFO")
if s_block_start("CINFO_C_LIST"):
    s_delim(" ")
    s_string("SET")
s_block_end("CINFO_C_LIST")
s_repeat("CINFO_C_LIST", min_reps=0, max_reps=100000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/config-get
# -----------------------------------------------------------------------------

s_initialize("CONFIGGET")
s_static("CONFIG GET")
s_delim(" ")
s_string("*requirepa*")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/config-set
# -----------------------------------------------------------------------------

s_initialize("CONFIGSET")
s_static("CONFIG SET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/debug-object
# -----------------------------------------------------------------------------

s_initialize("DEBUGOBJECT")
s_static("DEBUG OBJECT")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/object
# -----------------------------------------------------------------------------

s_initialize("OBJECT")
s_static("OBJECT")
s_delim(" ")
s_group("OBJECT_OP", values=["REFCOUNT", "ENCODING", "IDLETIME"])
s_delim(" ")
if s_block_start("OBJECT_OBJ", dep="OBJECT_OP", dep_values=["REFCOUNT", "ENCODING", "IDLETIME"]):
    s_string("test")
s_block_end("OBJECT_OBJ")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/decr
# -----------------------------------------------------------------------------

s_initialize("DECR")
s_static("DECR")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/decrby
# -----------------------------------------------------------------------------

s_initialize("DECR_BY")
s_static("DECRBY")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/dump
# -----------------------------------------------------------------------------

s_initialize("DUMP")
s_static("DUMP")
s_delim(" ")
s_string("test")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/echo
# -----------------------------------------------------------------------------

s_initialize("ECHO")
s_static("ECHO")
s_delim(" ")
s_static("\"")
s_string("FuzzLabs")
s_static("\"")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/eval
# -----------------------------------------------------------------------------

s_initialize("EVAL")
s_static("EVAL")
s_delim(" ")
s_static("\"")
s_string("return 'OK'")
s_static("\"")
s_delim(" ")
s_int(0, format="ascii")
if s_block_start("EVAL_PARAMS"):
    s_delim(" ")
    s_string("test")
s_block_end("EVAL_PARAMS")
s_repeat("EVAL_PARAMS", min_reps=0, max_reps=100000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/evalsha
# -----------------------------------------------------------------------------

s_initialize("EVALSHA")
s_static("EVALSHA")
s_delim(" ")
s_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
s_delim(" ")
s_int(0, format="ascii")
if s_block_start("EVALSHA_PARAMS"):
    s_delim(" ")
    s_string("a")
s_block_end("EVALSHA_PARAMS")
s_repeat("EVALSHA_PARAMS", min_reps=0, max_reps=100000, step=1000)
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/exec
# -----------------------------------------------------------------------------

s_initialize("EXEC")
s_static("MULTI\r\n")
if s_block_start("EXEC_MULTI"):
    s_string("set")
    s_delim(" ")
    s_string("x")
    s_delim(" ")
    s_string("y")
    s_static("\r\n")
s_block_end("EXEC_MULTI")
s_repeat("EXEC_MULTI", min_reps=0, max_reps=100000, step=1000)
s_static("EXEC\r\n")
s_static("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/expire
# -----------------------------------------------------------------------------

s_initialize("EXPIRE")
s_static("EXPIRE")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(500, format="ascii")
s_static("\r\n")



# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------

s_initialize("INCR")
s_static("INCR")
s_delim(" ")
s_string("test")
s_static("\r\n")

s_initialize("INCR_BY")
s_static("INCRBY")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

s_initialize("GETSET")
s_static("GETSET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_static("\r\n")

s_initialize("PEXPIRE")
s_static("PEXPIRE")
s_delim(" ")
s_string("test")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

s_initialize("SET_EXP")
s_static("SET")
s_delim(" ")
s_static("test")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("ex")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

s_initialize("TTL")
s_static("TTL")
s_delim(" ")
s_string("test")
s_static("\r\n")

s_initialize("PTTL")
s_static("PTTL")
s_delim(" ")
s_string("test")
s_static("\r\n")

s_initialize("LPUSH")
s_static("LPUSH")
s_delim(" ")
s_string("p_test")
if s_block_start("LPUSH_LIST_ITEMS"):
    s_delim(" ")
    s_string("test")
s_block_end("LPUSH_LIST_ITEMS")
s_repeat("LPUSH_LIST_ITEMS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("RPUSH")
s_static("RPUSH")
s_delim(" ")
s_string("p_test")
if s_block_start("RPUSH_LIST_ITEMS"):
    s_delim(" ")
    s_string("test")
s_block_end("RPUSH_LIST_ITEMS")
s_repeat("RPUSH_LIST_ITEMS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("LRANGE")
s_static("LRANGE")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii")
s_static("\r\n")

s_initialize("RPOP")
s_static("RPOP")
s_delim(" ")
s_string("p_test")
s_static("\r\n")

s_initialize("LPOP")
s_static("LPOP")
s_delim(" ")
s_string("p_test")
s_static("\r\n")

s_initialize("LTRIM")
s_static("LTRIM")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii")
s_static("\r\n")

s_initialize("BRPOP")
s_static("BRPOP")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_static("1") # Not a good idea to fuzz this one...
s_static("\r\n")

s_initialize("RPOPLPUSH")
s_static("RPOPLPUSH")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_string("test")
s_static("\r\n")

s_initialize("HMSET")
s_static("HMSET")
s_delim(" ")
s_string("user")
s_delim(":")
s_string("1000")
s_delim(" ")
if s_block_start("HMSET_KV_VALUES"):
    s_delim(" ")
    s_string("key")
    s_delim(" ")
    s_string("1000")
s_block_end("HMSET_KV_VALUES")
s_repeat("HMSET_KV_VALUES", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("HGET")
s_static("HGET")
s_delim(" ")
s_string("user")
s_delim(":")
s_string("1000")
s_delim(" ")
s_string("key")
s_static("\r\n")

s_initialize("HGETALL")
s_static("HGETALL")
s_delim(" ")
s_string("user")
s_delim(":")
s_string("1000")
s_static("\r\n")

s_initialize("HMGET")
s_static("HMGET")
s_delim(" ")
s_string("user")
s_delim(":")
s_string("1000")
s_delim(" ")
if s_block_start("HMGET_K_VALUES"):
    s_delim(" ")
    s_string("key")
s_block_end("HMGET_K_VALUES")
s_repeat("HMGET_K_VALUES", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("HINCRBY")
s_static("HINCRBY")
s_delim(" ")
s_string("user")
s_delim(":")
s_string("1000")
s_delim(" ")
s_string("key")
s_delim(" ")
s_int(1, format="ascii")
s_static("\r\n")

s_initialize("SADD")
s_static("SADD")
s_delim(" ")
s_string("news")
s_delim(":")
s_int(1000, format="ascii")
s_delim(":")
s_string("tags")
s_delim(" ")
if s_block_start("SADD_TEST_SET"):
    s_delim(" ")
    s_string("value")
s_block_end("SADD_TEST_SET")
s_repeat("SADD_TEST_SET", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("SMEMBERS")
s_static("SMEMBERS")
s_delim(" ")
s_string("news:1000:tags")
s_static("\r\n")

s_initialize("SISMEMBER")
s_static("SISMEMBER")
s_delim(" ")
s_string("news:1000:tags")
s_delim(" ")
s_string("value")
s_static("\r\n")

s_initialize("SINTER")
s_static("SINTER")
if s_block_start("SINTER_PARAMS"):
    s_delim(" ")
    s_string("news")
    s_delim(":")
    s_int(1000, format="ascii")
    s_delim(":")
    s_string("tags")
s_block_end("SINTER_PARAMS")
s_repeat("SINTER_PARAMS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

s_initialize("SPOP")
s_static("SPOP")
s_delim(" ")
s_string("news:1000:tags")
s_static("\r\n")

s_initialize("SUNIONSTORE")
s_static("SUNIONSTORE")
s_delim(" ")
s_string("news:1000:backup")
s_delim(" ")
s_string("news:1000:tags")
s_static("\r\n")

s_initialize("ZADD")
s_static("ZADD")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_int(1000, format="ascii")
s_delim(" ")
s_static("\"")
s_string("Item name")
s_static("\"")
s_static("\r\n")

s_initialize("ZRANGE")
s_static("ZRANGE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii", signed=True)
s_static("\r\n")

s_initialize("ZREVRANGE")
s_static("ZREVRANGE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1, format="ascii", signed=True)
s_static("\r\n")

s_initialize("ZRANGEBYSCORE")
s_static("ZRANGEBYSCORE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_static("-")
s_string("inf")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

s_initialize("ZRANGEBYSCORE_R")
s_static("ZRANGEBYSCORE_R")
s_delim(" ")
s_static("zadd_test")
s_delim(" ")
s_int(0, format="ascii")
s_delim(" ")
s_int(1000, format="ascii")
s_static("\r\n")

s_initialize("ZRANK")
s_static("ZRANK")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_static("\"")
s_string("Item name")
s_static("\"")
s_static("\r\n")

s_initialize("ZREVRANK")
s_static("ZREVRANK")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_static("\"")
s_string("Item name")
s_static("\"")
s_static("\r\n")

s_initialize("ZADD_LEX")
s_static("ZADD")
s_delim(" ")
s_string("zadd_test_lex")
if s_block_start("ZADD_LEX_PARAMS"):
    s_static(" 0 ")
    s_static("\"")
    s_string("Item name")
    s_static("\"")
s_block_end("ZADD_LEX_PARAMS")
s_repeat("ZADD_LEX_PARAMS", min_reps=0, max_reps=1000000, step=1000)
s_static("\r\n")

