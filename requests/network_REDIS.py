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
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/set
# -----------------------------------------------------------------------------

s_initialize("SET")
s_binary("SET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("xx")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/exists
# -----------------------------------------------------------------------------

s_initialize("EXISTS")
s_binary("EXISTS")
if s_block_start("EXISTS_KEYS"):
    s_delim(" ")
    s_string("test")
s_block_end("EXISTS_KEYS")
s_repeat("EXISTS_KEYS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/del
# -----------------------------------------------------------------------------

s_initialize("DEL")
s_binary("DEL")
if s_block_start("DEL_KEYS"):
    s_delim(" ")
    s_string("test")
s_block_end("DEL_KEYS")
s_repeat("DEL_KEYS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/append
# -----------------------------------------------------------------------------

s_initialize("APPEND")
s_binary("APPEND")
s_delim(" ")
s_string("test")
s_delim(" ")
s_binary("\"")
s_string("test")
s_binary("\"")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/get
# -----------------------------------------------------------------------------

s_initialize("GET")
s_binary("GET")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitcount
# -----------------------------------------------------------------------------

s_initialize("BITCOUNT")
s_binary("BITCOUNT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitop
# -----------------------------------------------------------------------------

s_initialize("BITOP")
s_binary("BITOP")
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
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/bitpos
# -----------------------------------------------------------------------------

s_initialize("BITPOS")
s_binary("BITPOS")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/client-kill
# -----------------------------------------------------------------------------

s_initialize("CLIENTKILL")
s_binary("CLIENT KILL")
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
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/client-setname
# -----------------------------------------------------------------------------

s_initialize("CLIENTSETNAME")
s_binary("CLIENT SETNAME")
s_delim(" ")
s_string("FuzzLabs")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-addslots
# -----------------------------------------------------------------------------

s_initialize("CLUSTERADDSLOTS")
s_binary("CLUSTER ADDSLOTS")
if s_block_start("CLUST_ADD_SLOTS"):
    s_delim(" ")
    s_string("1")
s_block_end("CLUST_ADD_SLOTS")
s_repeat("CLUST_ADD_SLOTS", min_reps=0, max_reps=100000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-count-failure-reports
# -----------------------------------------------------------------------------

s_initialize("CLUSTERCFR")
s_binary("CLUSTER COUNT-FAILURE-REPORTS")
s_delim(" ")
s_string("FuzzLabs")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-countkeysinslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERCKIS")
s_binary("CLUSTER COUNTKEYSINSLOT")
s_delim(" ")
s_string("7000")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-delslots
# -----------------------------------------------------------------------------

s_initialize("CLUSTERDELSLOTS")
s_binary("CLUSTER DELSLOTS")
if s_block_start("CLUST_DEL_SLOTS"):
    s_delim(" ")
    s_string("1")
s_block_end("CLUST_DEL_SLOTS")
s_repeat("CLUST_DEL_SLOTS", min_reps=0, max_reps=100000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-forget
# -----------------------------------------------------------------------------

s_initialize("CLUSTERFORGET")
s_binary("CLUSTER FORGET")
s_delim(" ")
s_string("FuzzLabs")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-getkeysinslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERGKIS")
s_binary("CLUSTER GETKEYSINSLOT")
s_delim(" ")
s_dword(7000, format="ascii")
s_delim(" ")
s_dword(3, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-keyslot
# -----------------------------------------------------------------------------

s_initialize("CLUSTERKEYSLOT")
s_binary("CLUSTER KEYSLOT")
s_delim(" ")
s_string("test")
s_binary("{")
s_string("test")
s_binary("}")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-meet
# -----------------------------------------------------------------------------

s_initialize("CLUSTERMEET")
s_binary("CLUSTER MEET")
s_delim(" ")
s_string("127.0.0.1")
s_delim(" ")
s_dword(6666, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/cluster-replicate
# -----------------------------------------------------------------------------

s_initialize("CLUSTERREPLICATE")
s_binary("CLUSTER REPLICATE")
s_delim(" ")
s_string("FuzzLabs")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/command-getkeys
# -----------------------------------------------------------------------------

s_initialize("COMMANDGETKEYS")
s_binary("COMMAND GETKEYS")
s_delim(" ")
s_string("SET")
s_delim(" ")
s_string("a")
s_delim(" ")
s_string("b")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/command-info
# -----------------------------------------------------------------------------

s_initialize("COMMANDINFO")
s_binary("COMMAND INFO")
if s_block_start("CINFO_C_LIST"):
    s_delim(" ")
    s_string("SET")
s_block_end("CINFO_C_LIST")
s_repeat("CINFO_C_LIST", min_reps=0, max_reps=100000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/config-get
# -----------------------------------------------------------------------------

s_initialize("CONFIGGET")
s_binary("CONFIG GET")
s_delim(" ")
s_string("*requirepa*")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/config-set
# -----------------------------------------------------------------------------

s_initialize("CONFIGSET")
s_binary("CONFIG SET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/debug-object
# -----------------------------------------------------------------------------

s_initialize("DEBUGOBJECT")
s_binary("DEBUG OBJECT")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/object
# -----------------------------------------------------------------------------

s_initialize("OBJECT")
s_binary("OBJECT")
s_delim(" ")
s_group("OBJECT_OP", values=["REFCOUNT", "ENCODING", "IDLETIME"])
s_delim(" ")
if s_block_start("OBJECT_OBJ", dep="OBJECT_OP", dep_values=["REFCOUNT", "ENCODING", "IDLETIME"]):
    s_string("test")
s_block_end("OBJECT_OBJ")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/decr
# -----------------------------------------------------------------------------

s_initialize("DECR")
s_binary("DECR")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/decrby
# -----------------------------------------------------------------------------

s_initialize("DECR_BY")
s_binary("DECRBY")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/dump
# -----------------------------------------------------------------------------

s_initialize("DUMP")
s_binary("DUMP")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/echo
# -----------------------------------------------------------------------------

s_initialize("ECHO")
s_binary("ECHO")
s_delim(" ")
s_binary("\"")
s_string("FuzzLabs")
s_binary("\"")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/eval
# -----------------------------------------------------------------------------

s_initialize("EVAL")
s_binary("EVAL")
s_delim(" ")
s_binary("\"")
s_string("return 'OK'")
s_binary("\"")
s_delim(" ")
s_dword(0, format="ascii")
if s_block_start("EVAL_PARAMS"):
    s_delim(" ")
    s_string("test")
s_block_end("EVAL_PARAMS")
s_repeat("EVAL_PARAMS", min_reps=0, max_reps=100000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/evalsha
# -----------------------------------------------------------------------------

s_initialize("EVALSHA")
s_binary("EVALSHA")
s_delim(" ")
s_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
s_delim(" ")
s_dword(0, format="ascii")
if s_block_start("EVALSHA_PARAMS"):
    s_delim(" ")
    s_string("a")
s_block_end("EVALSHA_PARAMS")
s_repeat("EVALSHA_PARAMS", min_reps=0, max_reps=100000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/exec
# -----------------------------------------------------------------------------

s_initialize("EXEC")
s_binary("MULTI\r\n")
if s_block_start("EXEC_MULTI"):
    s_string("set")
    s_delim(" ")
    s_string("x")
    s_delim(" ")
    s_string("y")
    s_binary("\r\n")
s_block_end("EXEC_MULTI")
s_repeat("EXEC_MULTI", min_reps=0, max_reps=100000, step=1000)
s_binary("EXEC\r\n")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/expire
# -----------------------------------------------------------------------------

s_initialize("EXPIRE")
s_binary("EXPIRE")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(500, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/expireat
# -----------------------------------------------------------------------------

s_initialize("EXPIREAT")
s_binary("EXPIREAT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1293840000, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/getbit
# -----------------------------------------------------------------------------

s_initialize("GETBIT")
s_binary("GETBIT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/setbit
# -----------------------------------------------------------------------------

s_initialize("SETBIT")
s_binary("SETBIT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1, format="ascii")
s_delim(" ")
s_dword(0, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/getrange
# -----------------------------------------------------------------------------

s_initialize("GETRANGE")
s_binary("GETRANGE")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/getset
# -----------------------------------------------------------------------------

s_initialize("GETSET")
s_binary("GETSET")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hset
# -----------------------------------------------------------------------------

s_initialize("HSET")
s_binary("HSET")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_binary("\"")
s_string("h_test")
s_binary("\"")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hdel
# -----------------------------------------------------------------------------

s_initialize("HDEL")
s_binary("HDEL")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hexists
# -----------------------------------------------------------------------------

s_initialize("HEXISTS")
s_binary("HEXISTS")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hget
# -----------------------------------------------------------------------------

s_initialize("HGET")
s_binary("HGET")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hgetall
# -----------------------------------------------------------------------------

s_initialize("HGETALL")
s_binary("HGETALL")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hincrby
# -----------------------------------------------------------------------------

s_initialize("HINCRBY")
s_binary("HINCRBY")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hincrbyfloat
# -----------------------------------------------------------------------------

s_initialize("HINCRBYFLOAT")
s_binary("HINCRBYFLOAT")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_dword(1, format="ascii")
s_delim(".")
s_dword(10, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hkeys
# -----------------------------------------------------------------------------

s_initialize("HKEYS")
s_binary("HKEYS")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hlen
# -----------------------------------------------------------------------------

s_initialize("HLEN")
s_binary("HLEN")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hmget
# -----------------------------------------------------------------------------

s_initialize("HMGET")
s_binary("HMGET")
s_delim(" ")
s_string("h_test")
s_delim(" ")
if s_block_start("HMGET_K_VALUES"):
    s_delim(" ")
    s_string("h_test")
s_block_end("HMGET_K_VALUES")
s_repeat("HMGET_K_VALUES", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hmset
# -----------------------------------------------------------------------------

s_initialize("HMSET")
s_binary("HMSET")
s_delim(" ")
s_string("h_test")
if s_block_start("HMSET_KV_VALUES"):
    s_delim(" ")
    s_string("key")
    s_delim(" ")
    s_string("1000")
s_block_end("HMSET_KV_VALUES")
s_repeat("HMSET_KV_VALUES", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hsetnx
# -----------------------------------------------------------------------------

s_initialize("HSETNX")
s_binary("HSETNX")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_binary("\"")
s_string("h_test")
s_binary("\"")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hstrlen
# -----------------------------------------------------------------------------

s_initialize("HSTRLEN")
s_binary("HSTRLEN")
s_delim(" ")
s_string("h_test")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/hvals
# -----------------------------------------------------------------------------

s_initialize("HVALS")
s_binary("HVALS")
s_delim(" ")
s_string("h_test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/incr
# -----------------------------------------------------------------------------

s_initialize("INCR")
s_binary("INCR")
s_delim(" ")
s_string("test")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/incrby
# -----------------------------------------------------------------------------

s_initialize("INCRBY")
s_binary("INCRBY")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/incrbyfloat
# -----------------------------------------------------------------------------

s_initialize("INCRBYFLOAT")
s_binary("INCRBYFLOAT")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1, format="ascii")
s_delim(".")
s_dword(1, format="ascii")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/info
# -----------------------------------------------------------------------------

s_initialize("INFO")
s_binary("INFO")
s_delim(" ")
s_string("all")
s_binary("\r\n")

# -----------------------------------------------------------------------------
# http://redis.io/commands/keys
# -----------------------------------------------------------------------------

s_initialize("KEYS")
s_binary("KEYS")
s_delim(" ")
s_string("*a*")
s_binary("\r\n")






# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------

s_initialize("PEXPIRE")
s_binary("PEXPIRE")
s_delim(" ")
s_string("test")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

s_initialize("SET_EXP")
s_binary("SET")
s_delim(" ")
s_binary("test")
s_delim(" ")
s_string("test")
s_delim(" ")
s_string("ex")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

s_initialize("TTL")
s_binary("TTL")
s_delim(" ")
s_string("test")
s_binary("\r\n")

s_initialize("PTTL")
s_binary("PTTL")
s_delim(" ")
s_string("test")
s_binary("\r\n")

s_initialize("LPUSH")
s_binary("LPUSH")
s_delim(" ")
s_string("p_test")
if s_block_start("LPUSH_LIST_ITEMS"):
    s_delim(" ")
    s_string("test")
s_block_end("LPUSH_LIST_ITEMS")
s_repeat("LPUSH_LIST_ITEMS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

s_initialize("RPUSH")
s_binary("RPUSH")
s_delim(" ")
s_string("p_test")
if s_block_start("RPUSH_LIST_ITEMS"):
    s_delim(" ")
    s_string("test")
s_block_end("RPUSH_LIST_ITEMS")
s_repeat("RPUSH_LIST_ITEMS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

s_initialize("LRANGE")
s_binary("LRANGE")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

s_initialize("RPOP")
s_binary("RPOP")
s_delim(" ")
s_string("p_test")
s_binary("\r\n")

s_initialize("LPOP")
s_binary("LPOP")
s_delim(" ")
s_string("p_test")
s_binary("\r\n")

s_initialize("LTRIM")
s_binary("LTRIM")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii")
s_binary("\r\n")

s_initialize("BRPOP")
s_binary("BRPOP")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_binary("1") # Not a good idea to fuzz this one...
s_binary("\r\n")

s_initialize("RPOPLPUSH")
s_binary("RPOPLPUSH")
s_delim(" ")
s_string("p_test")
s_delim(" ")
s_string("test")
s_binary("\r\n")

s_initialize("SADD")
s_binary("SADD")
s_delim(" ")
s_string("news")
s_delim(":")
s_dword(1000, format="ascii")
s_delim(":")
s_string("tags")
s_delim(" ")
if s_block_start("SADD_TEST_SET"):
    s_delim(" ")
    s_string("value")
s_block_end("SADD_TEST_SET")
s_repeat("SADD_TEST_SET", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

s_initialize("SMEMBERS")
s_binary("SMEMBERS")
s_delim(" ")
s_string("news:1000:tags")
s_binary("\r\n")

s_initialize("SISMEMBER")
s_binary("SISMEMBER")
s_delim(" ")
s_string("news:1000:tags")
s_delim(" ")
s_string("value")
s_binary("\r\n")

s_initialize("SINTER")
s_binary("SINTER")
if s_block_start("SINTER_PARAMS"):
    s_delim(" ")
    s_string("news")
    s_delim(":")
    s_dword(1000, format="ascii")
    s_delim(":")
    s_string("tags")
s_block_end("SINTER_PARAMS")
s_repeat("SINTER_PARAMS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

s_initialize("SPOP")
s_binary("SPOP")
s_delim(" ")
s_string("news:1000:tags")
s_binary("\r\n")

s_initialize("SUNIONSTORE")
s_binary("SUNIONSTORE")
s_delim(" ")
s_string("news:1000:backup")
s_delim(" ")
s_string("news:1000:tags")
s_binary("\r\n")

s_initialize("ZADD")
s_binary("ZADD")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_dword(1000, format="ascii")
s_delim(" ")
s_binary("\"")
s_string("Item name")
s_binary("\"")
s_binary("\r\n")

s_initialize("ZRANGE")
s_binary("ZRANGE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii", signed=True)
s_binary("\r\n")

s_initialize("ZREVRANGE")
s_binary("ZREVRANGE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1, format="ascii", signed=True)
s_binary("\r\n")

s_initialize("ZRANGEBYSCORE")
s_binary("ZRANGEBYSCORE")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_binary("-")
s_string("inf")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

s_initialize("ZRANGEBYSCORE_R")
s_binary("ZRANGEBYSCORE_R")
s_delim(" ")
s_binary("zadd_test")
s_delim(" ")
s_dword(0, format="ascii")
s_delim(" ")
s_dword(1000, format="ascii")
s_binary("\r\n")

s_initialize("ZRANK")
s_binary("ZRANK")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_binary("\"")
s_string("Item name")
s_binary("\"")
s_binary("\r\n")

s_initialize("ZREVRANK")
s_binary("ZREVRANK")
s_delim(" ")
s_string("zadd_test")
s_delim(" ")
s_binary("\"")
s_string("Item name")
s_binary("\"")
s_binary("\r\n")

s_initialize("ZADD_LEX")
s_binary("ZADD")
s_delim(" ")
s_string("zadd_test_lex")
if s_block_start("ZADD_LEX_PARAMS"):
    s_binary(" 0 ")
    s_binary("\"")
    s_string("Item name")
    s_binary("\"")
s_block_end("ZADD_LEX_PARAMS")
s_repeat("ZADD_LEX_PARAMS", min_reps=0, max_reps=1000000, step=1000)
s_binary("\r\n")

