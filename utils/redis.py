import redis

def autoinc(redis, key):
    key = "_incs:%s" % key
    if not redis.exists(key):
        redis.set(key, -1)
    
    return redis.incr(key)
