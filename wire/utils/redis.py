def autoinc(redis, key):
    key = "_incs:%s" % key
    if not redis.exists(key):
        redis.set(key, 0)

    return redis.incr(key)
