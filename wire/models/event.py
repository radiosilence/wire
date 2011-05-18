import redis

class Event:
    def __init__(self, redis=False, user=False):
        self.redis = redis
        self.user = user
        self.data = {}