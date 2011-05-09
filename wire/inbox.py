import json
import redis
from wire.message import Message
class Inbox:
    def __init__(self, user=False, redis=False):
        self.user = user
        self.messages = []
        self.redis = redis
    def load(self):
        mkeys = self.redis.lrange('user:%s:inbox' % self.user.key, 0, -1)
        for message in mkeys:
            m = Message(self.redis, key=message, user=self.user)
            m.load()
            m.status = self.redis.get('user:%smessage:%s:status' % (self.user.key, message))
            self.messages.append(m)
        