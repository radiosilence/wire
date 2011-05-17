from wire.thread import Thread, ThreadError
class Inbox:
    def __init__(self, user=False, redis=False):
        self.user = user
        self.threads = []
        self.redis = redis
    def load_messages(self):
        thread_keys = self.user.get_threads()
        for thread_key in thread_keys:
            t = Thread(redis=self.redis, user=self.user)
            try:
                t.load(key=thread_key)
                t.get_unread_count()
                self.threads.append(t)
            except ThreadError:
                t.delete(recipient=self.user)
    def unread_count(self, thread=False):
        r = self.redis
        count = 0
        for thread in r.lrange('user:%s:threads' % self.user.key, 0, -1):
            t = Thread(redis=self.redis, user=self.user)
            count += t.get_unread_count(key=thread)
        
        return count        