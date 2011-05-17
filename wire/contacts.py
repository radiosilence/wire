import redis

class Contacts:
    def __init__(self, redis=False, user=False):
        self.user = user
        self.redis = redis
        self.key = 'user:%s:contacts' % user.key
        self.contacts = []
        self._update()

    def _update(self):
        self.contacts = [c.decode("UTF-8") for c in self.redis.lrange(self.key, 0, -1)]


    def add(self, username):
        r = self.redis
        if username in self.contacts:
            raise ContactExistsError()
        if not r.exists('username:%s' % username):
            raise ContactInvalidError()
        r.lpush(self.key, username)
        self.redis.sort(self.key, alpha=True, store=self.key)
        self._update()

    def delete(self, contact):
        self.redis.lrem(self.key, contact, 0)
        self._update()

    def search(self, part):
        results = []
        users = self.redis.lrange('list:usernames', 0, -1)
        part = part.encode("UTF-8")
        for contact in users:
            if part in contact:
                results.append(contact)
        return results

class ContactInvalidError(Exception):
    pass

class ContactExistsError(Exception):
    pass