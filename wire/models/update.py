from wire.utils.redis import autoinc
import json
import datetime


class Update:
    def __init__(self, text, redis=None, user=None, key=None):
        self.redis = redis
        self.user = user
        self.mentions = []
        self.hashes = []
        self.text = text
        self.parse(text)
        self.datetime = datetime.now()

    def save(self):
        r = self.redis
        if not self.key:
            self.key = autoinc('update', r)

        r.set('update:%s' % self.key, self.json)

    def delete(self):
        pass

    def parse(self, text):
        pass

    def _update_followers(self):
        r = self.redis
        for follower in self.user.get_followers():
            r.push('user:%s:timeline' % follower.key, self.key)

    def _update_mentions(self):
        r = self.redis
        for mentionee in self.mentions:
            key = r.get('usernames:%s' % mentionee)
            if not key:
                continue
            r.push('user:%s:timeline' % key, self.key)
            r.push('user:%s:mentions' % key, self.key)

    def _update_timeline(self):
        self.redis.push('user:%s:timeline' % self.user.key, self.key)

    def get_data_json(self):
        return json.dumps({
            'text': self.text,
            'mentions': self.mentions,
            'hashes': self.hashes,
            'datetime': self.datetime
        })

    json = property(get_data_json)
