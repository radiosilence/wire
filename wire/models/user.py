from wire.utils.redis import autoinc
import json
from wire.utils.hasher import Hasher
from wire.models.contacts import Contacts
from datetime import datetime
import re


class User:
    def __init__(self, data={}, redis=False, key=False):
        if not redis:
            raise Exception("User must have redis object passed to it.")
        self.redis = redis
        self.key = key
        self.data = {}
        self.threads = []
        self.avatar = 'default.png'
        self._updating_password = False

    def load_by_username(self, username):
        self.load(self.redis.get('username:%s' % username))

    def update(self, data, new=False):
        fields = [
            'username',
            'password',
            'password_confirm'
        ]

        for field in fields:
            try:
                self.data[field] = data[field]
            except KeyError:
                self.data[field] = ""

        if new:
            try:
                self.username = data['username']
            except KeyError:
                self.username = ""

    def get_threads(self):
        threads = self.redis.lrange('user:%s:threads' % self.key, 0, -1)
        self.threads = threads
        return threads

    def reset_mentions(self):
        self.redis.set('user:%s:mentions:unread' % self.key, 0)

    def get_unread_mentions(self):
        k = 'user:%s:mentions:unread' % self.key
        r = self.redis
        if not r.exists(k):
            r.set(k, 0)
            return 0
        return int(self.redis.get(k))

    unread_mentions = property(get_unread_mentions)

    def save(self):
        self._validate()
        h = Hasher()

        if len(self.data['password']) >= 6:
            self.password = h.hash(self.data['password'])
        del self.data['password_confirm']

        if not self.key:
            self.key = autoinc(self.redis, 'user')
            self.redis.lpush("list:users", self.key)
            self.redis.lpush("list:usernames", self.username)

        self.redis.set("username:%s" % self.username, self.key)
        self.redis.set("user:%s" % self.key, json.dumps({
            'username': self.username,
            'password': self.password,
            'avatar': self.avatar
        }))

    def _validate(self):
        errors = []
        if len(self.username) < 1:
            errors.append("Username must be one character or longer.")

        for c in [
            ('\s', 'space'), ('\#', 'hash'), ('@', '@'), ('\/', 'slash')
        ]:
            if re.search(c[0], self.username):
                errors.append("Username must not have a %s in it." % c[1])

        if not self.key:
            try:
                self._test_unique_user()
            except UserExists:
                errors.append("User exists.")

        if len(self.data['password']) < 6 and \
            (len(self.data['password']) > 0 or not self.key):
            errors.append("Password must be at least 6 characters.")

            try:
                if self.data['password'] != self.data['password_confirm']:
                    errors.append("Passwords must match.")
            except KeyError:
                pass

        if len(errors) > 0:
            self.validation_errors = errors
            raise UserValidationError()

    def _test_unique_user(self):
        if self.redis.exists("username:" + self.username):
            raise UserExists()

    def load(self, key):
        if not self.redis.exists('user:%s' % key):
            raise UserNotFoundError
        self.key = key
        data = json.loads(self.redis.get('user:%s' % key))
        self.data = data
        self.password = data['password']
        self.username = data['username']
        if len(data['avatar']) > 0:
            self.avatar = data['avatar']
        else:
            self.avatar = 'default.png'

    def set_attending(self, event_id):
        r = self.redis
        r.lpush('user:%s:attending' % self.key, event_id)
        r.lrem('user:%s:maybe' % self.key, event_id, 0)

    def set_maybe(self, event_id):
        r = self.redis
        r.lpush('user:%s:maybe' % self.key, event_id)
        r.lrem('user:%s:attending' % self.key, event_id, 0)

    def set_unattending(self, event_id):
        r = self.redis
        r.lrem('user:%s:attending' % self.key, event_id, 0)
        r.lrem('user:%s:maybe' % self.key, event_id, 0)

    def get_event_state(self, event_id):
        r = self.redis
        event_id = str(event_id)
        print r.lrange('user:%s:attending' % self.key, 0, -1), event_id
        print event_id in r.lrange('user:%s:attending' % self.key, 0, -1)
        if event_id in r.lrange('user:%s:attending' % self.key, 0, -1):
            return 'attending'
        elif event_id in r.lrange('user:%s:maybe' % self.key, 0, -1):
            return 'maybe'
        else:
            return 'unattending'

    def get_contacts(self):
        c = Contacts(redis=self.redis, user=self)
        return c.contacts

    contacts = property(get_contacts)

    def get_followers(self):
        r = self.redis
        followers = []
        for follower in r.lrange('user:%s:followers' % self.key, 0, -1):
            u = User(redis=self.redis)
            u.load(follower)
            followers.append(u)
        return followers

    followers = property(get_followers)

    def get_timeline(self):
        t = Timeline(redis=self.redis, user=self)
        return t

    timeline = property(get_timeline)

    def get_mentions(self):
        t = Timeline(redis=self.redis, user=self, type='mentions')
        return t

    mentions = property(get_mentions)

    def get_posted(self):
        t = Timeline(redis=self.redis, user=self, type='updates')
        return t

    posted = property(get_posted)


class UserValidationError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class UserExists(Exception):
    pass


class Update:
    def __init__(self, text=None, redis=None,
        user=None, key=None, respond="", event=None, conversation=None):

        self.key = key
        self.redis = redis
        self.user = user
        self.mentions = []
        self.hashes = []
        self.data = {}
        self.datetime = str(datetime.now())
        self.conversation = conversation
        if respond:
            if len(respond) > 0:
                self.respond = int(respond)
            else:
                self.respond = None
        else:
            self.respond = None

        self.done_keys = []
        self.text = text
        self.event = event
        if self.text:
            self.parse(text)
        if self.key:
            self.load(key)

    def save(self):
        r = self.redis
        if not self.key:
            self.key = autoinc(r, 'update')

        self._get_conversation()

        r.set('update:%s' % self.key, self.json)

        if self.event:
            self._update_event()
        else:
            self._update_followers()
            self._update_timeline()
        self._update_conversation()
        self._update_mentions()

    def load(self, key):
        r = self.redis

        if not r.exists('update:%s' % key):
            raise UpdateError()

        self.key = key
        data = json.loads(r.get('update:%s' % self.key))

        self.hashes = data['hashes']
        self.text = data['text']
        u = User(redis=self.redis)
        u.load_by_username(data['username'])
        self.user = u
        try:
            self.event = data['event']
            if self.event:
                self.data['event_name'] = json.loads(
                    r.get('event:%s' % self.event))['name']
        except KeyError:
            self.event = None
        self.mentions = data['mentions']
        self.respond = data['respond']
        try:
            self.conversation = data['conversation']
        except KeyError:
            self.conversation = None
        self.datetime = data['datetime']
        self.data['date'] = self.datetime[:10]
        self.data['time'] = self.datetime[11:16]

    def delete(self):
        r = self.redis
        if not self.key:
            return None

        if self.event:
            self._del_event()
        else:
            self._del_followers()
            self._del_timeline()
        self._del_mentions()
        self._del_conversation()

        r.delete('update:%s' % self.key)

    def _del_event(self):
        self.redis.lrem('event:%s:comments' % self.event, self.key, 0)

    def _del_followers(self):
        r = self.redis
        for follower in self.user.followers:
            r.lrem('user:%s:timeline' % follower.key, self.key, 0)

    def _del_mentions(self):
        r = self.redis
        for mentionee in self.mentions:
            key = r.get('username:%s' % mentionee)
            r.lrem('user:%s:timeline' % key, self.key, 0)
            r.lrem('user:%s:mentions' % key, self.key, 0)

    def _del_timeline(self):
        r = self.redis
        r.lrem('user:%s:timeline' % self.user.key, self.key, 0)
        r.lrem('user:%s:updates' % self.user.key, self.key, 0)

    def _del_conversation(self):
        r = self.redis
        r.lrem('conversation:%s' % self.conversation, self.key, 0)

    def parse(self, text):
        for match in re.finditer('(#[^\s]+)', text):
            self.hashes.append(match.group(0)[1:])
        for match in re.finditer('(@[^\s]+)', text):
            self.mentions.append(match.group(0)[1:])

    def _update_event(self):
        self.redis.lpush('event:%s:comments' % self.event, self.key)

    def _update_conversation(self):
        self.redis.lpush('conversation:%s' % self.conversation, self.key)

    def _get_conversation(self):
        if self.respond:
            u = Update(redis=self.redis, user=self.user)
            u.load(self.respond)
            if u.conversation:
                self.conversation = u.conversation
        if not self.conversation:
            self.conversation = autoinc(self.redis, 'conversation')

    def _update_followers(self):
        r = self.redis
        for follower in self.user.followers:
            if follower.key == self.user.key:
                continue
            if follower.key in self.done_keys:
                continue
            self.done_keys.append(follower.key)
            r.lpush('user:%s:timeline' % follower.key, self.key)

    def _update_mentions(self):
        r = self.redis
        for mentionee in self.mentions:
            key = r.get('username:%s' % mentionee)
            if not key:
                continue
            if key in self.done_keys:
                continue
            self.done_keys.append(key)
            r.lpush('user:%s:mentions' % key, self.key)
            r.incr('user:%s:mentions:unread' % key)
            if key == self.user.key:
                continue

            r.lpush('user:%s:timeline' % key, self.key)

    def _update_timeline(self):
        r = self.redis
        r.lpush('user:%s:timeline' % self.user.key, self.key)
        r.lpush('user:%s:updates' % self.user.key, self.key)

    def get_data_json(self):
        return json.dumps({
            'username': self.user.username,
            'text': self.text,
            'mentions': self.mentions,
            'hashes': self.hashes,
            'respond': self.respond,
            'datetime': self.datetime,
            'conversation': self.conversation,
            'event': self.event
        })

    json = property(get_data_json)


class UpdateError(Exception):
    pass


class Timeline:
    def __init__(self, redis=None, user=None, type='timeline'):
        self.redis = redis
        self.user = user
        self.type = type
        self.update_cache = []
        self.update_keys = []

    def add(self, update):
        if update.key not in self.update_keys:
            self.update_cache.append(update)
            self.update_keys.append(update.key)

    def rebuild(self):
        self.update_cache = []
        self.update_keys = []
        for contact in self.user.contacts:
            u = User(redis=self.redis)
            u.load_by_username(contact)
            for update in u.posted.updates:
                self.add(update)

        for update in self.user.mentions.updates:
            self.add(update)
        for update in self.user.posted.updates:
            self.add(update)
        self.update_cache = sorted(self.update_cache,
            key=lambda x: int(x.key), reverse=True)
        self.save_rebuilt()

    def save_rebuilt(self):
        r = self.redis
        r.delete('user:%s:timeline' % self.user.key)
        for update in self.update_cache:
            r.rpush('user:%s:timeline' % self.user.key, update.key)

    def get_updates(self):
        r = self.redis
        updates = []
        for update in r.lrange('user:%s:%s' %
                (self.user.key, self.type), 0, -1):
            u = Update(redis=self.redis, key=update, user=self.user)
            updates.append(u)
        return updates

    updates = property(get_updates)
