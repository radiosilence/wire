import copy
import json
import re

from datetime import datetime, time, date

from wire.utils import autoinc
from wire.utils import Hasher

class Contacts:
    def __init__(self, redis=False, user=False):
        self.user = user
        self.redis = redis
        self.key = 'user:%s:contacts' % user.key
        self.contacts = []
        self._update()

    def _update(self):
        self.contacts = [c.decode("UTF-8") 
            for c in self.redis.lrange(self.key, 0, -1)]

    def add(self, username):
        r = self.redis
        if username in self.contacts:
            raise ContactExistsError()
        if not r.exists('username:%s' % username):
            raise ContactInvalidError()
        r.lpush('user:%s:followers' %
            self.contact_key(username), self.user.key)

        r.lpush(self.key, username)
        self.redis.sort(self.key, alpha=True, store=self.key)
        self._update()

    def contact_key(self, username):
        return self.redis.get('username:%s' % username)

    def delete(self, contact):
        r = self.redis
        r.lrem(self.key, contact, 0)
        r.lrem('user:%s:followers' %
            self.contact_key(contact), self.user.key, 0)
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




class Event:
    def __init__(self, redis=False, user=False):
        self.redis = redis
        self.user = user
        self.data = {
            'image': 'default.png'
        }
        self.date = str(datetime.now())
        self.validation_errors = []
        self.key = False
        self.comments = []
        self.comment_count = 0
        self.attendees = []
        self.attendees_count = 0
        self.maybes = []
        self.maybes_count = 0
        self.creator = User(redis=redis)
        self.conversation_id = None

    def list(self, limit=-1, start=0):
        if limit > 0:
            limit = start + limit

        keys = self.redis.lrange('_list:events', start, limit)
        count = self.redis.llen('_list:events')
        events = []
        for key in keys:
            e = Event(redis=self.redis, user=self.user)
            e.load(key)
            events.append(e)
        return events, count

    def update(self, data):
        form_fields = [
            'name',
            'date',
            'time',
            'location',
            'meeting_place',
            'description',
        ]
        for field in form_fields:
            try:
                self.data[field] = data[field]
            except KeyError:
                self.data[field] = ""

    def save(self):
        r = self.redis
        self._validate()

        if not self.key:
            self.data['creator'] = self.user.username
            self.key = autoinc(self.redis, 'event')
            r.lpush('_list:events', self.key)
            r.lpush('user:%s:events' % self.user.key, self.key)
        if len(self.data['location']) < 1:
            self.data['location'] = 'Undisclosed Location'
        self._load_creator()
        self.data['conversation'] = self.conversation
        r.set('event:%s' % self.key, json.dumps(self.data))

    def _load_creator(self):
        self.creator.load_by_username(self.data['creator'])

    def add_comment(self, message, respond=None):
        if not self.key:
            raise EventMustLoadError()
        r = self.redis

        if len(message) < 1:
            raise EventCommentError("Message must be at least one character.")

        u = Update(text=message, user=self.user, redis=r,
            respond=respond, event=self.key, conversation=self.conversation)
        u.save()

    def del_comment(self, comment_id):
        r = self.redis

        u = Update(user=self.user, redis=r)
        u.load(comment_id)
        u.delete()

    def comment_user(self, comment_id):
        c = Update(redis=self.redis, user=self.user)
        c.load(comment_id)
        return c.user

    def load(self, event_id):
        r = self.redis

        if r.exists('event:%s' % event_id):
            self.key = event_id
            self.data = json.loads(r.get('event:%s' % self.key))
        else:
            raise EventNotFoundError()

        try:
            self.conversation_id = self.data['conversation']
        except KeyError:
            self.conversation_id = self.conversation

        if len(self.data['meeting_place']) > 0:
            self.show_meeting_place = True
        else:
            self.show_meeting_place = False

        self._load_attendees_count()
        self._load_maybes_count()
        self._reload_comments()
        self._load_creator()

    def delete(self):
        r = self.redis
        r.lrem('_list:events', self.key, 0)
        self.load_attendees()
        self.load_maybes()

        for attendee in self.attendees:
            r.lrem('user:%s:attending' % attendee.key, self.key, 0)

        for maybe in self.maybes:
            r.lrem('user:%s:maybe' % maybe.key, self.key, 0)

        r.delete('event:%s' % self.key)
        r.delete('event:%s:attendees' % self.key)
        r.delete('event:%s:maybes' % self.key)

    def _reload_comments(self):
        r = self.redis
        k = 'conversation:%s' % self.conversation
        self.comments_count = r.llen(k)
        for key in r.lrange(k, 0, -1):
            try:
                c = Update(redis=r, user=self.user)
                c.load(key)
                self.comments.append(c)
            except UpdateError:
                r.delete(k, key, 0)

    def load_attendees(self):
        r = self.redis
        for key in r.lrange('event:%s:attendees' % self.key, 0, -1):
            u = User(redis=self.redis)
            u.load(key)
            self.attendees.append(u)
        self._load_attendees_count()

    def load_maybes(self):
        r = self.redis
        for key in r.lrange('event:%s:maybes' % self.key, 0, -1):
            u = User(redis=self.redis)
            u.load(key)
            self.maybes.append(u)
        self._load_maybes_count()

    def set_attending(self):
        if self.user.get_event_state(self.key) == 'attending':
            return False
        r = self.redis
        r.lpush('event:%s:attendees' % self.key, self.user.key)
        r.lrem('event:%s:maybes' % self.key, self.user.key, 0)
        self.user.set_attending(self.key)

    def set_unattending(self):
        if self.user.get_event_state(self.key) == 'unattending':
            return False
        r = self.redis
        r.lrem('event:%s:attendees' % self.key, self.user.key, 0)
        r.lrem('event:%s:maybes' % self.key, self.user.key, 0)
        self.user.set_unattending(self.key)

    def set_maybe(self):
        if self.user.get_event_state(self.key) == 'maybe':
            return False
        r = self.redis
        r.lpush('event:%s:maybes' % self.key, self.user.key)
        r.lrem('event:%s:attendees' % self.key, self.user.key, 0)
        self.user.set_maybe(self.key)

    def _load_attendees_count(self):
        self.attendees_count = self.redis.llen('event:%s:attendees' % self.key)

    def _load_maybes_count(self):
        self.maybes_count = self.redis.llen('event:%s:maybes' % self.key)

    def _validate(self):
        if len(self.data['name']) < 1:
            self.validation_errors.append("Event name must be set.")
        try:
            t = self.data['time'].split(':')
            time(int(t[0]), int(t[1]))
        except ValueError:
            self.validation_errors.append("Time must be valid 24 hour time.")

        try:
            d = self.data['date'].split('-')
            date(int(d[0]), int(d[1]), int(d[2]))
        except ValueError:
            self.validation_errors.append("Date must be a real date.")

        if len(self.validation_errors) > 0:
            raise EventValidationError()

    def get_conversation(self):
        if not self.conversation_id:
            self.conversation_id = autoinc(self.redis, 'conversation')
            self.save()
        return self.conversation_id

    conversation = property(get_conversation)


class EventNotFoundError(Exception):
    pass


class EventValidationError(Exception):
    pass


class EventCommentError(Exception):
    pass


class EventMustLoadError(Exception):
    pass


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




class Message:
    def __init__(self, redis, key=False, user=False):
        self.id = ""
        self.redis = redis
        self.key = key
        self.thread = False
        self.data = {}
        self.user = user
        self.recipient_usernames = []
        self.recipients = False
        self.date = str(datetime.now())
        self.status = False
        if key:
            self.load()

    def get_key(self):
        if not self.key:
            self.key = autoinc(self.redis, 'message')
        return self.key

    def send(self):
        r = self.redis
        self._validate()

        self.get_key()

        data = {
            'sender': self.user.username,
            'date': self.date,
            'content': self.data['content'],
            'thread': self.thread,
        }

        r.set('message:%s' % self.key, json.dumps(data))

    def delete(self):
        r = self.redis
        r.delete('message:%s' % self.key)

    def update(self, data, new=False):
        fields = [
            'date',
            'content',
            'self_destruct',
            'destruct_cascade'
        ]

        for field in fields:
            try:
                self.data[field] = data[field]
            except KeyError:
                pass

    def _validate(self):
        errors = []
        if len(self.data['content']) < 1:
            errors.append('Message must be set.')
        if len(errors) > 0:
            self.validation_errors = errors
            raise MessageValidationError()

    def load(self, key=False):
        if key:
            self.key = key
        if not self.redis.exists('message:%s' % self.key):
            raise MessageError("404, message %s not found." % self.key)
        m = self.redis.get('message:%s' % self.key)
        self.data = json.loads(m)
        self.thread = self.data['thread']
        sender = User(redis=self.redis)
        sender.load_by_username(self.data['sender'])
        self.sender = sender
        self.data['date_date'] = self.data['date'][:10]
        self.data['date_time'] = self.data['date'][11:16]


class MessageValidationError(Exception):
    pass


class MessageError(Exception):
    pass




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


class Thread:
    def __init__(self, subject=False, redis=False, user=False):
        self.messages = []
        self.queued_messages = []
        self.redis = redis
        self.subject = subject
        self.recipients = []
        self.recipient_usernames = []
        self.user = user
        self.key = False
        self.unread_count = 0
        self.encryption = None

    def get_unread_count(self, key=False):
        if not key:
            key = self.key
        try:
            count = int(self.redis.get('user:%s:thread:%s:unreads' % \
                (self.user.key, key)))
        except TypeError:
            count = 0
        self.unread_count = count
        return count

    def get_form_recipients(self):
        result = []
        for recipient in self.recipient_usernames:
            if recipient != self.user.username:
                result.append(recipient)
        return result

    def reset_unread_count(self):
        self.redis.set('user:%s:thread:%s:unreads' % \
            (self.user.key, self.key), 0)

    def _update_recipients(self):
        r = self.redis
        self.recipients = []
        self.recipients = r.lrange('thread:%s:recipients' % self.key, 0, -1)
        self.recipient_usernames = []
        for rec in self.recipients:
            try:
                self.recipient_usernames.append(json.loads( \
                    r.get('user:%s' % rec) \
                    )['username'])
            except TypeError:
                r.lrem('thread:%s:recipients' % self.key, rec, 0)

    def set_recipients(self, recipients):
        self.recipients = recipients
        self.recipients.append(self.user.key)

    def parse_recipients(self, usernames):
        usernames = [s.strip() for s in usernames.split(",")]
        self.invalid_recipients = []
        if len(usernames) < 1:
            raise Exception("No users.")
        for recipient in usernames:
            if self.redis.exists('username:%s' % recipient):
                user_key = self.redis.get('username:%s' % recipient)
                if user_key not in self.recipients:
                    self.recipients.append(user_key)

            elif len(recipient) > 0:
                self.invalid_recipients.append(recipient)

        if self.user.key not in self.recipients:
            self.recipients.append(self.user.key)
        self.recipient_usernames.extend(usernames)

        if len(self.invalid_recipients) > 0:
            raise InvalidRecipients()

    def _validate(self):
        errors = []
        if len(self.data['subject']) < 1:
            errors.append('Subject must be set.')
        if len(errors) > 0:
            self.validation_errors = errors
            raise ValidationError()

    def _sync_recipients(self):
        r = self.redis
        new_recipients = copy.deepcopy(self.recipients)
        self._update_recipients()
        for recipient in new_recipients:
            if recipient not in self.recipients:
                r.rpush('thread:%s:recipients' % self.key, recipient)
                r.lpush('user:%s:threads' % recipient, self.key)
                r.incr('user:%s:thread:%s:unreads' % \
                    (recipient, self.key), len(self.messages))

        del new_recipients

    def save(self):
        r = self.redis
        if not self.key:
            self.key = autoinc(self.redis, 'thread')

        data = {
            'subject': self.subject,
            'encryption': self.encryption
        }

        r.set('thread:%s:data' % self.key, json.dumps(data))

        self._sync_recipients()
        for message in self.queued_messages:
            self._commit_message(message)

    def add_message(self, m):
        m.get_key()
        if len(self.messages) == 0:
            self.save()

        if self.key:
            m.thread = self.key
            self.messages.append(m)
            self._commit_message(m)
        else:
            self.queued_messages.append(m)

    def _commit_message(self, message):
        self.redis.rpush('thread:%s:messages' % self.key, message.get_key())
        self._incr_unreads()

    def _incr_unreads(self):
        for recipient in self.recipients:
            if recipient != self.user.key:
                self.redis.incr('user:%s:thread:%s:unreads' \
                    % (recipient, self.key))

    def delete_message(self, message):
        r = self.redis
        r.lrem('thread:%s:messages' % self.key, message.key, 0)
        self.messages = r.lrange('thread:%s:messages' % self.key, 0, -1)
        if not self.messages or len(self.messages) < 1:
            self.delete()

    def load(self, key):
        self.messages = []
        self.key = key
        message_keys = self.redis.lrange('thread:%s:messages' % key, 0, -1)
        self._update_recipients()
        data = self.redis.get('thread:%s:data' % key)
        if not data:
            raise ThreadError("Thread %s data doesn't exist." % self.key)
        data = json.loads(data)
        self.subject = data['subject']
        try:
            self.encryption = data['encryption']
        except KeyError:
            self.encryption = 'plain'
        for message_key in message_keys:
            m = Message(redis=self.redis, user=self.user)
            try:
                m.load(message_key)
            except MessageError:
                pass
            self.messages.append(m)
        if len(self.messages) < 1:
            self.delete()
            raise DestroyedThreadError
        try:
            self.sender = self.messages[0].data['sender']
        except KeyError:
            self.delete_message(self.messages[0])

    def delete(self, recipient=False):
        r = self.redis
        if recipient:
            r.lrem('user:%s:threads' % recipient.key, self.key, 0)
        if self.recipients:
            for recipient_key in self.recipients:
                r.lrem('user:%s:threads' % recipient_key, self.key, 0)
                r.delete('user:%s:thread:%s:unreads' % \
                    (recipient_key, self.key))

        [m.delete() for m in self.messages]

        r.delete('thread:%s:data' % self.key)
        r.delete('thread:%s:recipients' % self.key)
        r.delete('thread:%s:messages' % self.key)

    def unsubscribe(self):
        r = self.redis
        r.lrem('thread:%s:recipients' % self.key, self.user.key, 0)
        r.lrem('user:%s:threads' % self.user.key, self.key, 0)
        self._update_recipients()
        if len(self.recipients) < 1:
            self.delete()


class DestroyedThreadError(Exception):
    pass


class ThreadError(Exception):
    pass


class ValidationError(Exception):
    pass


class InvalidRecipients(Exception):
    pass
