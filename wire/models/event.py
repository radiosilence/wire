import json
from wire.utils.redis import autoinc
from wire.models.user import User, UserNotFoundError, Update, UpdateError
from datetime import datetime


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
            respond=respond, event=self.key)

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
        self.comments_count = r.llen('event:%s:comments' % self.key)
        for key in r.lrange('event:%s:comments' % self.key, 0, -1):
            try:
                c = Update(redis=r, user=self.user)
                c.load(key)
                self.comments.append(c)
            except UpdateError:
                r.delete('event:%s:comments' % self.key, key, 0)

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

        if len(self.validation_errors) > 0:
            raise EventValidationError()


class EventNotFoundError(Exception):
    pass


class EventValidationError(Exception):
    pass


class EventCommentError(Exception):
    pass


class EventMustLoadError(Exception):
    pass
