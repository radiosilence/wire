import redis, json
from wire.utils.redis import autoinc
from wire.models.user import User
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
            limit = start+limit

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

    def add_comment(self, message):
        if not self.key:
            raise EventMustLoadError()
        r = self.redis
        if len(message) < 1:
            raise EventCommentError("Message must be at least one character.")
        comment_id = autoinc(r, 'comment')
        r.set('comment:%s' % comment_id, json.dumps({
            'user': self.user.key,
            'text': message,
            'date': self.date
        }))
        r.lpush('event:%s:comments' % self.key, comment_id)

    def del_comment(self, comment_id):
        r = self.redis
        r.lrem('event:%s:comments' % self.key, comment_id, 0)
        r.delete('comment:%s' % comment_id)
    
    def comment_user(self, comment_id):
        r = self.redis
        c = json.loads(r.get('comment:%s' % comment_id))
        return c['user']

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

    def _reload_comments(self):
        r = self.redis
        self.comments_count = r.llen('event:%s:comments' % self.key)
        for key in r.lrange('event:%s:comments' % self.key, 0, -1):
            comment = json.loads(r.get('comment:%s' % key))
            u = User(redis=self.redis)
            u.load(comment['user'])
            comment['user'] = u
            comment['date_date'] = comment['date'][:10]
            comment['date_time'] = comment['date'][11:16]
            comment['key'] = key
            self.comments.append(comment)

    def load_attendees(self):
        r = self.redis
        for key in r.lrange('event:%s:attendees' % self.key):
            u = User(redis=self.redis)
            u.load(key)
            self.attendees.append(u)
        self._load_attendees_count()

    def load_maybes(self):
        r = self.redis
        for key in r.lrange('event:%s:maybes' % self.key):
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