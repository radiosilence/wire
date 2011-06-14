from wire.utils.redis import autoinc
import json
from datetime import datetime
from wire.models.user import User


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
