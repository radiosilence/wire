from wire.message import Message
import redis, json
from wire.utils.redis import autoinc
class Thread:
    def __init__(self, subject=False, recipients=False, redis=False, user=False):
        self.messages = []
        self.queued_messages = []
        self.redis = redis
        self.subject = subject
        self.recipients = recipients
        self.user = user
        self.key = False
        self.encrypted = False
        self.decrypted = True

    def set_recipients(self, recipients):
        self.recipients = recipients
    def parse_recipients(self, usernames):
        usernames = [s.strip() for s in usernames.split(",")]
        self.invalid_recipients = []
        self.recipients = []
        if len(usernames) < 1:
            raise Exception("No users.")
        for recipient in usernames:
            if self.redis.exists('username:%s' % recipient):
                self.recipients.append(self.redis.get('username:%s' % recipient))
            else:
                self.invalid_recipients.append(recipient)
        if len(self.invalid_recipients) > 0:
            raise InvalidRecipients()
    
    def _validate(self):
        errors = []
        if len(self.data['subject']) < 1:
            errors.append('Subject must be set.')
        if len(errors) > 0:
            self.validation_errors = errors
            raise ValidationError()
    def save(self):
        r = self.redis
        new = False
        if not self.key:
            new = True
            self.key = autoinc(self.redis, 'thread')
        d = {
            'subject': self.subject,
            'encrypted': self.encrypted
        }
        r.set('thread:%s:data' % self.key, json.dumps(d))
        if new:
            for recipient in self.recipients:
                r.lpush('thread:%s:recipients' % self.key, recipient)
                r.lpush('user:%s:threads' % recipient, self.key)
        for message in self.queued_messages:
            self._save_message(message)
    
    def add_message(self, m):
        if len(self.messages) == 0:
            self.encrypted = m.encrypted
            self.save()
            print self.encrypted, m.encrypted, m
        elif self.encrypted != m.encrypted:
            raise ThreadError("Messages in same thread must have same encryption.")
    
        if self.key:
            self.messages.append(m)
            self._save_message(m)
        else:
            self.queued_messages.append(m)

    def _save_message(self, message):
        self.redis.lpush('thread:%s:messages' % self.key, message.key)

    def delete(self):
        pass

    def load(self, key):
        self.messages = []
        self.key = key
        message_keys = self.redis.lrange('thread:%s:messages' % key, 0, -1)
        d = self.redis.get('thread:%s:data' % key)
        d = json.loads(d)
        self.subject = d['subject']
        self.encrypted = d['encrypted']
        if self.encrypted:
            self.decrypted = False
        for message_key in message_keys:
            m = Message(redis=self.redis, user=self.user)
            m.load(message_key)
            self.messages.append(m)
        self.sender = self.messages[0].data['sender']

    def decrypt(self, encryption_key):
        for message in self.messages:
            message.decrypt(encryption_key)
        self.decrypted = True

class ThreadError(Exception):
    pass
class ValidationError(Exception):
    pass
