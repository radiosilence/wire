from wire.message import Message, MessageError, DestructKey
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
        self.unread_count = 0

    def get_unread_count(self, key=False):
        if not key:
            key = self.key
        try:
            count = int(self.redis.get('user:%s:thread:%s:unreads' % (self.user.key, key)))
        except TypeError:
            count = 0
        self.unread_count = count
        return count

    def reset_unread_count(self):
        self.redis.set('user:%s:thread:%s:unreads' % (self.user.key, self.key), 0)
            
    def set_recipients(self, recipients):
        self.recipients = recipients
        self.recipients.append(self.user.key)

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

        self.recipients.append(self.user.key)
    
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
            self._commit_message(message)
    
    def add_message(self, m):
        if len(self.messages) == 0:
            self.encrypted = m.encrypted
            self.save()
        elif self.encrypted != m.encrypted:
            raise ThreadError("Messages in same thread must have same encryption.")
    
        if self.key:
            self.messages.append(m)
            self._commit_message(m)
        else:
            self.queued_messages.append(m)

    def _commit_message(self, message):
        self.redis.rpush('thread:%s:messages' % self.key, message.key)
        self._incr_unreads()
        
    def _incr_unreads(self):
        for recipient in self.recipients:
            if recipient != self.user.key:
                self.redis.incr('user:%s:thread:%s:unreads' % (recipient, self.key))

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
        self.recipients = self.redis.lrange('thread:%s:recipients' % key, 0, -1)
        data = self.redis.get('thread:%s:data' % key)
        if not data:
            raise ThreadError("Thread %s data doesn't exist." % self.key)
        data = json.loads(data)
        self.subject = data['subject']
        self.encrypted = data['encrypted']
        if self.encrypted:
            self.decrypted = False
        for message_key in message_keys:
            m = Message(redis=self.redis, user=self.user)
            m.load(message_key)
            self.messages.append(m)


        self.sender = self.messages[0].data['sender']

    def delete(self, recipient=False):
        r = self.redis
        print "deleting thread", self.key
        if recipient:
            r.lrem('user:%s:threads' % recipient.key, self.key, 0)
        if self.recipients:
            for recipient_key in self.recipients:
                print "deleting thread", self.key, "from ", recipient_key
                r.lrem('user:%s:threads' % recipient_key, self.key, 0)
                r.delete('user:%s:thread:%s:unreads' % (recipient_key, self.key))

        r.delete('thread:%s:data' % self.key)
        r.delete('thread:%s:recipients' % self.key)
        r.delete('thread:%s:messages' % self.key)


    def decrypt(self, encryption_key):
        for message in self.messages:
            try:
                message.decrypt(encryption_key)
            except DestructKey:
                self.delete_message(message)
                raise DestroyedThreadError()

        self.decrypted = True

class DestroyedThreadError(Exception):
    pass
class ThreadError(Exception):
    pass
class ValidationError(Exception):
    pass

class InvalidRecipients(Exception):
    pass
