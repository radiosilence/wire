import redis
from wire.utils.redis import autoinc
import json
from datetime import datetime
from wire.utils.crypto import encrypt, decrypt
from wire.utils.hasher import Hasher, HashMismatch

class Message:
    def __init__(self, redis, key=False, user=False):
        self.id = ""
        self.redis = redis
        self.key = key
        self.thread = False
        self.data = {}
        self.user = user
        self.recipient_usernames = []
        self.date = str(datetime.now())
        self.status = False
        if key:
            self.load()

    def send(self):
        r = self.redis
        self._recipient_ids()
        self._validate()
        if not self.thread:
            self.thread = autoinc(self.redis, 'thread')
        if not self.key:
            self.key = autoinc(self.redis, 'message')
        
        data = {
            'sender': self.user.username,
            'date': self.date,
            'subject': self.data['subject'],
            'content': self.data['content'],
            'thread': self.thread
        }

        if len(self.data['encryption_key']) >= 8:
            data['content'] = encrypt(self.data['encryption_key'], data['content'])
            data['encrypted'] = True
        
        if len(self.data['destruct_key']) > 0 and data['encrypted']:
            h = Hasher(2)
            data['destruct_key'] = h.hash(self.data['destruct_key'])

        r.set('message:%s' % self.key, json.dumps(data))

        for recp in self.recipients:
            r.lpush('user:%s:inbox' % recp, self.key)
            r.lpush('user:%s:message:%s:status' % (recp, self.key), 'unread')
            r.incr('user:%s:unread' % recp)
        
        r.lpush('thread:%s' % self.thread, self.key)

    def update(self, data, new=False):
        fields = [
            'date',
            'subject',
            'content',
            'recv',
            'encryption_key',
            'destruct_key',
            'self_destruct',
            'destruct_cascade'
        ]
        self.recipient_usernames = [s.strip() for s in data['recv'].split(",")]
        for field in fields:
            try:
                self.data[field] = data[field]
            except KeyError:
                pass
            
    def delete(self):
        print "cut my life into pieces"

    def _recipient_ids(self):
        self.invalid_recipients = []
        self.recipients = []
        if len(self.recipient_usernames) < 1:
            raise Exception("No users.")
        for recipient in self.recipient_usernames:
            if self.redis.exists('username:%s' % recipient):
                self.recipients.append(self.redis.get('username:%s' % recipient))
            else:
                self.invalid_recipients.append(recipient)
        if len(self.invalid_recipients) > 0:
            raise InvalidRecipients()

    def _validate(self):
        errors = []
        if len(self.data['content']) < 1:
            errors.append('Message must be set.')
        if len(self.data['subject']) < 1:
            errors.append('Subject must be set.')
        if len(self.data['encryption_key']) > 0 and len(self.data['encryption_key']) < 8:
            errors.append('Crypto Key must be at least eight characters.')
        if len(errors) > 0:
            self.validation_errors = errors
            raise ValidationError()
    
    def load(self, key=False):
        if key:
            self.key = key
        if not self.redis.exists('message:%s' % self.key):
            raise MessageError()
        m = self.redis.get('message:%s' % self.key)
        self.data = json.loads(m)
        self.thread = self.data['thread']
        self.sender = self.data['sender']
        try: 
            self.data['encrypted']
            self.decrypted = False
        except KeyError:
            print "plain"
            self.decrypted = True
    
    def decrypt(self, encryption_key):
        try:
            h = Hasher()
            h.check(encryption_key, self.data['destruct_key'])
            self.delete()
        except (KeyError, HashMismatch):
            pass
            
        self.data['content'] = decrypt(encryption_key, self.data['content'])
        self.decrypted = True
        
    def encrypt(self, encryption_key):
        self.data['content'] = encrypt(encryption_key, self.data['content'])
        self.decrypted = False

class ValidationError(Exception):
    pass

class InvalidRecipients(Exception):
    pass

class MessageError(Exception):
    pass