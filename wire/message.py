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
        self.recipients = False
        self.date = str(datetime.now())
        self.status = False
        self.encrypted = False
        self.decrypted = False
        if key:
            self.load()

    def send(self):
        r = self.redis
        self._validate()

        if not self.key:
            self.key = autoinc(self.redis, 'message')
        
        data = {
            'sender': self.user.username,
            'date': self.date,
            'content': self.data['content'],
            'thread': self.thread,
        }

        try:
            if len(self.data['encryption_key']) >= 8:
                data['content'] = encrypt(self.data['encryption_key'], data['content'])
                self.encrypted = True
                data['encrypted'] = True
            if len(self.data['destruct_key']) > 0 and data['encrypted']:
                h = Hasher(2)
                data['destruct_key'] = h.hash(self.data['destruct_key'])
        except KeyError:
            pass
        r.set('message:%s' % self.key, json.dumps(data))

    def delete(self):
        r = self.redis
        r.delete('message:%s' % self.key)

    def update(self, data, new=False):
        fields = [
            'date',
            'content',
            'encryption_key',
            'destruct_key',
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
        try:
            if len(self.data['encryption_key']) > 0 and len(self.data['encryption_key']) < 8:
                errors.append('Crypto Key must be at least eight characters.')
        except KeyError:
            pass
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
            self.encrypted = True
            self.decrypted = False
        except KeyError:
            self.encrypted = False
    
    def decrypt(self, encryption_key):
        try:
            h = Hasher()
            h.check(encryption_key, self.data['destruct_key'])
            self.delete()
        except (KeyError, HashMismatch):
            pass
        
        try:
            self.data['content'] = decrypt(encryption_key, self.data['content'])
        except TypeError:
            print "WHY DOES THIS HAPPEN?"
        self.decrypted = True
        self.encrypted = True
        
    def encrypt(self, encryption_key):
        self.data['content'] = encrypt(encryption_key, self.data['content'])
        self.decrypted = False
        self.encrypted = True

class ValidationError(Exception):
    pass

class InvalidRecipients(Exception):
    pass

class MessageError(Exception):
    pass