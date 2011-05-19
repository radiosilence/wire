import redis
from wire.utils.redis import autoinc
import json
from datetime import datetime
from wire.utils.crypto import encrypt, decrypt, DecryptFailed
from wire.utils.hasher import Hasher, HashMismatch
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
        self.encrypted = False
        self.decrypted = False
        self.enc_data = {}
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
            'encrypted': self.enc_data['encrypted'],
        }
        try:
            data['destruct_key'] = self.enc_data['destruct_key']
        except KeyError:
            data['destruct_key'] = False

        r.set('message:%s' % self.key, json.dumps(data))

    def _try_encrypt(self):
        try:
            if len(self.data['encryption_key']) >= 6:
                self.data['content'] = encrypt(self.data['encryption_key'], self.data['content'])
                self.encrypted = True
                self.enc_data['encrypted'] = True
            else: 
                raise KeyError()
            if len(self.data['destruct_key']) > 0 and data['encrypted']:
                h = Hasher(4)
                self.enc_data['destruct_key'] = h.hash(self.data['destruct_key'])

        except KeyError:
            self.enc_data['encrypted'] = False

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
        self._try_encrypt()

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

        try: 
            self.data['encrypted']
            self.encrypted = True
            self.decrypted = False
        except KeyError:
            self.encrypted = False
    
    def decrypt(self, encryption_key):
        if self.data['destruct_key']:
            try:
                h = Hasher()
                h.check(encryption_key, self.data['destruct_key'])
                raise DestructKey()
            except (KeyError, HashMismatch):
                pass
        try:
            self.data['content'] = decrypt(encryption_key, self.data['content']).decode("UTF-8")
        except TypeError:
            pass
        self.decrypted = True
        self.encrypted = True
        
    def encrypt(self, encryption_key):
        self.data['content'] = encrypt(encryption_key, self.data['content'])
        self.decrypted = False
        self.encrypted = True

class MessageValidationError(Exception):
    pass

class MessageError(Exception):
    pass

class DestructKey(DecryptFailed):
    pass