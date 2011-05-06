import redis
from utils.redis import autoinc
import json
from wire.utils.hasher import Hasher

class User:
    def __init__(self, data={}, redis=False, key=False):
        if not redis:
            raise Exception("User must have redis object passed to it.")
        self.redis = redis
        self.key = key
        self.data = {}

    def update(self, data, new=False):  
        fields = [
            'username',
            'avatar',
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

    def save(self):
        self._validate()
        h = Hasher()

        if len(self.data['password']) >= 6:
            self.data['password'] = h.hash(self.data['password'])
        del self.data['password_confirm']

        if len(self.data['avatar']) < 1:
            self.data['avatar'] = 'default.png'

        if not self.key:
            self.key = autoinc(self.redis, 'user')
            self.redis.lpush("list:users", self.key)
            self.redis.lpush("list:usernames", self.username)
                
        self.redis.set("usernames:%s" % self.username, self.key)
        self.redis.set("users:%s" % self.key, json.dumps({
            'username': self.username,
            'password': self.data['password'],
            'avatar': self.data['avatar']
        }))

    def _validate(self):
        errors = []
        if len(self.username) < 1:
            errors.append("Username must be one character or longer.")

        if not self.key:
            try:
                self._test_unique_user()
            except UserExists:
                errors.append("User exists.")
            if len(self.data['password']) < 6:
                errors.append("Password must be at least 6 characters.")

        try:
            if self.data['password'] != self.data['password_confirm']:
                errors.append("Passwords must match.")
        except KeyError:
            pass

        if len(errors) > 0:
            self.validation_errors = errors
            raise ValidationError()

    def _test_unique_user(self):
        if self.redis.exists("usernames:"+self.username):
            raise UserExists()

    def load(self, key):
        if not self.redis.exists('users:%s' % key):
            return False
        self.key = key
        data = json.loads(self.redis.get('users:%s' % key))
        self.data = data
        self.username = data['username']
        if len(data['avatar']) > 0:
            self.avatar = data['avatar']
        else:
            self.avatar = 'default.png'

class ValidationError(Exception):
    pass

class UserExists(Exception):
    pass