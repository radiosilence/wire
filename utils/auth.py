import json
from utils.hasher import Hasher, HashMismatch
from user import User

class Auth:
    def __init__(self, redis):
        self.redis = redis
        self.user = False
    def attempt(self, username, password):
        r = self.redis
        h = Hasher()
        if not r.exists('usernames:%s' % username):
            raise AuthError()

        key = r.get('usernames:%s' % username)
        data = json.loads(r.get('users:%s' % key))
        try:
            h.check(password, data['password'])
        except HashMismatch:
            raise AuthError()
        self.user = User(data=data, redis=r, key=key)
    def set_user(self, user):
        self.user = user

class AuthError(Exception):
    pass