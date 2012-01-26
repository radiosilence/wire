import json
import math
from base64 import b64encode
from binascii import b2a_hex
from os import urandom

import redis
import whirlpool


class Auth:
    def __init__(self, redis):
        self.redis = redis
        self.user = False

    def attempt(self, username, password):
        from wire.models import User

        r = self.redis
        h = Hasher()
        if not r.exists('username:%s' % username):
            raise AuthError()

        key = r.get('username:%s' % username)
        data = json.loads(r.get('user:%s' % key))
        try:
            h.check(password, data['password'])
        except HashMismatch:
            raise AuthError()
        self.user = User(data=data, redis=r, key=key)
    def set_user(self, user):
        self.user = user

    def action(self, action, id=False):
        pass

class AuthError(Exception):
    pass

class DeniedError(AuthError):
    pass



class Hasher:
    def __init__(self, strength=16):
        self._strength = strength

    def hash(self, password, salt=False, encode=True):
        if salt is False:
            salt = urandom(32)
        if encode:
            salt = b64encode(salt)
        return "$w$%s$%s$%s" % (
            self._strength,
            salt,
            self._hash_multi(salt + password, self._strength)
        )

    def check(self, attempt, h):
        bits = h.split("$")
        try:
            if self._hash_multi(bits[3] + attempt, float(bits[2])) != bits[4]:
                raise HashMismatch()
        except IndexError:
            raise HashMismatch()

    def _hash_multi(self, string, strength):
        for i in range(int(math.pow(2, strength))):
            string = b2a_hex(whirlpool.hash(string))
        return string


class HashMismatch(Exception):
    pass


def autoinc(redis, key):
    key = "_incs:%s" % key
    if not redis.exists(key):
        redis.set(key, 0)

    return redis.incr(key)
