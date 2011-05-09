#!/usr/bin/env python

# Thanks to MostAwesomeDude at irc.freenode.net/#python

from base64 import b64encode, b64decode
from os import urandom
import math
import whirlpool
from binascii import b2a_hex
class Hasher:
    def __init__(self, strength=16):
        self._strength = strength

    def hash(self, password, salt=False):
        if salt is False:
            salt = b64encode(urandom(32))
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

