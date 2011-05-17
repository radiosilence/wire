from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from base64 import b64encode, b64decode
from hasher import Hasher

def encrypt(key, data):
    key, data = key.encode("UTF-8"), data.encode("UTF-8")
    ctr = Counter.new(128)
    key, salt = _derive_key(key)
    iv = get_random_bytes(16)
    aes = AES.new(key, AES.MODE_CTR, iv, counter=ctr)
    msg = iv + aes.encrypt(data)
    mac = HMAC.new(key, msg)
    msg = msg + mac.digest()
    msg = salt + msg
    return b64encode(msg)

def decrypt(key, data):
    key, data = key.encode("UTF-8"), data.encode("UTF-8")
    ctr = Counter.new(128)
    msg = b64decode(data)
    salt = msg[:32]
    msg = msg[32:]
    key, _ = _derive_key(key, salt=salt)
    iv = msg[:16]
    mac_offset = len(msg) - 16
    extracted_mac = msg[mac_offset:]
    msg = msg[16:len(msg) - 16]
    new_mac = HMAC.new(key, iv + msg).digest()
    if extracted_mac != new_mac:
        raise DecryptFailed()
    aes = AES.new(key, AES.MODE_CTR, iv, counter=ctr)
    return aes.decrypt(msg)

def _derive_key(key, salt=get_random_bytes(32)):
    h = Hasher(10)
    return h.hash(key, salt)[-32:], salt


class DecryptFailed(Exception):
    pass

if __name__ == '__main__':
    enc = encrypt("moo", "LOREM")
    print enc
    dec = decrypt("moo", enc)
    print dec
    dec = decrypt("maoo", enc)
    print dec


