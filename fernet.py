import base64
import hmac as HMAC
import time
# python 3.4 added built in pbkdf2
from hashlib import sha256 as SHA256, pbkdf2_hmac
import os
import struct

from pyaes import AESModeOfOperationCBC, Encrypter


class Fernet:
    """Pure python Ferent module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes.")

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        encrypter = Encrypter(AESModeOfOperationCBC(self._encryption_key, iv))
        ciphertext = encrypter.feed(data)
        ciphertext += encrypter.feed()

        basic_parts = (b"\x80" + struct.pack(">Q", current_time)
                       + iv + ciphertext)

        hmac = HMAC.new(self._signing_key, digestmod='sha256')
        hmac.update(basic_parts)

        return base64.urlsafe_b64encode(basic_parts + hmac.digest())

