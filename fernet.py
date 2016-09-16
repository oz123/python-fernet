import base64
import binascii
import hmac
import time
import os
import struct
from pyaes import AESModeOfOperationCBC, Encrypter, Decrypter

__all__ = [
    "InvalidSignature",
    "InvalidToken",
    "Fernet"
]
_MAX_CLOCK_SKEW = 60


class InvalidToken(Exception):
    pass


class InvalidSignature(Exception):
    pass


class Fernet:
    """
    Pure python Ferent module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes.")

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes.")

        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        encrypter = Encrypter(AESModeOfOperationCBC(self._encryption_key, iv))
        ciphertext = encrypter.feed(data)
        ciphertext += encrypter.feed()

        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext)

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(basic_parts)

        return base64.urlsafe_b64encode(basic_parts + hmactext.digest())

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or data[0] != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(data[:-32])
        if not hmac.compare_digest(hmactext.digest(), data[-32:]):
            raise InvalidToken

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Decrypter(AESModeOfOperationCBC(self._encryption_key, iv))
        try:
            plaintext = decryptor.feed(ciphertext)
            plaintext += decryptor.feed()
        except ValueError:
            raise InvalidToken

        return plaintext
