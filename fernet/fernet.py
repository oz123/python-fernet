import base64
import hmac as HMAC
from hashlib import sha256 as SHA256
import os



class Fernet:
    """Pure python Ferent module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(key):
        pass

    @classmethod
    def generate_key(cls):
        pass

    def encrypt(self, text):
        pass

    def decrypt(self, cipher):
        pass

