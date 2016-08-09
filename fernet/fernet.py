import base64
import hmac as HMAC
import time
# python 3.4 added built in pbkdf2
from hashlib import sha256 as SHA256, pbkdf2_hmac
import os
import struct

from pyaes import AESModeOfOperationCBC


def pkcs7_decode(bytestring, k=16):
    """
    Remove the PKCS#7 padding from a text bytestring.
    # @param bytestring    The padded bytestring for which the padding is to be
    # removed.
    # @param k             The padding block size.
    # @exception ValueError Raised when the input padding is missing or
    corrupt.
    # @return bytestring    Original unpadded bytestring.
    d
    """

    val = bytestring[-1]
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')
    l = len(bytestring) - val
    return bytestring[:l]


def pkcs7_encode(bytestring, k=16):
    """
    Pad an input bytestring according to PKCS#7
    # @param bytestring    The text to encode.
    # @param k             The padding block size.
    # @return bytestring    The padded bytestring.
    """
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)


class Fernet:
    """Pure python Ferent module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes.")

        self._key = key

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        padded_data = pkcs7_encode(data)
        encryptor = AESModeOfOperationCBC(self._key, iv)
        ciphertext = encryptor.encrypt(padded_data)
        basic_parts = (b"\x80" + struct.pack(">Q", current_time)
                       + iv + ciphertext)

        hmac = HMAC.new(self._key[:16], ciphertext, SHA256)
        hmac = hmac.digest()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, cipher):
        # TODO: implement this ...
        pass


def test_padding():
    from cryptography.fernet import padding, algorithms
    secret_message = b"Secret message!"

    padded_data = pkcs7_encode(secret_message)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data2 = padder.update(secret_message) + padder.finalize()

    assert padded_data2 == padded_data

    secret_message = b"lorem impsum doler"
    padded_data = pkcs7_encode(secret_message)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data2 = padder.update(secret_message) + padder.finalize()
    assert padded_data2 == padded_data


def test_aes():
    secret_message = b"Secret message!"
    iv = os.urandom(16)

    key = pbkdf2_hmac('sha256', b'password', b'salt', 100000)
    padded_data = pkcs7_encode(secret_message)
    from pyaes import AESModeOfOperationCBC
    encryptor = AESModeOfOperationCBC(key, iv)
    ciphertext2 = encryptor.encrypt(padded_data)

    from cryptography.fernet import Cipher, modes
    from cryptography.fernet import padding, algorithms, default_backend
    backend = default_backend()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(secret_message) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key),
                       modes.CBC(iv), backend).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    assert ciphertext == ciphertext2


def test_kdf():
    import base64
    import os
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    key2 = pbkdf2_hmac('sha256', b"password", salt, 100000)
    key3 = pbkdf2_hmac('sha256', b"password", salt, 100000)
    assert key2 == key3
    key2 = base64.urlsafe_b64encode(key2)
    assert key2 == key


def test_fernet():
    current_time = int(time.time())
    iv = os.urandom(16)
    from cryptography.fernet import Fernet as CFernet

    salt = os.urandom(16)
    key = pbkdf2_hmac('sha256', b"password", salt, 100000)
    ckey = base64.urlsafe_b64encode(key)
    cfernet = CFernet(ckey)
    ccipher = cfernet._encrypt_from_parts(b"Secret message!", current_time, iv)

    fernet = Fernet(key)
    cipher = fernet._encrypt_from_parts(b"Secret message!", current_time, iv)
    print(cipher)
    print(ccipher)
    assert cipher == ccipher

if __name__ == "__main__":
    test_padding()
    test_aes()
    test_kdf()
    test_fernet()
