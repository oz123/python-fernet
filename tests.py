import base64
import hmac as HMAC
import os
import struct
import time
from hashlib import sha256 as SHA256, pbkdf2_hmac

from pyaes import AESModeOfOperationCBC, Encrypter

from fernet import Fernet


def test_aes():
    from cryptography.fernet import Cipher, modes
    from cryptography.fernet import padding, algorithms, default_backend

    secret_message = (b"Secret message! A VERRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRY"
                      b"LLLLLLLLLLLLONG message")
    iv = os.urandom(16)

    key = pbkdf2_hmac('sha256', b'password', b'salt', 100000)
    encrypter = Encrypter(AESModeOfOperationCBC(key, iv))
    ciphertext2 = encrypter.feed(secret_message)
    ciphertext2 += encrypter.feed()
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


def test_hmac():
    current_time = int(time.time())
    salt = os.urandom(16)
    ciphertext = b'this is garbelled normally'
    key = pbkdf2_hmac('sha256', b"password", salt, 100000)
    iv = os.urandom(16)
    basic_parts = (b"\x80" + struct.pack(">Q", current_time)
                   + iv + ciphertext)

    enc_key = base64.urlsafe_b64encode(key)
    hmac = HMAC.new(enc_key[:16], digestmod=SHA256)
    hmac.update(basic_parts)
    hmac = hmac.digest()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hmac import HMAC as CHMAC
    from cryptography.hazmat.backends import default_backend

    h = CHMAC(enc_key[:16], hashes.SHA256(), backend=default_backend())
    h.update(basic_parts)
    chmac = h.finalize()
    assert hmac == chmac


def test_fernet():
    current_time = int(time.time())
    iv = os.urandom(16)
    from cryptography.fernet import Fernet as CFernet

    salt = os.urandom(16)
    key = pbkdf2_hmac('sha256', b"password", salt, 100000, dklen=32)
    ckey = base64.urlsafe_b64encode(key)
    cfernet = CFernet(ckey)
    ccipher = cfernet._encrypt_from_parts(b"Secret message!", current_time, iv)

    fernet = Fernet(ckey)
    cipher = fernet._encrypt_from_parts(b"Secret message!", current_time, iv)
    assert cipher == ccipher
