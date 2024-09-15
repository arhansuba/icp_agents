# agents/data_encryption_tools.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import os
import base64

class DataEncryptionTools:
    """
    A class to handle encryption and decryption for secure communication between agents and canisters.
    """

    def __init__(self, key: bytes):
        """
        Initialize the encryption tool with a key.

        :param key: The encryption key.
        """
        self.key = key
        self.backend = default_backend()

    def encrypt(self, data: str) -> str:
        """
        Encrypt the given data using AES encryption.

        :param data: The plaintext data to encrypt.
        :return: The base64 encoded encrypted data.
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self._generate_iv()), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt the given data using AES decryption.

        :param encrypted_data: The base64 encoded encrypted data.
        :return: The decrypted plaintext data.
        """
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self._generate_iv()), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
        return decrypted_data.decode('utf-8')

    def _generate_iv(self) -> bytes:
        """
        Generate a random initialization vector (IV) for AES encryption/decryption.

        :return: A 16-byte random IV.
        """
        return os.urandom(16)

    @staticmethod
    def generate_key(password: str, salt: bytes) -> bytes:
        """
        Generate a key from a password using PBKDF2HMAC.

        :param password: The password to generate the key from.
        :param salt: The salt used in key generation.
        :return: The generated key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

class DataEncryptionError(Exception):
    """Custom exception for data encryption/decryption errors."""
    pass
