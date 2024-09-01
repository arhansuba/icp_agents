# agents/key_management.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class KeyManagementError(Exception):
    """Custom exception for key management errors."""
    pass

class KeyManagement:
    """
    A class to manage key generation, encryption, and decryption for secure communication between agents.
    """
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_key_pair(self, key_size: int = 2048):
        """
        Generate an RSA key pair.

        :param key_size: The size of the RSA key to generate.
        :return: Private and public key as PEM encoded bytes.
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
        except Exception as e:
            raise KeyManagementError(f"Key generation failed: {e}")

    def load_private_key(self, private_key_pem: bytes):
        """
        Load a private key from PEM encoded bytes.

        :param private_key_pem: PEM encoded private key.
        :return: RSA private key object.
        """
        try:
            return serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
        except Exception as e:
            raise KeyManagementError(f"Loading private key failed: {e}")

    def load_public_key(self, public_key_pem: bytes):
        """
        Load a public key from PEM encoded bytes.

        :param public_key_pem: PEM encoded public key.
        :return: RSA public key object.
        """
        try:
            return serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
        except Exception as e:
            raise KeyManagementError(f"Loading public key failed: {e}")

    def encrypt_message(self, public_key_pem: bytes, message: str) -> str:
        """
        Encrypt a message using a public key.

        :param public_key_pem: PEM encoded public key.
        :param message: The message to encrypt.
        :return: The encrypted message, base64 encoded.
        """
        try:
            public_key = self.load_public_key(public_key_pem)
            encrypted_message = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                    algorithm=crypto_hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_message).decode('utf-8')
        except Exception as e:
            raise KeyManagementError(f"Message encryption failed: {e}")

    def decrypt_message(self, private_key_pem: bytes, encrypted_message: str) -> str:
        """
        Decrypt a message using a private key.

        :param private_key_pem: PEM encoded private key.
        :param encrypted_message: The encrypted message, base64 encoded.
        :return: The decrypted message.
        """
        try:
            private_key = self.load_private_key(private_key_pem)
            encrypted_message_bytes = base64.b64decode(encrypted_message)
            decrypted_message = private_key.decrypt(
                encrypted_message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                    algorithm=crypto_hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_message.decode('utf-8')
        except Exception as e:
            raise KeyManagementError(f"Message decryption failed: {e}")

    def generate_symmetric_key(self, key_size: int = 32) -> bytes:
        """
        Generate a symmetric key.

        :param key_size: Size of the symmetric key in bytes (e.g., 32 bytes for AES-256).
        :return: Symmetric key.
        """
        try:
            return os.urandom(key_size)
        except Exception as e:
            raise KeyManagementError(f"Symmetric key generation failed: {e}")

    def encrypt_with_symmetric_key(self, key: bytes, data: str) -> str:
        """
        Encrypt data using a symmetric key.

        :param key: Symmetric key.
        :param data: Data to encrypt.
        :return: Encrypted data, base64 encoded.
        """
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            return base64.b64encode(iv + encrypted_data).decode('utf-8')
        except Exception as e:
            raise KeyManagementError(f"Symmetric encryption failed: {e}")

    def decrypt_with_symmetric_key(self, key: bytes, encrypted_data: str) -> str:
        """
        Decrypt data using a symmetric key.

        :param key: Symmetric key.
        :param encrypted_data: Encrypted data, base64 encoded.
        :return: Decrypted data.
        """
        try:
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_data_bytes[:16]
            encrypted_data = encrypted_data_bytes[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise KeyManagementError(f"Symmetric decryption failed: {e}")

