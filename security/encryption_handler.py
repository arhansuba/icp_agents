# agents/encryption_handler.py

from .key_management import KeyManagement, KeyManagementError
from typing import Union, Tuple

class EncryptionHandler:
    """
    A class to handle encryption and decryption of ICP chain data and agent communication.
    """

    def __init__(self):
        self.key_manager = KeyManagement()
    
    def encrypt_data(self, data: str, key_type: str, key_pem: bytes) -> str:
        """
        Encrypt data using the specified key type and key.

        :param data: The data to encrypt.
        :param key_type: Type of key used for encryption ('symmetric' or 'asymmetric').
        :param key_pem: PEM encoded key for encryption.
        :return: Encrypted data, base64 encoded.
        """
        try:
            if key_type == 'asymmetric':
                return self.key_manager.encrypt_message(key_pem, data)
            elif key_type == 'symmetric':
                symmetric_key = self.key_manager.load_symmetric_key(key_pem)
                return self.key_manager.encrypt_with_symmetric_key(symmetric_key, data)
            else:
                raise ValueError("Unsupported key type. Use 'symmetric' or 'asymmetric'.")
        except KeyManagementError as e:
            raise EncryptionHandlerError(f"Data encryption failed: {e}")

    def decrypt_data(self, encrypted_data: str, key_type: str, key_pem: bytes) -> str:
        """
        Decrypt data using the specified key type and key.

        :param encrypted_data: The encrypted data, base64 encoded.
        :param key_type: Type of key used for decryption ('symmetric' or 'asymmetric').
        :param key_pem: PEM encoded key for decryption.
        :return: Decrypted data.
        """
        try:
            if key_type == 'asymmetric':
                return self.key_manager.decrypt_message(key_pem, encrypted_data)
            elif key_type == 'symmetric':
                symmetric_key = self.key_manager.load_symmetric_key(key_pem)
                return self.key_manager.decrypt_with_symmetric_key(symmetric_key, encrypted_data)
            else:
                raise ValueError("Unsupported key type. Use 'symmetric' or 'asymmetric'.")
        except KeyManagementError as e:
            raise EncryptionHandlerError(f"Data decryption failed: {e}")

    def generate_symmetric_key(self, key_size: int = 32) -> bytes:
        """
        Generate a new symmetric key.

        :param key_size: Size of the symmetric key in bytes (e.g., 32 bytes for AES-256).
        :return: Symmetric key.
        """
        try:
            return self.key_manager.generate_symmetric_key(key_size)
        except KeyManagementError as e:
            raise EncryptionHandlerError(f"Symmetric key generation failed: {e}")

class EncryptionHandlerError(Exception):
    """Custom exception for encryption handler errors."""
    pass
