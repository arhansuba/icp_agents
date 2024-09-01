# agents/signature_verification.py

import base64
from typing import Union
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class SignatureVerification:
    """
    A class to handle signature verification for ICP transactions, ensuring message integrity and security.
    """

    def __init__(self):
        pass

    def verify_signature(self, message: str, signature: str, public_key_pem: bytes) -> bool:
        """
        Verify the signature of a message using the provided public key.

        :param message: The original message whose signature is being verified.
        :param signature: The signature to verify, base64 encoded.
        :param public_key_pem: PEM encoded public key for verification.
        :return: True if the signature is valid, False otherwise.
        """
        try:
            public_key = self.load_public_key(public_key_pem)
            signature_bytes = base64.b64decode(signature)
            message_bytes = message.encode('utf-8')
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, ValueError) as e:
            # Handle specific errors
            print(f"Signature verification failed: {e}")
            return False

    def load_public_key(self, public_key_pem: bytes) -> ec.EllipticCurvePublicKey:
        """
        Load a public key from PEM encoded data.

        :param public_key_pem: PEM encoded public key.
        :return: EllipticCurvePublicKey instance.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("Public key is not an EllipticCurvePublicKey.")
            return public_key
        except (ValueError, TypeError) as e:
            raise SignatureVerificationError(f"Public key loading failed: {e}")

class SignatureVerificationError(Exception):
    """Custom exception for signature verification errors."""
    pass
