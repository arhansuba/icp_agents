# communication/message_protocol.py

import json
import uuid
import time
from enum import Enum
from typing import Any, Dict, Optional, Union
from cryptography.fernet import Fernet
from ..exceptions import MessageProtocolError
from ..logger import get_logger

# Initialize Logger
logger = get_logger(__name__)

class MessageType(Enum):
    """
    Enum for defining various types of messages for inter-agent communication.
    """
    REQUEST = "request"
    RESPONSE = "response"
    COMMAND = "command"
    STATUS = "status"
    ERROR = "error"

class MessageProtocol:
    """
    A class defining the structure, validation, and encryption of messages between agents.
    This ensures that agents use a consistent and secure messaging format.
    """
    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initialize the MessageProtocol class.

        :param encryption_key: Optional encryption key for secure communication.
        """
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        logger.info(f"MessageProtocol initialized with encryption key: {self.encryption_key.decode('utf-8')}")

    def create_message(self, message_type: MessageType, content: Dict[str, Any], sender_id: str, receiver_id: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Creates a structured message for inter-agent communication.

        :param message_type: The type of message (e.g., request, response, command).
        :param content: The content of the message.
        :param sender_id: ID of the sending agent.
        :param receiver_id: ID of the receiving agent.
        :param metadata: Optional metadata (e.g., timestamp, priority).
        :return: A dictionary representing the structured message.
        """
        message_id = str(uuid.uuid4())
        timestamp = int(time.time())

        message = {
            "message_id": message_id,
            "message_type": message_type.value,
            "content": content,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "metadata": metadata or {},
            "timestamp": timestamp
        }

        logger.info(f"Message created: {message}")
        return message

    def serialize_message(self, message: Dict[str, Any]) -> str:
        """
        Serializes the message to a JSON string for transmission.

        :param message: The message dictionary to serialize.
        :return: The serialized message as a JSON string.
        """
        try:
            serialized_message = json.dumps(message)
            logger.debug(f"Message serialized: {serialized_message}")
            return serialized_message
        except (TypeError, ValueError) as e:
            logger.error(f"Failed to serialize message: {e}")
            raise MessageProtocolError(f"Serialization failed: {e}")

    def encrypt_message(self, message: str) -> bytes:
        """
        Encrypts the serialized message for secure transmission.

        :param message: The serialized message as a string.
        :return: The encrypted message as bytes.
        """
        try:
            encrypted_message = self.fernet.encrypt(message.encode())
            logger.debug(f"Message encrypted: {encrypted_message}")
            return encrypted_message
        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            raise MessageProtocolError(f"Encryption failed: {e}")

    def decrypt_message(self, encrypted_message: bytes) -> str:
        """
        Decrypts an encrypted message back to a serialized string.

        :param encrypted_message: The encrypted message as bytes.
        :return: The decrypted message as a string.
        """
        try:
            decrypted_message = self.fernet.decrypt(encrypted_message).decode()
            logger.debug(f"Message decrypted: {decrypted_message}")
            return decrypted_message
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            raise MessageProtocolError(f"Decryption failed: {e}")

    def deserialize_message(self, serialized_message: str) -> Dict[str, Any]:
        """
        Deserializes a JSON string back into a message dictionary.

        :param serialized_message: The serialized message as a JSON string.
        :return: The deserialized message as a dictionary.
        """
        try:
            message = json.loads(serialized_message)
            logger.debug(f"Message deserialized: {message}")
            return message
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to deserialize message: {e}")
            raise MessageProtocolError(f"Deserialization failed: {e}")

    def validate_message(self, message: Dict[str, Any]) -> bool:
        """
        Validates the structure of the message to ensure it meets protocol requirements.

        :param message: The message dictionary to validate.
        :return: True if the message is valid, raises an error if not.
        """
        required_fields = ["message_id", "message_type", "content", "sender_id", "receiver_id", "timestamp"]

        for field in required_fields:
            if field not in message:
                logger.error(f"Message validation failed: Missing field {field}")
                raise MessageProtocolError(f"Missing required field: {field}")

        if not isinstance(message["message_type"], str) or message["message_type"] not in MessageType.__members__.values():
            logger.error(f"Invalid message type: {message['message_type']}")
            raise MessageProtocolError(f"Invalid message type: {message['message_type']}")

        logger.info(f"Message validated successfully: {message['message_id']}")
        return True

    def send_message(self, message: Dict[str, Any]) -> bytes:
        """
        Full process of serializing, encrypting, and sending the message.

        :param message: The message dictionary to send.
        :return: The encrypted message bytes ready for transmission.
        """
        try:
            serialized_message = self.serialize_message(message)
            encrypted_message = self.encrypt_message(serialized_message)
            return encrypted_message
        except MessageProtocolError as e:
            logger.error(f"Failed to send message: {e}")
            raise

    def receive_message(self, encrypted_message: bytes) -> Dict[str, Any]:
        """
        Full process of receiving, decrypting, and deserializing the message.

        :param encrypted_message: The encrypted message bytes received.
        :return: The deserialized and decrypted message dictionary.
        """
        try:
            decrypted_message = self.decrypt_message(encrypted_message)
            deserialized_message = self.deserialize_message(decrypted_message)
            self.validate_message(deserialized_message)
            return deserialized_message
        except MessageProtocolError as e:
            logger.error(f"Failed to receive message: {e}")
            raise

