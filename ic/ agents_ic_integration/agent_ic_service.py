# agents/agent_ic_service.py

from ic import client, canister
from ..communication.message_protocol import MessageProtocol, MessageType
from ..exceptions import AgentICServiceError
from ..logger import get_logger  # Adjusted import to go one level up
from typing import Any, Dict, Optional

# Initialize Logger
logger = get_logger(__name__)

class AgentICService:
    """
    A service class to handle ICP chain interaction logic, including sending messages,
    reading data, and managing inter-agent communication via the ICP chain.
    """
    def __init__(self, agent_id: str, canister_id: str, encryption_key: Optional[bytes] = None):
        """
        Initialize the AgentICService.

        :param agent_id: Unique ID of the agent.
        :param canister_id: ID of the target canister on the ICP chain.
        :param encryption_key: Optional encryption key for secure message communication.
        """
        self.agent_id = agent_id
        self.canister_id = canister_id
        self.message_protocol = MessageProtocol(encryption_key)
        self.ic_client = client.Client()
        logger.info(f"AgentICService initialized for agent {self.agent_id} and canister {self.canister_id}")

    def send_message_to_canister(self, receiver_id: str, content: Dict[str, Any], message_type: MessageType = MessageType.COMMAND) -> Dict[str, Any]:
        """
        Sends a message to a canister on the ICP chain.

        :param receiver_id: ID of the receiving agent or canister.
        :param content: The content of the message.
        :param message_type: The type of the message (e.g., command, request).
        :return: The response from the canister or a status dictionary.
        """
        try:
            # Create the message using the MessageProtocol
            message = self.message_protocol.create_message(
                message_type=message_type,
                content=content,
                sender_id=self.agent_id,
                receiver_id=receiver_id
            )

            # Serialize and encrypt the message
            encrypted_message = self.message_protocol.send_message(message)

            # Send the message to the ICP canister
            response = self.ic_client.call_canister(
                canister_id=self.canister_id,
                method="send_message",  # Assume the canister has a `send_message` method
                arguments=[encrypted_message]
            )

            # Decrypt and return the response
            decrypted_response = self.message_protocol.receive_message(response)
            logger.info(f"Message sent to canister {self.canister_id}, response received: {decrypted_response}")
            return decrypted_response
        except Exception as e:
            logger.error(f"Failed to send message to canister: {e}")
            raise AgentICServiceError(f"Failed to send message: {e}")

    def query_canister_data(self, query_type: str, query_params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Queries data from the canister on the ICP chain.

        :param query_type: The type of query (e.g., "get_status", "get_balance").
        :param query_params: Additional parameters for the query.
        :return: The queried data from the canister.
        """
        try:
            # Make a query to the canister using the ICP client
            response = self.ic_client.query_canister(
                canister_id=self.canister_id,
                method=query_type,
                arguments=[query_params] if query_params else []
            )

            logger.info(f"Data queried from canister {self.canister_id}, response: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to query data from canister: {e}")
            raise AgentICServiceError(f"Query failed: {e}")

    def read_state_from_chain(self, path: str) -> Any:
        """
        Reads the state of the canister from the ICP chain.

        :param path: The path to the specific state or key being read.
        :return: The state data from the ICP chain.
        """
        try:
            # Read the state from the ICP chain
            state_data = self.ic_client.read_state(
                canister_id=self.canister_id,
                path=path
            )

            logger.info(f"State data read from canister {self.canister_id}, path {path}: {state_data}")
            return state_data
        except Exception as e:
            logger.error(f"Failed to read state from canister: {e}")
            raise AgentICServiceError(f"Read state failed: {e}")

    def handle_incoming_message(self, encrypted_message: bytes) -> Dict[str, Any]:
        """
        Handles an incoming encrypted message from another agent or canister.

        :param encrypted_message: The incoming encrypted message as bytes.
        :return: The decrypted and validated message content.
        """
        try:
            # Decrypt the message using the MessageProtocol
            decrypted_message = self.message_protocol.receive_message(encrypted_message)
            logger.info(f"Incoming message handled successfully: {decrypted_message}")
            return decrypted_message
        except Exception as e:
            logger.error(f"Failed to handle incoming message: {e}")
            raise AgentICServiceError(f"Failed to handle message: {e}")

