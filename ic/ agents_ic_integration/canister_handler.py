# agents/canister_handler.py

from ic import client
from .exceptions import CanisterHandlerError
from .logger import get_logger
from typing import Any, Dict, Optional

# Initialize Logger
logger = get_logger(__name__)

class CanisterHandler:
    """
    A class to handle specific interactions with canisters on the ICP chain.
    This includes invoking methods, querying data, and processing responses.
    """
    def __init__(self, canister_id: str):
        """
        Initialize the CanisterHandler.

        :param canister_id: ID of the target canister on the ICP chain.
        """
        self.canister_id = canister_id
        self.ic_client = client.Client()
        logger.info(f"CanisterHandler initialized for canister {self.canister_id}")

    def invoke_canister_method(self, method_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """
        Invokes a method on the canister.

        :param method_name: The name of the method to call on the canister.
        :param arguments: Optional arguments to pass to the method.
        :return: The response from the canister.
        """
        try:
            # Call the canister method using the ICP client
            response = self.ic_client.call_canister(
                canister_id=self.canister_id,
                method=method_name,
                arguments=[arguments] if arguments else []
            )
            
            logger.info(f"Method {method_name} invoked on canister {self.canister_id}, response: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to invoke method {method_name} on canister: {e}")
            raise CanisterHandlerError(f"Method invocation failed: {e}")

    def query_canister_data(self, query_name: str, query_params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Queries data from the canister.

        :param query_name: The name of the query to perform on the canister.
        :param query_params: Optional parameters for the query.
        :return: The data retrieved from the canister.
        """
        try:
            # Query the canister using the ICP client
            response = self.ic_client.query_canister(
                canister_id=self.canister_id,
                method=query_name,
                arguments=[query_params] if query_params else []
            )
            
            logger.info(f"Query {query_name} executed on canister {self.canister_id}, response: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to query data from canister: {e}")
            raise CanisterHandlerError(f"Query failed: {e}")

    def read_canister_state(self, state_path: str) -> Any:
        """
        Reads the state of the canister from the ICP chain.

        :param state_path: The path to the specific state or key being read.
        :return: The state data from the canister.
        """
        try:
            # Read the state from the canister
            state_data = self.ic_client.read_state(
                canister_id=self.canister_id,
                path=state_path
            )
            
            logger.info(f"State data read from canister {self.canister_id}, path {state_path}: {state_data}")
            return state_data
        except Exception as e:
            logger.error(f"Failed to read state from canister: {e}")
            raise CanisterHandlerError(f"Read state failed: {e}")

    def handle_canister_response(self, response: Any) -> Dict[str, Any]:
        """
        Handles and processes the response from a canister method or query.

        :param response: The response data from the canister.
        :return: The processed response as a dictionary.
        """
        try:
            # Process the canister response
            if isinstance(response, dict) and 'status' in response and response['status'] == 'error':
                logger.error(f"Canister responded with an error: {response['error']}")
                raise CanisterHandlerError(f"Canister error: {response['error']}")
            
            # Return the processed response
            logger.info(f"Canister response processed successfully: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to handle canister response: {e}")
            raise CanisterHandlerError(f"Response handling failed: {e}")

