# communication/communication_client.py

import asyncio
import json
from typing import Any, Dict, Optional, Union
from ic.agent import Agent  # Assuming this is an existing class in the ic module
from ic.candid import Candid
from ic.principal import Principal
from ..exceptions import CommunicationError  # Adjusted import path
from ..logger import get_logger  # Adjusted import path

# Initialize Logger
logger = get_logger(__name__)

class CommunicationClient:
    """
    Manages communication between agents and canisters on the ICP network.
    Handles sending messages, querying canisters, and processing responses.
    """
    def __init__(self, agent: Agent, canister_id: str):
        self.agent = agent
        self.canister_id = Principal.from_str(canister_id)
        self.candid = Candid()
        logger.info(f"Initialized CommunicationClient for canister {canister_id}")

    async def send_message(self, method: str, args: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], str]:
        """
        Sends a message to a canister and awaits the response.
        
        :param method: The method name on the canister to be invoked.
        :param args: The arguments to be passed to the method, serialized to Candid.
        :return: The response from the canister, decoded from Candid.
        """
        try:
            logger.info(f"Sending message to canister {self.canister_id}, method: {method}, args: {args}")
            # Encode arguments using Candid
            candid_args = self.candid.encode(args) if args else b''
            
            # Send message to canister
            response = await self.agent.update(self.canister_id, method, candid_args)
            logger.info(f"Received response from canister: {response}")
            
            # Decode the response from Candid
            decoded_response = self.candid.decode(response)
            return decoded_response
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise CommunicationError(f"Error communicating with canister {self.canister_id}: {e}")

    async def query_canister(self, method: str, args: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], str]:
        """
        Queries a canister method without state-changing operations.
        
        :param method: The method name on the canister to query.
        :param args: The arguments to be passed to the method, serialized to Candid.
        :return: The response from the canister, decoded from Candid.
        """
        try:
            logger.info(f"Querying canister {self.canister_id}, method: {method}, args: {args}")
            candid_args = self.candid.encode(args) if args else b''
            
            # Query canister
            response = await self.agent.query(self.canister_id, method, candid_args)
            logger.info(f"Query response: {response}")
            
            decoded_response = self.candid.decode(response)
            return decoded_response
        except Exception as e:
            logger.error(f"Failed to query canister: {e}")
            raise CommunicationError(f"Error querying canister {self.canister_id}: {e}")

    async def send_and_wait(self, method: str, args: Optional[Dict[str, Any]] = None, timeout: int = 30) -> Union[Dict[str, Any], str]:
        """
        Sends a message to a canister and waits for the response, with a timeout.
        
        :param method: The method name on the canister to invoke.
        :param args: The arguments to be passed to the method, serialized to Candid.
        :param timeout: The timeout for awaiting the response.
        :return: The response from the canister, decoded from Candid.
        """
        try:
            logger.info(f"Sending message to canister {self.canister_id} with timeout {timeout}s")
            response = await asyncio.wait_for(self.send_message(method, args), timeout=timeout)
            return response
        except asyncio.TimeoutError:
            logger.error(f"Timeout while waiting for response from canister {self.canister_id}")
            raise CommunicationError(f"Timeout while waiting for response from canister {self.canister_id}")
        except Exception as e:
            logger.error(f"Error during send_and_wait: {e}")
            raise CommunicationError(f"Error during send_and_wait: {e}")

    async def get_canister_status(self) -> Dict[str, Any]:
        """
        Retrieves the status of the canister (e.g., cycle balance, memory, etc.).
        
        :return: A dictionary containing the canister status.
        """
        try:
            logger.info(f"Fetching canister status for {self.canister_id}")
            status = await self.query_canister("canister_status")
            return status
        except Exception as e:
            logger.error(f"Failed to retrieve canister status: {e}")
            raise CommunicationError(f"Error retrieving canister status: {e}")

    async def manage_cycles(self, amount: int) -> str:
        """
        Adjusts cycles in the canister based on operations.
        
        :param amount: The number of cycles to adjust.
        :return: A success or error message.
        """
        try:
            logger.info(f"Managing {amount} cycles for canister {self.canister_id}")
            response = await self.send_message("manage_cycles", {"amount": amount})
            return response.get('status', 'Cycle management complete')
        except Exception as e:
            logger.error(f"Failed to manage cycles: {e}")
            raise CommunicationError(f"Error managing cycles for canister {self.canister_id}: {e}")

    def disconnect(self):
        """
        Disconnects the agent from the canister.
        """
        logger.info(f"Disconnecting CommunicationClient from canister {self.canister_id}")
        self.agent.disconnect()
