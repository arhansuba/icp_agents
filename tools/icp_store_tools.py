import logging
import requests
from icp_agents.agent import ICPAgent
from icp_agents.config.default_config import global_config
import time
from eth_account.messages import encode_defunct
from web3 import Web3
import json

# Configure logging
logger = logging.getLogger(__name__)

def upload_to_icp_canister(filepath: str) -> str:
    """
    Uploads a file to an ICP canister.
    """
    try:
        # Load configuration
        config = global_config["capabilities"]["icp_tools"]["upload_to_icp_canister"]
        ic_endpoint = config["ic_endpoint"]
        api_key = config.get("api_key")

        # Initialize ICP client
        client = ICPAgent(api_key=api_key, base_url=ic_endpoint)

        # Define the URL and headers for the request
        url = f'{ic_endpoint}/canister/upload'  # Replace with actual ICP canister endpoint
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        # Define the file to upload
        with open(filepath, 'rb') as file:
            files = {'file': file}
            response = client.upload_file(url, headers=headers, files=files)

        # Return response from ICP canister
        try:
            response_json = response.json()
            return response_json.get('url', 'No URL found')
        except requests.exceptions.JSONDecodeError:
            return response.text

    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        return "Error: " + str(e)
