import logging
import json
from typing import List, Dict
from gradio_client import Client as client_gradio
from openai import OpenAI
from icp_agents.agent import ICPAgent
from icp_agents.config.default_config import global_config

# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger('httpx').setLevel(logging.ERROR)

def generate_smart_contract(prompt: str) -> str:
    """
    Generate smart contract code based on a user's prompt.
    """
    system_prompt = """
    Generate a smart contract for a decentralized application on ICP. The smart contract should include all relevant best practices and be as secure as possible. Return nothing but the smart contract code.
    """
    try:
        config = global_config["capabilities"]["smart_contract_tools"]["generate_smart_contract"]
        edgecloud_endpoint = config["edgecloud_endpoint"]
        edgecloud_endpoint_type = config["edgecloud_endpoint_type"]
        model_name = config["model_name"]
        api_key = config.get("api_key")

        if edgecloud_endpoint_type == "gradio":
            client = client_gradio(edgecloud_endpoint)
            result = client.predict(
                prompt,
                api_name="/predict"
            )
            return result.get('output', '')
        elif edgecloud_endpoint_type == 'openai':
            client = OpenAI(api_key=api_key, base_url=edgecloud_endpoint)
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ]
            )
            content = response.choices[0].message.content
            return content
        else:
            logger.error("Invalid edgecloud endpoint type.")
            return "Error: Invalid endpoint type."
    except Exception as e:
        logger.error(f"Failed to generate smart contract: {e}")
        return "Error: Failed to generate smart contract."
    
def analyze_smart_contract(prompt: str) -> str:
    """
    Analyze smart contracts for security vulnerabilities, refactoring, etc.
    """
    system_prompt = """
    Analyze the smart contract for any security vulnerabilities, refactoring, or other issues. Return nothing but the analysis in text form.
    """
    try:
        config = global_config["capabilities"]["smart_contract_tools"]["analyze_smart_contract"]
        edgecloud_endpoint = config["edgecloud_endpoint"]
        edgecloud_endpoint_type = config["edgecloud_endpoint_type"]
        model_name = config["model_name"]
        api_key = config.get("api_key")

        if edgecloud_endpoint_type == "gradio":
            client = client_gradio(edgecloud_endpoint)
            result = client.predict(
                prompt,
                api_name="/predict"
            )
            return result.get('output', '')
        elif edgecloud_endpoint_type == 'openai':
            client = OpenAI(api_key=api_key, base_url=edgecloud_endpoint)
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ]
            )
            content = response.choices[0].message.content
            return content
        else:
            logger.error("Invalid edgecloud endpoint type.")
            return "Error: Invalid endpoint type."
    except Exception as e:
        logger.error(f"Failed to analyze smart contract: {e}")
        return "Error: Failed to analyze smart contract."

def deploy_smart_contract(contract_source_code, contract_name, initial_supply=1000000):
    """
    Deploys a smart contract to the Internet Computer (ICP) canister.
    """
    try:
        # ICP client setup
        config = global_config["capabilities"]["smart_contract_tools"]["deploy_smart_contract"]
        ic_client = ICPAgent(url=config["ic_endpoint"], api_key=config["ic_api_key"])

        # Convert contract source code to the appropriate format for ICP
        # This is a placeholder and should be replaced with actual logic to compile and deploy contracts on ICP
        canister_id = ic_client.create_canister(
            contract_source_code=contract_source_code,
            contract_name=contract_name,
            initial_supply=initial_supply
        )

        return canister_id
    except Exception as e:
        logger.error(f"Failed to deploy smart contract: {e}")
        return "Error: Failed to deploy smart contract."
