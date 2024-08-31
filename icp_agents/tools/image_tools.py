import logging
from dataclasses_json import global_config
from icp_agents.agent import ICPAgent
from icp_agents.config.default_config import global_config


# Configure logging
logger = logging.getLogger(__name__)

def create_image_from_prompt(prompt: str) -> str:
    """
    Create an image based on a prompt and return the image URL.
    """
    try:
        config = global_config["capabilities"]["image_tools"]["create_image_from_prompt"]
        ic_endpoint = config["ic_endpoint"]
        api_key = config.get("api_key")

        # Initialize ICP client
        client = ICPAgent(api_key=api_key, base_url=ic_endpoint)
        
        # Assuming ICPClient has a method for generating images
        result = client.generate_image(prompt=prompt)
        
        # Extract the image URL from the result
        image_url = result.get('url', '')

        if image_url:
            return image_url
        else:
            logger.error("Image URL not found in the response.")
            return "Error: Image URL not found."

    except Exception as e:
        logger.error(f"Failed to create image: {e}")
        return "Error: Failed to create image."
