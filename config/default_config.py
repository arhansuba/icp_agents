import os
import yaml
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load YAML configuration
config_file_path = os.getenv('CONFIG_FILE', 'config.yaml')
with open(config_file_path, 'r') as file:
    yaml_config = yaml.safe_load(file)

def get_config_value(env_var, yaml_path, default=None):
    """Helper function to get configuration values from environment variables or YAML."""
    value = os.getenv(env_var)
    if value is None:
        keys = yaml_path.split('.')
        config_value = yaml_config
        for key in keys:
            config_value = config_value.get(key, {})
        value = config_value if config_value else default
    return value

def get_env_variable_from_yaml(yaml_config, yaml_path, default=None):
    """Get environment variable value based on the variable name defined in YAML."""
    keys = yaml_path.split('.')
    config_value = yaml_config
    for key in keys:
        config_value = config_value.get(key, {})
    if isinstance(config_value, str):
        env_var_name = config_value
        return os.getenv(env_var_name, default)
    return default

# Global configuration combining YAML and environment variables
global_config = {
    "llm_endpoint": get_config_value('LLM_ENDPOINT', 'llm_endpoint', 'https://icp.default.endpoint'),
    "llm_model_name": get_config_value('LLM_MODEL_NAME', 'llm_model_name', 'gpt-4'),
    "llm_api_key": get_env_variable_from_yaml(yaml_config, 'llm_api_key_env'),
    
    "capabilities": {
        "image_tools": {
            "create_image_from_prompt": {
                "icp_endpoint": get_config_value('IMAGE_ENDPOINT', 'capabilities.image_tools.create_image_from_prompt.icp_endpoint'),
                "model_name": get_config_value('IMAGE_MODEL_NAME', 'capabilities.image_tools.create_image_from_prompt.model_name'),
                "api_key": get_env_variable_from_yaml(yaml_config, 'capabilities.image_tools.create_image_from_prompt.api_key_env')
            }
        },
        "video_tools": {
            "create_video_from_image": {
                "icp_endpoint": get_config_value('VIDEO_ENDPOINT', 'capabilities.video_tools.create_video_from_image.icp_endpoint'),
                "model_name": get_config_value('VIDEO_MODEL_NAME', 'capabilities.video_tools.create_video_from_image.model_name'),
                "api_key": get_env_variable_from_yaml(yaml_config, 'capabilities.video_tools.create_video_from_image.api_key_env', None)
            }
        },
        "smart_contract_tools": {
            "generate_smart_contract": {
                "icp_endpoint": get_config_value('SMART_CONTRACT_ENDPOINT', 'capabilities.smart_contract_tools.generate_smart_contract.icp_endpoint'),
                "model_name": get_config_value('SMART_CONTRACT_MODEL_NAME', 'capabilities.smart_contract_tools.generate_smart_contract.model_name'),
                "api_key": get_env_variable_from_yaml(yaml_config, 'capabilities.smart_contract_tools.generate_smart_contract.api_key_env')
            },
            "analyze_smart_contract": {
                "icp_endpoint": get_config_value('SMART_CONTRACT_ENDPOINT', 'capabilities.smart_contract_tools.analyze_smart_contract.icp_endpoint'),
                "model_name": get_config_value('SMART_CONTRACT_MODEL_NAME', 'capabilities.smart_contract_tools.analyze_smart_contract.model_name'),
                "api_key": get_env_variable_from_yaml(yaml_config, 'capabilities.smart_contract_tools.analyze_smart_contract.api_key_env')
            },
            "deploy_smart_contract": {
                "icp_wallet_public_address": get_config_value('ICP_WALLET_PUBLIC_ADDRESS', 'capabilities.smart_contract_tools.deploy_smart_contract.icp_wallet_public_address'),
                "icp_wallet_private_key": get_env_variable_from_yaml(yaml_config, 'capabilities.smart_contract_tools.deploy_smart_contract.icp_wallet_private_key_env')
            }
        },
        "icp_store_tools": {
            "upload_to_store": {
                "icp_provider_endpoint": get_config_value('ICP_PROVIDER_ENDPOINT', 'capabilities.icp_edgestore_tools.upload_to_edgestore.icp_provider_endpoint'),
                "address": get_config_value('ICP_WALLET_PUBLIC_ADDRESS', 'capabilities.icp_edgestore_tools.upload_to_edgestore.address'),
                "icp_wallet_private_key": get_env_variable_from_yaml(yaml_config, 'capabilities.icp_edgestore_tools.upload_to_edgestore.icp_wallet_private_key_env')
            }
        },
        "icp_video_tools": {
            "upload_video_to_icp": {
                "service_account_id": get_config_value('SERVICE_ACCOUNT_ID', 'capabilities.icp_video_tools.upload_video_to_icp.service_account_id'),
                "service_account_secret": get_env_variable_from_yaml(yaml_config, 'capabilities.icp_video_tools.upload_video_to_icp.service_account_secret_env')
            }
        }
    }
}
