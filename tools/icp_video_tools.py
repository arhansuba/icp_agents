import logging
import requests
from icp_agents.agent import ICPAgent
from icp_agents.config.default_config import global_config

# Configure logging
logger = logging.getLogger(__name__)

def _get_presigned_url_and_upload_id(filepath, ic_client: ICPAgent):
    """
    Get a presigned URL and upload ID for uploading a file to ICP canister.
    """
    try:
        # Define the ICP canister endpoint and headers
        url = f'{ic_client.base_url}/canister/upload-url'  # Replace with actual ICP canister endpoint
        headers = {'Authorization': f'Bearer {ic_client.api_key}'}

        # Request a presigned URL and upload ID
        response = requests.post(url, headers=headers)
        response_data = response.json()

        if response.status_code == 200 and response_data.get('status') == 'success':
            upload_info = response_data.get('body', {})
            pre_signed_url = upload_info.get('presigned_url')
            upload_id = upload_info.get('upload_id')
            return pre_signed_url, upload_id
        return None, None
    except Exception as e:
        logger.error(f"Failed to get presigned URL and upload ID: {e}")
        return None, None

def _upload_video(filepath, pre_signed_url):
    """
    Upload a video file to the ICP canister using a presigned URL.
    """
    try:
        with open(filepath, 'rb') as file:
            response = requests.put(pre_signed_url, headers={'Content-Type': 'application/octet-stream'}, data=file)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to upload video: {e}")
        return False

def _transcode_video(upload_id, ic_client: ICPAgent):
    """
    Request video transcoding for the uploaded file in ICP canister.
    """
    try:
        url = f'{ic_client.base_url}/canister/transcode'  # Replace with actual ICP canister endpoint
        headers = {
            'Authorization': f'Bearer {ic_client.api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            "source_upload_id": upload_id,
            "playback_policy": "public",
            "metadata": {
                "key": "value"  # Replace with actual metadata
            }
        }
        response = requests.post(url, headers=headers, json=data)
        response_data = response.json()

        if response.status_code == 200 and response_data.get('status') == 'success':
            video_id = response_data.get('body', {}).get('video_id')
            return video_id
        return None
    except Exception as e:
        logger.error(f"Failed to transcode video: {e}")
        return None

def _get_video_playback_url(video_id, ic_client: ICPAgent):
    """
    Get the playback URL for the transcoded video from ICP canister.
    """
    try:
        url = f'{ic_client.base_url}/canister/video/{video_id}'  # Replace with actual ICP canister endpoint
        headers = {'Authorization': f'Bearer {ic_client.api_key}'}

        response = requests.get(url, headers=headers)
        response_data = response.json()

        if response.status_code == 200 and response_data.get('status') == 'success':
            video_info = response_data.get('body', {}).get('video', {})
            playback_uri = video_info.get('playback_uri')
            return playback_uri
        return None
    except Exception as e:
        logger.error(f"Failed to get video playback URL: {e}")
        return None

def upload_video_to_icp(filepath: str) -> str:
    """
    Uploads a video to an ICP canister and gets the playback URL.
    """
    try:
        # Load configuration
        config = global_config["capabilities"]["icp_tools"]["upload_video_to_icp"]
        ic_endpoint = config["ic_endpoint"]
        api_key = config.get("api_key")

        # Initialize ICP client
        ic_client = ICPAgent(api_key=api_key, base_url=ic_endpoint)

        # Get presigned URL and upload ID
        pre_signed_url, upload_id = _get_presigned_url_and_upload_id(filepath, ic_client)
        if pre_signed_url is None:
            return "Error: Failed to get presigned URL."
        if upload_id is None:
            return "Error: Failed to get upload ID."

        # Upload video
        is_video_upload_successful = _upload_video(filepath, pre_signed_url)
        if not is_video_upload_successful:
            return "Error: Failed to upload video."

        # Transcode video
        video_id = _transcode_video(upload_id, ic_client)
        if video_id is None:
            return "Error: Failed to transcode video."

        # Get playback URL
        playback_uri = _get_video_playback_url(video_id, ic_client)
        if playback_uri is None:
            return "Error: Failed to get playback URI."
        return playback_uri

    except Exception as e:
        logger.error(f"Failed to upload video: {e}")
        return "Error: " + str(e)
