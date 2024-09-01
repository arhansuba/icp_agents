import json
import logging
import textwrap
from json import JSONDecodeError
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)


def read_json(file_path: str) -> dict:
    """
    Read the JSON file from the specified path and return the JSON data.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The JSON data.
    """
    with open(file_path) as file:
        return json.load(file)


def requests_debug(response: requests.Response) -> None:
    """
    Log the request and response details.

    Args:
        response (requests.Response): The response object.
    """

    def format_headers(d: Dict) -> str:
        return "\n".join(f"{k}: {v}" for k, v in d.items())

    req_headers = response.request.headers.copy()
    # Remove the Authorization header as it may contain sensitive information
    req_headers.pop("Authorization", None)
    try:
        content = response.json()
    except JSONDecodeError:
        content = (
            response.text if len(response.text) < 1000 else f"{response.text[:1000]}..."
        )

    body = response.request.body if response.request.body else ""
    if isinstance(body, bytes) and len(body) > 1000:
        body = body[:1000] + b"..."
    
    try:
        print(
            textwrap.dedent(
                """
            ---------------- request ----------------
            {req.method} {req.url}
            {reqhdrs}

            {req_body}
            ---------------- response ----------------
            {res.status_code} {res.reason} {res.url}
            {reshdrs}

            {res_content}
        """
            ).format(
                req=response.request,
                req_body=body,
                res=response,
                res_content=content,
                reqhdrs=format_headers(req_headers),
                reshdrs=format_headers(response.headers),
            )
        )
    except Exception as e:
        logger.debug(f"Failed to log request and response details: {e}")


def get_workspace_uri() -> str:
    """
    Placeholder function for retrieving the workspace URI.
    This function can be implemented based on specific requirements.

    Returns:
        str: The URL of the current workspace.
    """
    # Implement workspace retrieval logic here
    return "http://example.com/workspace"  # Example placeholder