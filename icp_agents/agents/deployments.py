import logging
import os  # noqa: E402
from typing import Any

# Replace get_workspace_uri with a generic function to get the workspace URI
def get_workspace_uri() -> str:
    return os.getenv("WORKSPACE_URI", "")

os.environ["PREFECT_API_URL"] = f"{get_workspace_uri()}/api"
os.environ["PREFECT_UI_URL"] = get_workspace_uri()

from prefect.deployments import run_deployment  # noqa: E402

logger = logging.getLogger(__name__)


def run_action_deployment(name: str, parameters: dict = None) -> Any:
    deployment_run = run_deployment(name=name, parameters=parameters)
    logger.info(
        f"Deployment run name: {deployment_run.name} exited with state: {deployment_run.state_name}"
    )
    return deployment_run