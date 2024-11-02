from pydantic import HttpUrl
from ducopy.rest.models import ActionsResponse, ConfigNodeResponse, NodeInfo, NodesResponse
from ducopy.rest.utils import DucoUrlSession
from loguru import logger

import importlib.resources as pkg_resources
from ducopy import certs


class APIClient:
    def __init__(self, base_url: HttpUrl) -> None:
        self.base_url = base_url
        self.session = DucoUrlSession(base_url, verify=self._duco_pem())
        logger.info("APIClient initialized with base URL: {}", base_url)

    def _duco_pem(self) -> str:
        """Enable certificate pinning."""
        pem_path = pkg_resources.files(certs).joinpath("api_cert.pem")
        logger.debug("Using certificate at path: {}", pem_path)

        return str(pem_path)

    def get_api_info(self) -> dict:
        """Fetch API version and available endpoints."""
        logger.info("Fetching API information")
        response = self.session.get("/api")
        response.raise_for_status()
        logger.debug("Received API information")
        return response.json()

    def get_info(self, module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict:
        """Fetch general API information."""
        params = {k: v for k, v in {"module": module, "submodule": submodule, "parameter": parameter}.items() if v}
        logger.info("Fetching info with parameters: {}", params)
        response = self.session.get("/info", params=params)
        response.raise_for_status()
        logger.debug("Received general info")
        return response.json()

    def get_nodes(self) -> NodesResponse:
        """Retrieve list of all nodes."""
        logger.info("Fetching list of all nodes")
        response = self.session.get("/info/nodes")
        response.raise_for_status()
        logger.debug("Received nodes data")
        return NodesResponse.model_validate(response.json())

    def get_node_info(self, node_id: int) -> NodeInfo:
        """Retrieve detailed information for a specific node."""
        logger.info("Fetching info for node ID: {}", node_id)
        response = self.session.get(f"/info/nodes/{node_id}")
        response.raise_for_status()
        logger.debug("Received node info for node ID: {}", node_id)
        return NodeInfo.model_validate(response.json())

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        """Retrieve configuration settings for a specific node."""
        logger.info("Fetching configuration for node ID: {}", node_id)
        response = self.session.get(f"/config/nodes/{node_id}")
        response.raise_for_status()
        logger.debug("Received config for node ID: {}", node_id)
        return ConfigNodeResponse.model_validate(response.json())

    def get_action(self, action: str | None = None) -> dict:
        """Retrieve action data."""
        logger.info("Fetching action data for action: {}", action)
        params = {"action": action} if action else {}
        response = self.session.get("/action", params=params)
        response.raise_for_status()
        logger.debug("Received action data for action: {}", action)
        return response.json()

    def get_actions_node(self, node_id: int, action: str | None = None) -> ActionsResponse:
        """Retrieve available actions for a specific node."""
        logger.info("Fetching actions for node ID: {} with action filter: {}", node_id, action)
        params = {"action": action} if action else {}
        response = self.session.get(f"/action/nodes/{node_id}", params=params)
        response.raise_for_status()
        logger.debug("Received actions for node ID: {}", node_id)
        return ActionsResponse.model_validate(response.json())

    def get_logs(self) -> dict:
        """Retrieve API logs."""
        logger.info("Fetching API logs")
        response = self.session.get("/log/api")
        response.raise_for_status()
        logger.debug("Received API logs")
        return response.json()

    def close(self) -> None:
        """Close the HTTP session."""
        logger.info("Closing the API client session")
        self.session.close()
