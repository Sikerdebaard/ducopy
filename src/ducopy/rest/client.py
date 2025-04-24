# “Commons Clause” License Condition v1.0
#
# The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.
#
# Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.
#
# For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/ support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Clause License Condition notice.
#
# Software: ducopy
# License: MIT License
# Licensor: Thomas Phil
#
#
# MIT License
#
# Copyright (c) 2024 Thomas Phil
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
from pydantic import HttpUrl
from ducopy.rest.models import (
    ActionsResponse,
    NodeInfo,
    NodesResponse,
    ConfigNodeResponse,
    ConfigNodeRequest,
    ParameterConfig,
    NodesInfoResponse,
    ActionsChangeResponse
)
from ducopy.rest.utils import DucoUrlSession
from loguru import logger

import importlib.resources as pkg_resources
from ducopy import certs
import json


class APIClient:
    def __init__(self, base_url: HttpUrl, verify: bool = True) -> None:
        self.base_url = base_url
        if verify:
            self.session = DucoUrlSession(base_url, verify=self._duco_pem())
        else:
            self.session = DucoUrlSession(base_url, verify=verify)
        logger.info("APIClient initialized with base URL: {}", base_url)

    def _duco_pem(self) -> str:
        """Enable certificate pinning."""
        pem_path = pkg_resources.files(certs).joinpath("api_cert.pem")
        logger.debug("Using certificate at path: {}", pem_path)

        return str(pem_path)

    def raw_get(self, endpoint: str, params: dict = None) -> dict:
        """
        Perform a raw GET request to the specified endpoint.

        Args:
            endpoint (str): The endpoint to send the GET request to (e.g., "/api").
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: JSON response from the server.
        """
        logger.info("Performing raw GET request to endpoint: {} with params: {}", endpoint, params)
        response = self.session.get(endpoint, params=params)
        response.raise_for_status()
        logger.debug("Received response for raw GET request to endpoint: {}", endpoint)
        return response.json()

    def post_action_node(self, action: str, value: str, node_id: int) -> ActionsChangeResponse:
        """
        Perform a POST action by sending a JSON body to the endpoint.

        Args:
            action (str): The action key to include in the JSON body.
            value (Any): The value key to include in the JSON body.
            node_id (int): The ID of the node to perform the action on.

        Returns:
            dict: JSON response from the server.
        """
        # Fetch available actions for the node
        logger.info("Fetching available actions for node ID: {}", node_id)
        available_actions = self.get_actions_node(node_id=node_id)

        # Validate the action
        matching_action = next((a for a in available_actions.Actions if a.Action == action), None)
        if not matching_action:
            raise ValueError(f"Invalid action '{action}' for node {node_id}. Available actions: {[a.Action for a in available_actions.Actions]}")

        # Validate the value
        if matching_action.ValType == "Enum":
            if value not in matching_action.Enum:
                raise ValueError(f"Invalid value '{value}' for action '{action}'. Allowed values: {matching_action.Enum}")
        elif matching_action.ValType == "Boolean":
            if value not in ["true", "false", "True", "False"]:
                raise ValueError(f"Invalid value '{value}' for action '{action}'. Allowed values: ['true', 'false']")
        elif matching_action.ValType == "Integer":
            try:
                int(value)
            except ValueError:
                raise ValueError(f"Invalid value '{value}' for action '{action}'. Expected an integer.")       
        
    
        endpoint = f"/action/nodes/{node_id}" 
        logger.info("Performing POST action with Action: {} and Val: {}", action, value)
        request_body = {"Action": action,"Val": value}
        # Without this, aka without removing space between the two key value pairs, it will return a 400 error
        serialized_body = json.dumps(request_body, separators=(",", ":"))
        
        response = self.session.post(endpoint, data=serialized_body)
        response.raise_for_status()
        logger.debug("Received response for POST action from Node: {} with Action: {} and Val: {}", node_id, action, value)
        
        return ActionsChangeResponse(**response.json())

    def patch_config_node(self, node_id: int, config: ConfigNodeRequest) -> ConfigNodeResponse:
        """
        Update configuration settings for a specific node after validating the new values.

        Args:
            node_id (int): The ID of the node to update.
            config (ConfigNodeRequest): The configuration data to update.

        Returns:
            ConfigNodeResponse: The updated configuration response from the server.
        """
        logger.info("Updating configuration for node ID: {}", node_id)

        # Fetch current configuration of the node
        current_config_response = self.get_config_node(node_id)
        current_config = current_config_response.dict()

        # Validation logic (same as before)
        validation_errors = []
        for field, new_value in config.dict(exclude_unset=True).items():
            # Get current parameter configuration
            param_config_data = current_config.get(field)
            if param_config_data is None:
                error_message = f"Parameter '{field}' not available for node {node_id}."
                logger.error(error_message)
                validation_errors.append(error_message)
                continue

            # Create a ParameterConfig object
            param_config = ParameterConfig(**param_config_data)

            min_val = param_config.Min
            max_val = param_config.Max
            inc = param_config.Inc

            # Check if new_value is within Min and Max
            if min_val is not None and new_value < min_val:
                error_message = f"Value {new_value} for '{field}' is less than minimum {min_val}."
                logger.error(error_message)
                validation_errors.append(error_message)
            if max_val is not None and new_value > max_val:
                error_message = f"Value {new_value} for '{field}' is greater than maximum {max_val}."
                logger.error(error_message)
                validation_errors.append(error_message)

            # Check if new_value aligns with increment
            if inc is not None:
                base_value = min_val if min_val is not None else 0
                if (new_value - base_value) % inc != 0:
                    error_message = (
                        f"Value {new_value} for '{field}' is not a valid increment of {inc} starting from {base_value}."
                    )
                    logger.error(error_message)
                    validation_errors.append(error_message)

        if validation_errors:
            # Raise an exception with all validation errors
            raise ValueError("Validation errors:\n" + "\n".join(validation_errors))

        # Build the request body with 'Val' keys
        request_body = {}
        for field, new_value in config.dict(exclude_unset=True).items():
            request_body[field] = {"Val": new_value}

        # Send PATCH request if validation passes
        endpoint = f"/config/nodes/{node_id}"
        logger.info("Sending PATCH request with body: {}", request_body)
        response = self.session.patch(endpoint, json=request_body)
        response.raise_for_status()
        logger.debug("Updated config for node ID: {}", node_id)

        return self.get_config_node(node_id)

    def get_config_nodes(self) -> NodesResponse:
        """
        Retrieve the configuration settings for all nodes.

        Returns:
            NodesResponse: Parsed response containing configuration data for all nodes.
        """
        endpoint = "/config/nodes"
        logger.info("Fetching configuration for all nodes from endpoint: {}", endpoint)
        response = self.session.get(endpoint)
        response.raise_for_status()
        logger.debug("Received configuration data for all nodes")
        return NodesResponse(**response.json())  # Parse response into NodesResponse model

    def get_api_info(self) -> dict:
        """Fetch API version and available endpoints."""
        logger.info("Fetching API information")
        response = self.session.get("/api")
        response.raise_for_status()
        logger.debug("Received API information")
        return response.json()

    def get_info(self, module: str = None, submodule: str = None, parameter: str = None) -> dict:
        """Fetch general API information."""
        params = {k: v for k, v in {"module": module, "submodule": submodule, "parameter": parameter}.items() if v}
        logger.info("Fetching info with parameters: {}", params)
        response = self.session.get("/info", params=params)
        response.raise_for_status()
        logger.debug("Received general info")
        return response.json()

    def get_nodes(self) -> NodesInfoResponse:
        """Retrieve list of all nodes."""
        logger.info("Fetching list of all nodes")
        response = self.session.get("/info/nodes")
        response.raise_for_status()
        logger.debug("Received nodes data")
        return NodesInfoResponse(**response.json())

    def get_node_info(self, node_id: int) -> NodeInfo:
        """Retrieve detailed information for a specific node."""
        logger.info("Fetching info for node ID: {}", node_id)
        response = self.session.get(f"/info/nodes/{node_id}")
        response.raise_for_status()
        logger.debug("Received node info for node ID: {}", node_id)
        return NodeInfo(**response.json())  # Direct instantiation for Pydantic 1.x

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        """Retrieve configuration settings for a specific node."""
        logger.info("Fetching configuration for node ID: {}", node_id)
        response = self.session.get(f"/config/nodes/{node_id}")
        response.raise_for_status()
        logger.debug("Received config for node ID: {}", node_id)
        return ConfigNodeResponse(**response.json())  # Direct instantiation for Pydantic 1.x

    def get_action(self, action: str = None) -> dict:
        """Retrieve action data."""
        logger.info("Fetching action data for action: {}", action)
        params = {"action": action} if action else {}
        response = self.session.get("/action", params=params)
        response.raise_for_status()
        logger.debug("Received action data for action: {}", action)
        return response.json()

    def get_actions_node(self, node_id: int, action: str = None) -> ActionsResponse:
        """Retrieve available actions for a specific node."""
        logger.info("Fetching actions for node ID: {} with action filter: {}", node_id, action)
        params = {"action": action} if action else {}
        response = self.session.get(f"/action/nodes/{node_id}", params=params)
        response.raise_for_status()
        logger.debug("Received actions for node ID: {}", node_id)
        return ActionsResponse(**response.json())  # Direct instantiation for Pydantic 1.x

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
