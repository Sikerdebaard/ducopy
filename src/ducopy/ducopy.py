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
from ducopy.rest.client import APIClient
from ducopy.rest.models import (
    NodesResponse,
    NodeInfo,
    ConfigNodeResponse,
    ActionsResponse,
    ConfigNodeRequest,
    NodesInfoResponse,
    ActionsChangeResponse,
)
from pydantic import HttpUrl


class DucoPy:
    """A facade for interacting with the Duco API."""

    def __init__(self, base_url: HttpUrl, verify: bool = True) -> None:
        """Initialize the DucoPy facade with the base URL and verification option.

        Args:
            base_url (HttpUrl): The base URL of the Duco API.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """
        self.client = APIClient(base_url, verify)

    def raw_post(self, endpoint: str, data: str | None = None) -> dict:
        """Perform a raw POST request to the specified endpoint.

        Args:
            endpoint (str): The endpoint to send the POST request to (e.g., "/api").
            data (dict, optional): The data to include in the request body. Defaults to None.
            params (dict, optional): Query parameters to include in the request. Defaults to None.

        Returns:
            dict: JSON response from the server.
        """
        return self.client.raw_post(endpoint=endpoint, data=data)

    def raw_patch(self, endpoint: str, data: str | None = None) -> dict:
        """Perform a raw PATCH request to the specified endpoint.

        Args:
            endpoint (str): The endpoint to send the PATCH request to (e.g., "/api").
            data (dict, optional): The data to include in the request body. Defaults to None.
            params (dict, optional): Query parameters to include in the request. Defaults to None.

        Returns:
            dict: JSON response from the server.
        """
        return self.client.raw_patch(endpoint=endpoint, data=data)

    def raw_get(self, endpoint: str, params: dict = None) -> dict:
        """Perform a raw GET request to the specified endpoint.

        Args:
            endpoint (str): The endpoint to send the GET request to (e.g., "/api").
            params (dict, optional): Query parameters to include in the request. Defaults to None.

        Returns:
            dict: JSON response from the server.
        """
        return self.client.raw_get(endpoint=endpoint, params=params)

    def change_action_node(self, action: str, value: str, node_id: int) -> ActionsChangeResponse:
        """Change the action for a specific node.

        Args:
            action (str): The action to perform.
            value (str): The value associated with the action.
            node_id (int): The ID of the node to perform the action on.

        Returns:
            ActionsChangeResponse: The response from the server after changing the action.
        """
        return self.client.post_action_node(action, value, node_id)

    def update_config_node(self, node_id: int, config: ConfigNodeRequest) -> ConfigNodeResponse:
        """Update the configuration for a specific node.

        Args:
            node_id (int): The ID of the node to update.
            config (ConfigNodeRequest): The configuration data to update.

        Returns:
            ConfigNodeResponse: The updated configuration response from the server.
        """
        return self.client.patch_config_node(node_id=node_id, config=config)

    def get_api_info(self) -> dict:
        """Fetch API version and available endpoints.

        Returns:
            dict: API information including version and available endpoints.
        """
        return self.client.get_api_info()

    def get_info(self, module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict:
        """Fetch general API information.

        Args:
            module (str, optional): The module to fetch information for. Defaults to None.
            submodule (str, optional): The submodule to fetch information for. Defaults to None.
            parameter (str, optional): The parameter to fetch information for. Defaults to None.

        Returns:
            dict: General API information.
        """
        return self.client.get_info(module=module, submodule=submodule, parameter=parameter)

    def get_nodes(self) -> NodesInfoResponse:
        """Retrieve a list of all nodes.

        Returns:
            NodesInfoResponse: Information about all nodes.
        """
        return self.client.get_nodes()

    def get_node_info(self, node_id: int) -> NodeInfo:
        """Retrieve detailed information for a specific node.

        Args:
            node_id (int): The ID of the node to fetch information for.

        Returns:
            NodeInfo: Detailed information about the specified node.
        """
        return self.client.get_node_info(node_id=node_id)

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        """Retrieve configuration settings for a specific node.

        Args:
            node_id (int): The ID of the node to fetch configuration for.

        Returns:
            ConfigNodeResponse: Configuration settings for the specified node.
        """
        return self.client.get_config_node(node_id=node_id)

    def get_config_nodes(self) -> NodesResponse:
        """Retrieve the configuration settings for all nodes.

        Returns:
            NodesResponse: Configuration settings for all nodes.
        """
        return self.client.get_config_nodes()

    def get_action(self, action: str | None = None) -> dict:
        """Retrieve action data.

        Args:
            action (str, optional): The action to fetch data for. Defaults to None.

        Returns:
            dict: Action data.
        """
        return self.client.get_action(action=action)

    def get_actions_node(self, node_id: int, action: str | None = None) -> ActionsResponse:
        """Retrieve available actions for a specific node.

        Args:
            node_id (int): The ID of the node to fetch actions for.
            action (str, optional): The action to filter by. Defaults to None.

        Returns:
            ActionsResponse: Available actions for the specified node.
        """
        return self.client.get_actions_node(node_id=node_id, action=action)

    def get_logs(self) -> dict:
        """Retrieve API logs.

        Returns:
            dict: API logs.
        """
        return self.client.get_logs()

    def close(self) -> None:
        """Close the HTTP session.

        This method should be called to clean up resources.
        """
        self.client.close()
