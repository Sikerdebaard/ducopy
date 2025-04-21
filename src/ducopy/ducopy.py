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
    ActionsChangeResponse
)
from pydantic import HttpUrl


class DucoPy:
    def __init__(self, base_url: HttpUrl, verify: bool = True) -> None:
        self.client = APIClient(base_url, verify)

    def raw_get(self, endpoint: str, params: dict = None) -> dict:
        return self.client.raw_get(endpoint=endpoint, params=params)
    
    def change_action_node(self, action: str, value: str, node_id: int) -> ActionsChangeResponse:
        return self.client.post_action_node(action, value, node_id)

    def update_config_node(self, node_id: int, config: ConfigNodeRequest) -> ConfigNodeResponse:
        return self.client.patch_config_node(node_id=node_id, config=config)

    def get_api_info(self) -> dict:
        return self.client.get_api_info()

    def get_info(self, module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict:
        return self.client.get_info(module=module, submodule=submodule, parameter=parameter)

    def get_nodes(self) -> NodesInfoResponse:
        return self.client.get_nodes()

    def get_node_info(self, node_id: int) -> NodeInfo:
        return self.client.get_node_info(node_id=node_id)

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        return self.client.get_config_node(node_id=node_id)

    def get_config_nodes(self) -> NodesResponse:
        return self.client.get_config_nodes()

    def get_action(self, action: str | None = None) -> dict:
        return self.client.get_action(action=action)

    def get_actions_node(self, node_id: int, action: str | None = None) -> ActionsResponse:
        return self.client.get_actions_node(node_id=node_id, action=action)

    def get_logs(self) -> dict:
        return self.client.get_logs()

    def close(self) -> None:
        self.client.close()
