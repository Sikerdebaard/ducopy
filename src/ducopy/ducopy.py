from ducopy.rest.client import APIClient
from ducopy.rest.models import NodesResponse, NodeInfo, ConfigNodeResponse, ActionsResponse
from pydantic import HttpUrl


class DucoPy:
    def __init__(self, base_url: HttpUrl) -> None:
        self.client = APIClient(base_url)

    def get_api_info(self) -> dict:
        return self.client.get_api_info()

    def get_info(self, module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict:
        return self.client.get_info(module=module, submodule=submodule, parameter=parameter)

    def get_nodes(self) -> NodesResponse:
        return self.client.get_nodes()

    def get_node_info(self, node_id: int) -> NodeInfo:
        return self.client.get_node_info(node_id=node_id)

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        return self.client.get_config_node(node_id=node_id)

    def get_action(self, action: str | None = None) -> dict:
        return self.client.get_action(action=action)

    def get_actions_node(self, node_id: int, action: str | None = None) -> ActionsResponse:
        return self.client.get_actions_node(node_id=node_id, action=action)

    def get_logs(self) -> dict:
        return self.client.get_logs()

    def close(self) -> None:
        self.client.close()
