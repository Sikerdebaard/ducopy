from ducopy.devicetree.communicationboard import CommunicationBoard
from ducopy.devicetree.box import Box
from ducopy.rest.connectivityboard.client import APIClient
from cachetools import TTLCache, cached
from typing import Any


def safe_get(data: Any, *keys: tuple[str]) -> dict[Any] | str | None:  # noqa: ANN401
    """Safely get nested keys from a dict."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


class ConnectivityBoard(CommunicationBoard):
    def __init__(self, url: str, *args: tuple, **kwargs: dict):
        self._cache = {}
        self._url: str = url
        self._client: APIClient = APIClient(url, False)

    @cached(cache=TTLCache(maxsize=1, ttl=60))
    def _get_info(self) -> dict:
        return self._client.raw_get("/info")

    @cached(cache=TTLCache(maxsize=1, ttl=60))
    def _get_info_nodes(self) -> dict:
        return self._client.raw_get("/info/nodes")

    def detect(self, *args: tuple, **kwargs: dict) -> bool:
        return str(safe_get(self._get_info(), "General", "Board", "CommSubTypeName", "Val")).strip() == "CONNECTIVITY"

    def name(self) -> str:
        return "Ducobox Connectivity Board"

    def get_box(self) -> Box:
        print("get_box called")
        info = self._get_info()
        info_nodes = self._get_info_nodes()

        print(info)

        print(info_nodes)
