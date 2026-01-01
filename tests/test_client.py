import pytest
import requests_mock
import json
from typing import Any
from ducopy.rest.client import APIClient
from ducopy.rest.models import NodeInfo, ConfigNodeResponse, ActionsResponse, NodesInfoResponse, ActionsChangeResponse

BASE_URL = "http://localhost:5000"


def load_mock_data(filename: str) -> dict[str, Any]:
    """Helper to load JSON mock data from test_data directory."""
    with open(f"tests/test_data/{filename}") as f:
        return json.load(f)


def mock_info_endpoint(mock_requests: requests_mock.Mocker) -> None:
    """Mock the /info endpoint required for API key generation."""
    mock_data = {
        "General": {
            "Lan": {"Mac": {"Val": "00:00:00:00:00:00"}},
            "Board": {"SerialBoardBox": {"Val": "MOCKSERIAL123456"}, "Time": {"Val": 1730471603}},
        }
    }
    mock_requests.get(f"{BASE_URL}/info", json=mock_data)


def mock_detection_endpoint_modern(mock_requests: requests_mock.Mocker) -> None:
    """Mock the detection endpoint for Connectivity Board (modern API)."""
    mock_data = {
        "General": {
            "Lan": {"Mac": {"Val": "00:00:00:00:00:00"}},
            "Board": {"SerialBoardBox": {"Val": "MOCKSERIAL123456"}, "Time": {"Val": 1730471603}},
        }
    }
    mock_requests.get(f"{BASE_URL}/info", json=mock_data)


def mock_detection_endpoint_legacy(mock_requests: requests_mock.Mocker) -> None:
    """Mock the detection endpoint for Communication and Print Board (legacy API)."""
    mock_requests.get(f"{BASE_URL}/info", status_code=404)
    # Mock /boxinfoget for legacy API key generation
    mock_data = {"General": {"Time": 1730471603}}
    mock_requests.get(f"{BASE_URL}/boxinfoget", json=mock_data)


@pytest.fixture
def client() -> APIClient:
    return APIClient(base_url=BASE_URL, auto_detect=False)


@pytest.fixture
def mock_requests() -> Any:  # noqa: ANN401
    with requests_mock.Mocker() as m:
        yield m


def test_get_api_info(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("api_info.json")
    mock_requests.get(f"{BASE_URL}/api", json=mock_data)

    response = client.get_api_info()
    assert response == mock_data


def test_get_nodes(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("nodes.json")
    mock_requests.get(f"{BASE_URL}/info/nodes", json=mock_data)

    # Test the actual client method call
    response = client.get_nodes()
    assert isinstance(response, NodesInfoResponse)
    assert len(response.Nodes) == len(mock_data["Nodes"])


def test_post_action_node(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    # Set generation manually since auto-detect is disabled
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    # Mock get_actions_node for validation
    actions_data = load_mock_data("actions_node_1.json")
    mock_requests.get(f"{BASE_URL}/action/nodes/1", json=actions_data)
    
    mock_data = load_mock_data("set_actions_node_1.json")
    mock_requests.post(f"{BASE_URL}/action/nodes/1", json=mock_data)

    # Test the actual client method call - use AUTO which is valid in actions_node_1.json
    response = client.post_action_node(action="SetVentilationState", value="AUTO", node_id=1)
    assert isinstance(response, ActionsChangeResponse)
    assert response.Code == mock_data.get("Code")
    assert response.Result == mock_data["Result"]


def test_get_node_info(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("node_1.json")
    mock_requests.get(f"{BASE_URL}/info/nodes/1", json=mock_data)

    # Test the actual client method call
    response = client.get_node_info(node_id=1)
    assert isinstance(response, NodeInfo)
    assert response.Node == mock_data["Node"]


def test_get_config_node(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("config_node_1.json")
    mock_requests.get(f"{BASE_URL}/config/nodes/1", json=mock_data)

    # Test the actual client method call
    response = client.get_config_node(node_id=1)
    assert isinstance(response, ConfigNodeResponse)
    assert response.Node == mock_data["Node"]


# Uncomment this test if needed
# def test_get_firmware(client, mock_requests):
#     mock_info_endpoint(mock_requests)
#     mock_data = load_mock_data("firmware.json")
#     mock_requests.get(f"{BASE_URL}/firmware", json=mock_data)

#     firmware_response = FirmwareResponse(**mock_data)  # Instantiate FirmwareResponse directly with data
#     assert isinstance(firmware_response, FirmwareResponse)


def test_get_actions_node(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("actions_node_1.json")
    mock_requests.get(f"{BASE_URL}/action/nodes/1", json=mock_data)

    # Test the actual client method call
    response = client.get_actions_node(node_id=1)
    assert isinstance(response, ActionsResponse)
    assert len(response.Actions) == len(mock_data["Actions"])


def test_get_logs(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"
    
    mock_data = load_mock_data("logs.json")
    mock_requests.get(f"{BASE_URL}/log/api", json=mock_data)

    logs_response = client.get_logs()
    assert logs_response == mock_data

# Tests for Communication and Print Board (legacy API)


def test_post_action_node_legacy(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    """Test post_action_node on Communication and Print Board using GET request."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"
    
    # Mock the GET request to /nodesetoperstate
    mock_requests.get(f"{BASE_URL}/nodesetoperstate", text="SUCCESS")

    response = client.post_action_node(action="OperState", value="AUTO", node_id=1)
    assert isinstance(response, ActionsChangeResponse)
    assert response.Result == "Success"
    assert response.Action == "AUTO"
    assert response.Code is None


def test_post_action_node_legacy_failure(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    """Test post_action_node failure on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"
    
    # Mock the GET request to return FAILED
    mock_requests.get(f"{BASE_URL}/nodesetoperstate", text="FAILED")

    with pytest.raises(ValueError, match="Failed to change node 1 state to INVALID"):
        client.post_action_node(action="OperState", value="INVALID", node_id=1)


def test_get_node_info_legacy(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    """Test get_node_info on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"
    
    # Mock the legacy response format
    mock_data = {
        "node": 1,
        "devtype": "VLVRH",
        "addr": 2,
        "state": "AUTO",
        "ovrl": 255,
        "cerr": 0,
        "mode": "AUTO",
        "snsr": 10,
        "co2": 570,
        "temp": 21.4,
        "rh": 45.5
    }
    mock_requests.get(f"{BASE_URL}/nodeinfoget", json=mock_data)

    response = client.get_node_info(node_id=1)
    assert isinstance(response, NodeInfo)
    assert response.Node == 1
    assert response.General.Type.Val == "VLVRH"
    assert response.Sensor is not None


def test_get_nodes_legacy(client: APIClient, mock_requests: requests_mock.Mocker) -> None:
    """Test get_nodes on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"
    
    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})
    
    # Mock individual node info responses
    for node_id in [1, 2, 3]:
        mock_data = {
            "node": node_id,
            "devtype": "VLVRH",
            "addr": node_id,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0
        }
        mock_requests.get(f"{BASE_URL}/nodeinfoget", json=mock_data)
    
    response = client.get_nodes()
    assert isinstance(response, NodesInfoResponse)
    assert len(response.Nodes) == 3