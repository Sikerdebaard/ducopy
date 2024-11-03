import os
import pytest
from ducopy.rest.client import APIClient
from ducopy.rest.models import NodesResponse, NodeInfo, ConfigNodeResponse, ActionsResponse


@pytest.fixture(scope="module")
def client() -> APIClient:
    """Fixture to initialize the API client with SSL verification."""
    duco_ip = os.getenv("DUCOBOX_IP")
    if not duco_ip:
        pytest.skip("DUCOBOX_IP environment variable is not set, skipping tests.")

    base_url = f"https://{duco_ip}"
    client = APIClient(base_url=base_url, verify=True)  # SSL verification enabled
    yield client
    client.close()


@pytest.fixture(scope="module")
def client_insecure() -> APIClient:
    """Fixture to initialize the API client without SSL verification."""
    duco_ip = os.getenv("DUCOBOX_IP")
    if not duco_ip:
        pytest.skip("DUCOBOX_IP environment variable is not set, skipping tests.")

    base_url = f"https://{duco_ip}"
    client = APIClient(base_url=base_url, verify=False)  # SSL verification disabled
    yield client
    client.close()


def test_get_api_info(client: APIClient) -> None:
    """Test fetching API info with SSL verification."""
    api_info = client.get_api_info()
    assert isinstance(api_info, dict), "API info response should be a dictionary"


def test_get_api_info_insecure(client_insecure: APIClient) -> None:
    """Test fetching API info without SSL verification."""
    api_info = client_insecure.get_api_info()
    assert isinstance(api_info, dict), "API info response should be a dictionary"


def test_get_nodes(client: APIClient) -> None:
    """Test fetching nodes with SSL verification."""
    nodes_response = client.get_nodes()
    assert isinstance(nodes_response, NodesResponse), "Expected NodesResponse instance"
    assert nodes_response.Nodes, "Nodes response should contain nodes"


def test_get_nodes_insecure(client_insecure: APIClient) -> None:
    """Test fetching nodes without SSL verification."""
    nodes_response = client_insecure.get_nodes()
    assert isinstance(nodes_response, NodesResponse), "Expected NodesResponse instance"
    assert nodes_response.Nodes, "Nodes response should contain nodes"


def test_get_node_info(client: APIClient) -> None:
    """Test fetching detailed information for a specific node with SSL verification."""
    node_info = client.get_node_info(node_id=1)
    assert isinstance(node_info, NodeInfo), "Expected NodeInfo instance"
    assert node_info.Node == 1, "Node info response should match node ID 1"


def test_get_node_info_insecure(client_insecure: APIClient) -> None:
    """Test fetching detailed information for a specific node without SSL verification."""
    node_info = client_insecure.get_node_info(node_id=1)
    assert isinstance(node_info, NodeInfo), "Expected NodeInfo instance"
    assert node_info.Node == 1, "Node info response should match node ID 1"


def test_get_config_node(client: APIClient) -> None:
    """Test fetching configuration settings for a specific node with SSL verification."""
    config_node_response = client.get_config_node(node_id=1)
    assert isinstance(config_node_response, ConfigNodeResponse), "Expected ConfigNodeResponse instance"
    assert config_node_response.Node == 1, "Config node response should match node ID 1"


def test_get_config_node_insecure(client_insecure: APIClient) -> None:
    """Test fetching configuration settings for a specific node without SSL verification."""
    config_node_response = client_insecure.get_config_node(node_id=1)
    assert isinstance(config_node_response, ConfigNodeResponse), "Expected ConfigNodeResponse instance"
    assert config_node_response.Node == 1, "Config node response should match node ID 1"


def test_get_logs(client: APIClient) -> None:
    """Test fetching API logs with SSL verification."""
    logs_response = client.get_logs()
    assert isinstance(logs_response, dict), "Logs response should be a dictionary"


def test_get_logs_insecure(client_insecure: APIClient) -> None:
    """Test fetching API logs without SSL verification."""
    logs_response = client_insecure.get_logs()
    assert isinstance(logs_response, dict), "Logs response should be a dictionary"


def test_get_actions_node(client: APIClient) -> None:
    """Test fetching available actions for a specific node with SSL verification."""
    actions_response = client.get_actions_node(node_id=1)
    assert isinstance(actions_response, ActionsResponse), "Expected ActionsResponse instance"
    assert actions_response.Node == 1, "Actions response should match node ID 1"


def test_get_actions_node_insecure(client_insecure: APIClient) -> None:
    """Test fetching available actions for a specific node without SSL verification."""
    actions_response = client_insecure.get_actions_node(node_id=1)
    assert isinstance(actions_response, ActionsResponse), "Expected ActionsResponse instance"
    assert actions_response.Node == 1, "Actions response should match node ID 1"
