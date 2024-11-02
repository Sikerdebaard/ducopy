import os
import pytest
from ducopy.rest.client import APIClient


@pytest.fixture(scope="module")
def client() -> APIClient:
    """Fixture to initialize the API client based on DUCOBOX_IP environment variable."""
    duco_ip = os.getenv("DUCOBOX_IP")
    if not duco_ip:
        pytest.skip("DUCOBOX_IP environment variable is not set, skipping tests.")

    base_url = f"https://{duco_ip}"
    client = APIClient(base_url=base_url)
    yield client
    client.close()


def test_get_api_info(client: APIClient) -> None:
    """Test fetching API info."""
    api_info = client.get_api_info()
    assert isinstance(api_info, dict), "API info response should be a dictionary"


def test_get_nodes(client: APIClient) -> None:
    """Test fetching nodes."""
    nodes_response = client.get_nodes()
    assert nodes_response.Nodes, "Nodes response should contain nodes"


def test_get_node_info(client: APIClient) -> None:
    """Test fetching detailed information for a specific node."""
    node_info = client.get_node_info(node_id=1)  # Assuming node ID 1 exists
    assert node_info.Node == 1, "Node info response should match node ID 1"


def test_get_config_node(client: APIClient) -> None:
    """Test fetching configuration settings for a specific node."""
    config_node_response = client.get_config_node(node_id=1)
    assert config_node_response.Node == 1, "Config node response should match node ID 1"


def test_get_logs(client: APIClient) -> None:
    """Test fetching API logs."""
    logs_response = client.get_logs()
    assert isinstance(logs_response, dict), "Logs response should be a dictionary"


def test_get_actions_node(client: APIClient) -> None:
    """Test fetching available actions for a specific node."""
    actions_response = client.get_actions_node(node_id=1)
    assert actions_response.Node == 1, "Actions response should match node ID 1"
