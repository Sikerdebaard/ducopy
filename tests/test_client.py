import pytest
import requests_mock
import requests.exceptions
import json
from typing import Any, Protocol
import importlib.resources as pkg_resources
from ducopy.rest.client import APIClient
from ducopy.rest.utils import DucoUrlSession, CustomHostNameCheckingAdapter
from requests.adapters import HTTPAdapter
from ducopy import certs
from ducopy.rest.models import (
    NodeInfo,
    ConfigNodeResponse,
    ActionsResponse,
    NodesInfoResponse,
    ActionsChangeResponse,
    NodesResponse,
)

BASE_URL = "http://localhost:5000"


class _RequestLike(Protocol):
    qs: dict[str, list[str]]


class _ContextLike(Protocol):
    status_code: int


def load_mock_data(filename: str) -> dict[str, Any]:
    """Helper to load JSON mock data from test_data directory."""
    with open(f"tests/test_data/{filename}") as f:
        return json.load(f)


def mock_info_endpoint(mock_requests: requests_mock.Mocker) -> None:
    """Mock the /info endpoint required for API key generation."""
    mock_data = {
        "General": {
            "Lan": {"Mac": {"Val": "00:00:00:00:00:00"}},
            "Board": {
                "SerialBoardBox": {"Val": "MOCKSERIAL123456"},
                "Time": {"Val": 1730471603},
            },
        }
    }
    mock_requests.get(f"{BASE_URL}/info", json=mock_data)


def mock_detection_endpoint_modern(mock_requests: requests_mock.Mocker) -> None:
    """Mock the detection endpoint for Connectivity Board (modern API)."""
    mock_data = {
        "General": {
            "Lan": {"Mac": {"Val": "00:00:00:00:00:00"}},
            "Board": {
                "SerialBoardBox": {"Val": "MOCKSERIAL123456"},
                "Time": {"Val": 1730471603},
            },
        }
    }
    mock_requests.get(f"{BASE_URL}/info", json=mock_data)

    # Mock /api endpoint for version info (now fetched for both HTTP and HTTPS)
    api_info = load_mock_data("api_info.json")
    mock_requests.get(f"{BASE_URL}/api", json=api_info)


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


def test_duco_url_session_mounts_custom_adapter_only_for_https() -> None:
    cert_path = str(pkg_resources.files(certs).joinpath("api_cert.pem"))
    session = DucoUrlSession(base_url="http://localhost:5000", verify=cert_path)

    assert isinstance(
        session.get_adapter("https://example.com"), CustomHostNameCheckingAdapter
    )
    assert isinstance(session.get_adapter("http://example.com"), HTTPAdapter)
    assert not isinstance(
        session.get_adapter("http://example.com"), CustomHostNameCheckingAdapter
    )


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


def test_post_action_node(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
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
    response = client.post_action_node(
        action="SetVentilationState", value="AUTO", node_id=1
    )
    assert isinstance(response, ActionsChangeResponse)
    assert response.Code == mock_data.get("Code")
    assert response.Result == mock_data["Result"]


def test_post_action_node_failure_nonzero_code(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that post_action_node raises an error when board returns non-zero error code."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock get_actions_node for validation
    actions_data = load_mock_data("actions_node_1.json")
    mock_requests.get(f"{BASE_URL}/action/nodes/1", json=actions_data)

    # Mock a failure response with non-zero code
    failure_response = {
        "Code": 1,  # Non-zero indicates error
        "Result": "FAILURE: Invalid state",
    }
    mock_requests.post(f"{BASE_URL}/action/nodes/1", json=failure_response)

    # Should raise ValueError
    with pytest.raises(ValueError, match="Failed to perform action.*Error code: 1"):
        client.post_action_node(action="SetVentilationState", value="AUTO", node_id=1)


def test_post_action_node_failure_result(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that post_action_node raises an error when board returns failure result."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock get_actions_node for validation
    actions_data = load_mock_data("actions_node_1.json")
    mock_requests.get(f"{BASE_URL}/action/nodes/1", json=actions_data)

    # Mock a failure response with FAILURE in result (but Code could be None or 0)
    failure_response = {"Code": None, "Result": "FAILURE"}
    mock_requests.post(f"{BASE_URL}/action/nodes/1", json=failure_response)

    # Should raise ValueError
    with pytest.raises(ValueError, match="Failed to perform action.*Result: FAILURE"):
        client.post_action_node(action="SetVentilationState", value="AUTO", node_id=1)


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


def test_get_config_node(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    mock_data = load_mock_data("config_node_1.json")
    mock_requests.get(f"{BASE_URL}/config/nodes/1", json=mock_data)

    # Test the actual client method call
    response = client.get_config_node(node_id=1)
    assert isinstance(response, ConfigNodeResponse)
    assert response.Node == mock_data["Node"]


def test_get_config_nodes_legacy(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_config_nodes on Communication and Print Board - aggregates individual node configs."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock individual node info responses for get_nodes() call
    node_info_responses = {
        1: {
            "node": 1,
            "devtype": "VLVRH",
            "addr": 1,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        2: {
            "node": 2,
            "devtype": "VLVRH",
            "addr": 2,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        3: {
            "node": 3,
            "devtype": "VLVRH",
            "addr": 3,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
    }

    def nodeinfoget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        node_values = request.qs.get("node")
        if not node_values:
            context.status_code = 400
            return {"error": "missing node parameter"}
        node_id = int(node_values[0])
        return node_info_responses.get(node_id, {})

    mock_requests.get(
        f"{BASE_URL}/nodeinfoget",
        additional_matcher=lambda request: "node" in request.qs,
        json=nodeinfoget_callback,
    )

    # Mock individual node config responses (mapped from /config/nodes/{id} to /nodeconfigget?node={id})
    node_config_responses = {
        1: {
            "Node": 1,
            "SerialBoard": "SERIAL1",
            "FlowLvlMan1": {"Id": 196614, "Val": 30, "Min": 0, "Max": 50},
        },
        2: {
            "Node": 2,
            "SerialBoard": "SERIAL2",
            "FlowLvlMan1": {"Id": 196614, "Val": 40, "Min": 0, "Max": 50},
        },
        3: {
            "Node": 3,
            "SerialBoard": "SERIAL3",
            "FlowLvlMan1": {"Id": 196614, "Val": 50, "Min": 0, "Max": 50},
        },
    }

    def nodeconfigget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        node_values = request.qs.get("node")
        if not node_values:
            context.status_code = 400
            return {"error": "missing node parameter"}
        node_id = int(node_values[0])
        return node_config_responses.get(node_id, {})

    mock_requests.get(
        f"{BASE_URL}/nodeconfigget",
        additional_matcher=lambda request: "node" in request.qs,
        json=nodeconfigget_callback,
    )

    # Test the actual method
    response = client.get_config_nodes()
    assert isinstance(response, NodesResponse)
    assert len(response.Nodes) == 3
    # Verify node IDs match
    node_ids = [node.Node for node in response.Nodes]
    assert 1 in node_ids
    assert 2 in node_ids
    assert 3 in node_ids


def test_get_config_nodes_legacy_all_nodes_fail(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that get_config_nodes raises error when ALL node configs fail on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock individual node info responses for get_nodes() call
    node_info_responses = {
        1: {
            "node": 1,
            "devtype": "VLVRH",
            "addr": 1,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        2: {
            "node": 2,
            "devtype": "VLVRH",
            "addr": 2,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        3: {
            "node": 3,
            "devtype": "VLVRH",
            "addr": 3,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
    }

    def nodeinfoget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        node_values = request.qs.get("node")
        if not node_values:
            context.status_code = 400
            return {"error": "missing node parameter"}
        node_id = int(node_values[0])
        return node_info_responses.get(node_id, {})

    mock_requests.get(
        f"{BASE_URL}/nodeinfoget",
        additional_matcher=lambda request: "node" in request.qs,
        json=nodeinfoget_callback,
    )

    # Mock all node config requests to fail (e.g., 500 error)
    mock_requests.get(f"{BASE_URL}/nodeconfigget", status_code=500)

    # Should raise RuntimeError because all node configs failed
    with pytest.raises(
        RuntimeError, match="Failed to fetch configuration for all 3 nodes"
    ):
        client.get_config_nodes()


def test_get_config_nodes_legacy_partial_failure(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that get_config_nodes continues when SOME node configs fail on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock individual node info responses for get_nodes() call
    node_info_responses = {
        1: {
            "node": 1,
            "devtype": "VLVRH",
            "addr": 1,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        2: {
            "node": 2,
            "devtype": "VLVRH",
            "addr": 2,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        3: {
            "node": 3,
            "devtype": "VLVRH",
            "addr": 3,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
    }

    def nodeinfoget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        node_values = request.qs.get("node")
        if not node_values:
            context.status_code = 400
            return {"error": "missing node parameter"}
        node_id = int(node_values[0])
        return node_info_responses.get(node_id, {})

    mock_requests.get(
        f"{BASE_URL}/nodeinfoget",
        additional_matcher=lambda request: "node" in request.qs,
        json=nodeinfoget_callback,
    )

    # Mock responses: node 1 and 3 config succeed, node 2 config fails
    def node_config_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any] | str:
        params = request.qs
        node_id = int(params["node"][0]) if "node" in params else 1

        if node_id == 2:
            context.status_code = 500
            return "Internal Server Error"

        return {
            "Node": node_id,
            "SerialBoard": f"SERIAL{node_id}",
            "FlowLvlMan1": {"Id": 196614, "Val": 30 * node_id, "Min": 0, "Max": 50},
        }

    mock_requests.get(f"{BASE_URL}/nodeconfigget", json=node_config_callback)

    # Should succeed with 2 nodes (1 and 3), tolerating node 2's failure
    response = client.get_config_nodes()
    assert isinstance(response, NodesResponse)
    assert len(response.Nodes) == 2
    # Verify we got configs for nodes 1 and 3 only
    node_ids = [node.Node for node in response.Nodes]
    assert 1 in node_ids
    assert 2 not in node_ids  # Node 2 config failed, so it's excluded
    assert 3 in node_ids


# Uncomment this test if needed
# def test_get_firmware(client, mock_requests):
#     mock_info_endpoint(mock_requests)
#     mock_data = load_mock_data("firmware.json")
#     mock_requests.get(f"{BASE_URL}/firmware", json=mock_data)

#     firmware_response = FirmwareResponse(**mock_data)  # Instantiate FirmwareResponse directly with data
#     assert isinstance(firmware_response, FirmwareResponse)


def test_get_actions_node(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
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


def test_post_action_node_legacy(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
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


def test_post_action_node_legacy_failure(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test post_action_node failure on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock the GET request to return FAILED
    mock_requests.get(f"{BASE_URL}/nodesetoperstate", text="FAILED")

    with pytest.raises(ValueError, match="Failed to change node 1 state to INVALID"):
        client.post_action_node(action="OperState", value="INVALID", node_id=1)


def test_post_action_node_legacy_unsupported_action(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that unsupported actions raise NotImplementedError on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Attempt to use an unsupported action (Reboot, SetParent, etc.)
    with pytest.raises(
        NotImplementedError,
        match="Action 'Reboot' is not supported on Communication and Print Board",
    ):
        client.post_action_node(action="Reboot", value="true", node_id=1)

    with pytest.raises(
        NotImplementedError,
        match="Action 'SetParent' is not supported on Communication and Print Board",
    ):
        client.post_action_node(action="SetParent", value="5", node_id=1)


def test_get_node_info_legacy(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
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
        "rh": 45.5,
    }
    mock_requests.get(f"{BASE_URL}/nodeinfoget", json=mock_data)

    response = client.get_node_info(node_id=1)
    assert isinstance(response, NodeInfo)
    assert response.Node == 1
    assert response.General.Type.Val == "VLVRH"
    assert response.Sensor is not None


def test_get_nodes_legacy(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_nodes on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock individual node info responses keyed by requested node id
    node_responses = {
        1: {
            "node": 1,
            "devtype": "VLVRH",
            "addr": 1,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        2: {
            "node": 2,
            "devtype": "VLVRH",
            "addr": 2,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
        3: {
            "node": 3,
            "devtype": "VLVRH",
            "addr": 3,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        },
    }

    def nodeinfoget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        node_values = request.qs.get("node")
        if not node_values:
            context.status_code = 400
            return {"error": "missing node parameter"}

        node_id = int(node_values[0])
        mock_data = node_responses.get(node_id)
        if mock_data is None:
            context.status_code = 404
            return {"error": f"unknown node {node_id}"}

        return mock_data

    mock_requests.get(
        f"{BASE_URL}/nodeinfoget",
        additional_matcher=lambda request: "node" in request.qs,
        json=nodeinfoget_callback,
    )

    response = client.get_nodes()
    assert isinstance(response, NodesInfoResponse)
    assert len(response.Nodes) == 3


def test_get_nodes_legacy_all_nodes_fail(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that get_nodes raises error when ALL nodes fail on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock all node info requests to fail (e.g., 500 error)
    mock_requests.get(f"{BASE_URL}/nodeinfoget", status_code=500)

    # Should raise RuntimeError because all nodes failed
    with pytest.raises(
        RuntimeError, match="Failed to fetch information for all 3 nodes"
    ):
        client.get_nodes()


def test_get_nodes_legacy_partial_failure(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that get_nodes continues when SOME nodes fail on Communication and Print Board."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock nodelist response
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1, 2, 3]})

    # Mock responses: node 1 and 3 succeed, node 2 fails
    def node_info_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any] | str:
        params = request.qs
        node_id = int(params["node"][0]) if "node" in params else 1

        if node_id == 2:
            context.status_code = 500
            return "Internal Server Error"

        return {
            "node": node_id,
            "devtype": "VLVRH",
            "addr": node_id,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
        }

    mock_requests.get(f"{BASE_URL}/nodeinfoget", json=node_info_callback)

    # Should succeed with 3 nodes (1, 2 with placeholder, and 3)
    # New behavior: maintains expected node count with placeholder for failed nodes
    response = client.get_nodes()
    assert isinstance(response, NodesInfoResponse)
    assert len(response.Nodes) == 3
    # Verify we got all node IDs from nodelist
    node_ids = [node.Node for node in response.Nodes]
    assert 1 in node_ids
    assert 2 in node_ids
    assert 3 in node_ids
    # Verify node 2 is a placeholder with ERROR_FETCH_FAILED type
    node_2 = next(node for node in response.Nodes if node.Node == 2)
    assert node_2.General.Type.Val == "ERROR_FETCH_FAILED"
    # Verify nodes 1 and 3 have valid data
    node_1 = next(node for node in response.Nodes if node.Node == 1)
    node_3 = next(node for node in response.Nodes if node.Node == 3)
    assert node_1.General.Type.Val == "VLVRH"
    assert node_3.General.Type.Val == "VLVRH"


def test_get_info_legacy(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_info on Communication and Print Board with value wrapping."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock the legacy response format with flat values
    mock_data = {
        "General": {"Time": 1730471603, "SerialNumber": "ABC123"},
        "Network": {"IpAddress": "192.168.1.100", "MacAddress": "00:11:22:33:44:55"},
    }
    mock_requests.get(f"{BASE_URL}/boxinfoget", json=mock_data)

    response = client.get_info()

    # Verify the response has been transformed to {"Val": value} format
    assert isinstance(response, dict)
    assert "General" in response
    assert "Time" in response["General"]
    assert response["General"]["Time"] == {"Val": 1730471603}
    assert response["General"]["SerialNumber"] == {"Val": "ABC123"}
    assert "Network" in response
    assert response["Network"]["IpAddress"] == {"Val": "192.168.1.100"}
    assert response["Network"]["MacAddress"] == {"Val": "00:11:22:33:44:55"}


def test_normalize_node_structure(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that the library normalizes invalid node structures from the API."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock a response with invalid General field (integer instead of dict)
    # This simulates an API quirk where General is returned as an int
    mock_data = {
        "Node": 1,
        "General": 12345,  # Invalid: should be a dict
        "NetworkDuco": None,
        "Ventilation": None,
        "Sensor": None,
    }
    mock_requests.get(f"{BASE_URL}/info/nodes/1", json=mock_data)

    # The library should normalize this and not crash
    response = client.get_node_info(node_id=1)

    # Verify the response was normalized
    assert isinstance(response, NodeInfo)
    assert response.Node == 1
    # General should be normalized to a dict
    assert response.General is not None
    assert isinstance(response.General.dict(), dict)


# Tests for get_board_info()


def test_get_board_info_modern(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Connectivity Board (modern API)."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock the /info endpoint response
    mock_data = load_mock_data("board_info_modern.json")
    mock_requests.get(f"{BASE_URL}/info", json=mock_data)

    board_info = client.get_board_info()

    # Verify the normalized output schema
    assert isinstance(board_info, dict)
    assert "Mac" in board_info
    assert "Serial" in board_info
    assert "SwVersion" in board_info
    assert "Uptime" in board_info

    # Verify the values match expected data
    assert board_info["Mac"] == "AA:BB:CC:DD:EE:FF"
    assert board_info["Serial"] == "CONN12345678"
    assert board_info["SwVersion"] == "2.0.6.0"
    assert board_info["Uptime"] is None  # Modern boards don't return uptime


def test_get_board_info_legacy_with_cached_info(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Communication/Print Board with cached device info."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Pre-cache device info to simulate already initialized client
    client._mac_address = "00:08:5f:35:a8:0f"
    client._board_serial = "PRSN21401066"
    client._board_swversion = "16036.13.4.0"
    client._board_uptime = 2452
    client._device_info_cached = True

    # Mock the legacy /nodelist endpoint for BOX node lookup.
    # Legacy clients expect {"nodelist": [...]} here, not the modern {"Nodes": [...]} shape.
    # Note: SwVersion should come from cached _board_swversion, not from BOX node.
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": ["BOX"]})

    board_info = client.get_board_info()

    # Verify the normalized output schema
    assert isinstance(board_info, dict)
    assert "Mac" in board_info
    assert "Serial" in board_info
    assert "SwVersion" in board_info
    assert "Uptime" in board_info

    # Verify the values match cached data and BOX node
    assert board_info["Mac"] == "00:08:5f:35:a8:0f"
    assert board_info["Serial"] == "PRSN21401066"
    assert board_info["SwVersion"] == "16036.13.4.0"
    assert board_info["Uptime"] == 2452


def test_get_board_info_legacy_without_cached_info(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Communication/Print Board without cached device info."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # No cached info
    client._device_info_cached = False

    # Mock the /boardinfo endpoint for device info caching
    boardinfo_data = load_mock_data("board_info_legacy.json")
    mock_requests.get(f"{BASE_URL}/boardinfo", json=boardinfo_data)

    # Mock the legacy /nodelist endpoint for BOX node lookup
    nodes_data = load_mock_data("nodes_legacy_with_box.json")
    legacy_nodes_data = {
        "nodelist": nodes_data.get("nodelist", nodes_data.get("Nodes", []))
    }
    mock_requests.get(f"{BASE_URL}/nodelist", json=legacy_nodes_data)

    board_info = client.get_board_info()

    # Verify the normalized output schema
    assert isinstance(board_info, dict)
    assert "Mac" in board_info
    assert "Serial" in board_info
    assert "SwVersion" in board_info
    assert "Uptime" in board_info

    # Verify the values match /boardinfo and BOX node
    assert board_info["Mac"] == "00:08:5f:35:a8:0f"
    assert board_info["Serial"] == "PRSN21401066"
    assert board_info["SwVersion"] == "16036.13.4.0"
    assert board_info["Uptime"] == 2452

    # Verify device info was cached
    assert client._device_info_cached is True
    assert client._mac_address == "00:08:5f:35:a8:0f"
    assert client._board_serial == "PRSN21401066"
    assert client._board_swversion == "16036.13.4.0"
    assert client._board_uptime == 2452


def test_get_board_info_legacy_no_box_node(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Communication/Print Board when BOX node is not found."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Pre-cache device info
    client._mac_address = "00:08:5f:35:a8:0f"
    client._board_serial = "PRSN21401066"
    client._board_swversion = "16036.13.4.0"  # Cached from /boardinfo
    client._board_uptime = 2452
    client._device_info_cached = True

    # Mock the /nodelist endpoint without BOX node
    mock_data = {
        "Nodes": [
            {
                "Node": 2,
                "General": {
                    "Type": {"Val": "SENSOR"},
                    "Addr": 2,
                    "SwVersion": {"Val": "16036.13.4.0"},
                },
            }
        ]
    }
    mock_requests.get(f"{BASE_URL}/nodelist", json=mock_data)

    board_info = client.get_board_info()

    # Verify the normalized output schema
    assert isinstance(board_info, dict)
    assert "Mac" in board_info
    assert "Serial" in board_info
    assert "SwVersion" in board_info
    assert "Uptime" in board_info

    # Verify MAC, Serial, and SwVersion from cached /boardinfo (no BOX node needed)
    assert board_info["Mac"] == "00:08:5f:35:a8:0f"
    assert board_info["Serial"] == "PRSN21401066"
    assert board_info["SwVersion"] == "16036.13.4.0"  # From cached _board_swversion
    assert board_info["Uptime"] == 2452


def test_get_board_info_legacy_nodes_fetch_fails(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Communication/Print Board when fetching nodes fails."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Pre-cache device info but WITHOUT swversion to trigger BOX node fallback
    client._mac_address = "00:08:5f:35:a8:0f"
    client._board_serial = "PRSN21401066"
    client._board_swversion = (
        None  # Not available from /boardinfo - will trigger get_nodes() fallback
    )
    client._board_uptime = 2452
    client._device_info_cached = True

    # Mock the /nodelist endpoint to fail (simulates nodes fetch failure)
    mock_requests.get(f"{BASE_URL}/nodelist", status_code=500)

    board_info = client.get_board_info()

    # Verify the normalized output schema
    assert isinstance(board_info, dict)
    assert "Mac" in board_info
    assert "Serial" in board_info
    assert "SwVersion" in board_info
    assert "Uptime" in board_info

    # Verify MAC, Serial, and Uptime from cached /boardinfo
    assert board_info["Mac"] == "00:08:5f:35:a8:0f"
    assert board_info["Serial"] == "PRSN21401066"
    # SwVersion should be None since /boardinfo didn't have it and nodes fetch failed
    assert board_info["SwVersion"] is None
    assert board_info["Uptime"] == 2452


def test_get_board_info_legacy_swversion_fallback_to_box_node(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test get_board_info on Communication/Print Board falls back to BOX node when cached swversion is None."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Pre-cache device info but without swversion (simulates old /boardinfo that doesn't include it)
    client._mac_address = "00:08:5f:35:a8:0f"
    client._board_serial = "PRSN21401066"
    client._board_swversion = None  # Not available from /boardinfo
    client._board_uptime = 2452
    client._device_info_cached = True

    # Mock the legacy /nodelist endpoint to return integer node IDs
    mock_requests.get(f"{BASE_URL}/nodelist", json={"nodelist": [1]})

    # Mock the legacy /nodeinfoget lookup used to fetch per-node details.
    # Return proper legacy response structure with integer node ID and required fields
    def nodeinfoget_callback(
        request: _RequestLike, context: _ContextLike
    ) -> dict[str, Any]:
        query_values = {key.lower(): value for key, value in request.qs.items()}
        requested_node = None
        for key in ("node", "nodeid", "nodename", "id", "name"):
            values = query_values.get(key)
            if values:
                requested_node = values[0]
                break

        assert requested_node == "1"  # Should be integer node ID
        # Return legacy-shaped response with required fields for Pydantic validation
        return {
            "node": 1,
            "devtype": "BOX",
            "addr": 1,
            "state": "AUTO",
            "ovrl": 255,
            "cerr": 0,
            "sw": "16036.13.4.0",
        }

    # Mock /boxinfoget for BOX node (node 1) energy data merge
    mock_requests.get(f"{BASE_URL}/boxinfoget", json={})

    mock_requests.get(f"{BASE_URL}/nodeinfoget", json=nodeinfoget_callback)

    board_info = client.get_board_info()

    # Verify SwVersion comes from BOX node as fallback
    assert board_info["Mac"] == "00:08:5f:35:a8:0f"
    assert board_info["Serial"] == "PRSN21401066"
    assert board_info["SwVersion"] == "16036.13.4.0"  # From BOX node fallback
    assert board_info["Uptime"] == 2452


def test_nodes_response_never_none(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that NodesInfoResponse.Nodes is never None, always a list (possibly empty)."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock an empty nodes response
    mock_requests.get(f"{BASE_URL}/info/nodes", json={"Nodes": []})

    response = client.get_nodes()

    # Verify Nodes is a list, not None
    assert isinstance(response, NodesInfoResponse)
    assert response.Nodes is not None
    assert isinstance(response.Nodes, list)
    assert len(response.Nodes) == 0


def test_serialized_nodes_never_none(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that individual nodes in serialized response are never None."""
    mock_detection_endpoint_modern(mock_requests)
    client._generation = "modern"
    client._board_type = "Connectivity Board"

    # Mock a response with actual nodes
    mock_data = load_mock_data("nodes.json")
    mock_requests.get(f"{BASE_URL}/info/nodes", json=mock_data)

    response = client.get_nodes()

    # Serialize to dict (simulating what Home Assistant might do)
    try:
        # Pydantic v2
        response_dict = response.model_dump()
    except AttributeError:
        # Pydantic v1
        response_dict = response.dict()

    # Verify no None values in Nodes list
    assert "Nodes" in response_dict
    assert isinstance(response_dict["Nodes"], list)
    assert len(response_dict["Nodes"]) > 0

    # Check that each node in the serialized list is a dict, not None
    for i, node in enumerate(response_dict["Nodes"]):
        assert node is not None, f"Node at index {i} is None in serialized response"
        assert isinstance(node, dict), f"Node at index {i} is not a dict: {type(node)}"
        # Verify critical fields exist
        assert "Node" in node, f"Node at index {i} missing 'Node' field"


def test_detect_generation_populates_api_versions(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that detect_generation() populates API version properties for modern boards."""
    mock_detection_endpoint_modern(mock_requests)

    # Trigger detection
    client.detect_generation()

    # Verify generation detected correctly
    assert client.generation == "modern"
    assert client.is_modern_api is True
    assert client.is_legacy_api is False

    # Verify API version properties are populated (not None)
    assert client.api_version is not None
    assert client.public_api_version is not None

    # Verify values match the mock data
    assert client.api_version == "MOCKAPI 2.0.6.0"
    assert client.public_api_version == "MOCK 2.0"


def test_modern_node_calibration_data_preserved(client: APIClient) -> None:
    """Test that calibration data from Ventilation.Calibration is preserved in Ventilation section."""
    # Mock modern API response with nested Calibration data
    mock_data = {
        "Node": 1,
        "General": {"Type": {"Id": None, "Val": "BOX"}, "Addr": 1},
        "Ventilation": {
            "State": {"Val": "AUTO"},
            "Calibration": {
                "Valid": {"Val": True},
                "State": {"Val": "COMPLETED"},
                "Error": {"Val": 0},
            },
        },
    }

    # Transform the data
    transformed = client._transform_modern_node_info(mock_data)

    # Create NodeInfo object to verify fields are preserved
    node_info = NodeInfo(**transformed)

    # Verify calibration data is now in Ventilation section (not dropped)
    assert node_info.Ventilation is not None
    assert node_info.Ventilation.CalibIsValid is not None
    assert node_info.Ventilation.CalibState is not None
    assert node_info.Ventilation.CalibError is not None

    # Verify the values are correctly extracted from {"Val": ...} format
    assert node_info.Ventilation.CalibIsValid is True
    assert node_info.Ventilation.CalibState == "COMPLETED"
    assert node_info.Ventilation.CalibError == 0


def test_detect_generation_ssl_error_with_https() -> None:
    """Test that SSLError when using HTTPS raises helpful ConnectionError about using HTTP."""
    https_url = "https://localhost:5000"

    with requests_mock.Mocker() as mock_requests:
        # Simulate SSLError when trying to connect to HTTP-only legacy board via HTTPS
        # This often happens with "wrong version number" or similar SSL errors
        mock_requests.get(
            f"{https_url}/info",
            exc=requests.exceptions.SSLError(
                "HTTPSConnectionPool(host='localhost', port=5000): Max retries exceeded with url: /info (Caused by SSLError(SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1000)')))"
            ),
        )

        client = APIClient(base_url=https_url, verify=False, auto_detect=False)

        # Should raise ConnectionError with helpful message about using HTTP
        with pytest.raises(ConnectionError) as exc_info:
            client.detect_generation()

        # Verify the error message guides user to use HTTP instead
        error_message = str(exc_info.value)
        assert "http://" in error_message.lower()
        assert "https://" in error_message.lower()
        assert "Communication and Print Board" in error_message


def test_ssl_error_fails_fast_without_retry() -> None:
    """Test that SSL errors fail fast without retry delays."""
    https_url = "https://localhost:5000"

    with requests_mock.Mocker() as mock_requests:
        # Simulate SSLError - should not be retried
        mock_requests.get(
            f"{https_url}/info",
            exc=requests.exceptions.SSLError("SSL: WRONG_VERSION_NUMBER"),
        )

        client = APIClient(base_url=https_url, verify=False, auto_detect=False)

        with pytest.raises(ConnectionError):
            client.detect_generation()

        # Verify only one request was made (no retries)
        assert len(mock_requests.request_history) == 1


def test_raw_post_default_content_type(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that raw_post sets Content-Type: application/json by default."""
    # Set API key directly to avoid /info parsing dependency
    client.session.api_key = "test-api-key"
    client.session.api_key_timestamp = 9999999999

    mock_requests.post(f"{client.base_url}/test", json={"result": "success"})

    # Call with dict data (no explicit content_type)
    client.raw_post("/test", data={"key": "value"})

    # Verify Content-Type was set to application/json
    assert mock_requests.last_request.headers["Content-Type"] == "application/json"


def test_raw_post_custom_content_type(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that raw_post allows custom Content-Type header."""
    # Set API key directly to avoid /info parsing dependency
    client.session.api_key = "test-api-key"
    client.session.api_key_timestamp = 9999999999

    mock_requests.post(f"{client.base_url}/test", json={"result": "success"})

    # Call with string data and custom content type
    client.raw_post("/test", data="plain text content", content_type="text/plain")

    # Verify Content-Type was set to text/plain
    assert mock_requests.last_request.headers["Content-Type"] == "text/plain"


def test_raw_post_no_content_type(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that raw_post can omit Content-Type header when set to None."""
    # Set API key directly to avoid /info parsing dependency
    client.session.api_key = "test-api-key"
    client.session.api_key_timestamp = 9999999999

    mock_requests.post(f"{client.base_url}/test", json={"result": "success"})

    # Call with string data and no content type
    client.raw_post("/test", data="raw content", content_type=None)

    # Verify Content-Type header was not set
    assert "Content-Type" not in mock_requests.last_request.headers


def test_raw_patch_custom_content_type(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that raw_patch allows custom Content-Type header."""
    # Set API key directly to avoid /info parsing dependency
    client.session.api_key = "test-api-key"
    client.session.api_key_timestamp = 9999999999

    mock_requests.patch(f"{client.base_url}/test", json={"result": "success"})

    # Call with string data and custom content type
    client.raw_patch("/test", data="<xml>content</xml>", content_type="application/xml")

    # Verify Content-Type was set to application/xml
    assert mock_requests.last_request.headers["Content-Type"] == "application/xml"


def test_get_node_info_legacy_energy_caching(
    client: APIClient, mock_requests: requests_mock.Mocker
) -> None:
    """Test that energy data for node_id=1 is cached to reduce redundant /boxinfoget calls."""
    mock_detection_endpoint_legacy(mock_requests)
    client._generation = "legacy"
    client._board_type = "Communication and Print Board"

    # Mock the node info response
    node_data = {
        "node": 1,
        "devtype": "BOX",
        "addr": 0,
        "state": "AUTO",
    }
    mock_requests.get(f"{BASE_URL}/nodeinfoget", json=node_data)

    # Mock the boxinfoget response with energy data
    box_data = {
        "General": {"Time": 1730471603},
        "EnergyInfo": {"Power": {"Val": 150}},
        "EnergyFan": {"Speed": {"Val": 2500}},
    }
    mock_requests.get(f"{BASE_URL}/boxinfoget", json=box_data)

    # First call - should fetch from /boxinfoget
    node_info_1 = client.get_node_info(node_id=1)
    assert node_info_1.Node == 1

    # Count how many times /boxinfoget was called (excluding the one from mock_detection_endpoint_legacy)
    boxinfoget_calls_before = len(
        [req for req in mock_requests.request_history if "/boxinfoget" in req.url]
    )

    # Second call - should use cached data
    node_info_2 = client.get_node_info(node_id=1)
    assert node_info_2.Node == 1

    # Verify /boxinfoget wasn't called again (count should be the same)
    boxinfoget_calls_after = len(
        [req for req in mock_requests.request_history if "/boxinfoget" in req.url]
    )

    # Should only have 1 additional call (from first get_node_info), not 2
    # The mock_detection_endpoint_legacy also calls /boxinfoget once, so we compare before/after
    assert (
        boxinfoget_calls_after - boxinfoget_calls_before == 0
    ), "Energy data should be cached, but /boxinfoget was called again"
