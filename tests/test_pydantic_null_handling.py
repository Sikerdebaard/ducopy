"""Test Pydantic's handling of None values in lists to understand the HA error."""
import pytest
from ducopy.rest.models import NodesInfoResponse, NodeInfo


def test_defensive_filter_removes_none_values():
    """Verify that our defensive filter removes None values from Nodes list."""
    # Our defensive validator filters out None values instead of raising an error
    response = NodesInfoResponse(Nodes=[None])
    
    # Should result in an empty list, not an error
    assert response.Nodes == []
    assert response.Nodes is not None
    assert isinstance(response.Nodes, list)


def test_pydantic_accepts_empty_nodes_list():
    """Verify that empty list is accepted."""
    response = NodesInfoResponse(Nodes=[])
    assert response.Nodes == []
    assert response.Nodes is not None


def test_defensive_filter_with_dict_input():
    """Test that defensive filter works with dict input (simulating API response)."""
    # Simulate API returning {"Nodes": [null]}
    response = NodesInfoResponse(**{"Nodes": [None]})
    
    # Should filter out the None and result in empty list
    assert response.Nodes == []
    assert isinstance(response.Nodes, list)


def test_defensive_filter_with_mixed_nodes():
    """Test that defensive filter removes only None values, keeping valid nodes."""
    valid_node_data = {
        "Node": 1,
        "General": {
            "Type": {"Val": "BOX"},
            "Addr": {"Val": 1},
            "SwVersion": {"Val": "1.0.0"}
        }
    }
    
    another_valid_node = {
        "Node": 2,
        "General": {
            "Type": {"Val": "SENSOR"},
            "Addr": {"Val": 2},
            "SwVersion": {"Val": "2.0.0"}
        }
    }
    
    # Mix of valid nodes and None
    response = NodesInfoResponse(**{"Nodes": [valid_node_data, None, another_valid_node, None]})
    
    # Should filter out None values, keeping only valid nodes
    assert len(response.Nodes) == 2
    assert response.Nodes[0].Node == 1
    assert response.Nodes[1].Node == 2


def test_all_none_values_results_in_empty_list():
    """Test that a list of all None values results in an empty list."""
    response = NodesInfoResponse(**{"Nodes": [None, None, None]})
    
    assert response.Nodes == []
    assert isinstance(response.Nodes, list)

