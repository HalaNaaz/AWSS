import pytest
from uuid import uuid4
from backend.app.scanner.discovery.attack_surface_graph import AttackSurfaceGraph
from shared.schemas.discovery import NodeType, EdgeType


def test_graph_node_and_edge_addition():
    scan_id = uuid4()
    graph = AttackSurfaceGraph(scan_id=scan_id, max_nodes=50, max_edges=100)

    domain_node = graph.add_node("domain:example.com", "example.com", NodeType.DOMAIN)
    ep_node = graph.add_node("ep:https://example.com/api/users", "GET /api/users", NodeType.ENDPOINT)

    assert domain_node is not None
    assert ep_node is not None

    edge = graph.add_edge(domain_node.id, ep_node.id, EdgeType.HOSTED_ON)
    assert edge is not None

    schema = graph.to_schema()
    assert schema.node_count == 2
    assert schema.edge_count == 1


def test_graph_bounded_limits_and_deduplication():
    scan_id = uuid4()
    graph = AttackSurfaceGraph(scan_id=scan_id, max_nodes=5, max_edges=5)

    # Idempotent addition
    n1 = graph.add_node("node:1", "Node 1", NodeType.URL)
    n1_again = graph.add_node("node:1", "Node 1 Updated", NodeType.URL)
    assert n1.id == n1_again.id
    assert len(graph._nodes) == 1

    # Bounds
    for i in range(2, 10):
        graph.add_node(f"node:{i}", f"Node {i}", NodeType.URL)

    assert len(graph._nodes) == 5


def test_graph_cytoscape_export():
    scan_id = uuid4()
    graph = AttackSurfaceGraph(scan_id=scan_id)

    graph.add_node("n1", "Node 1", NodeType.DOMAIN)
    graph.add_node("n2", "Node 2", NodeType.ENDPOINT)
    graph.add_edge("n1", "n2", EdgeType.LINKS_TO)

    cyto = graph.to_cytoscape()
    assert "nodes" in cyto
    assert "edges" in cyto
    assert len(cyto["nodes"]) == 2
    assert len(cyto["edges"]) == 1
    assert cyto["edges"][0]["data"]["source"] == "n1"
    assert cyto["edges"][0]["data"]["target"] == "n2"
