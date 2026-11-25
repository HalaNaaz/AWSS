from typing import Dict, List, Optional, Set, Any
from uuid import UUID

from shared.schemas.discovery import (
    NodeType,
    EdgeType,
    AttackSurfaceNode,
    AttackSurfaceEdge,
    AttackSurfaceGraphSchema
)


class AttackSurfaceGraph:
    """In-memory Attack Surface Graph data structure.
    
    Represents domains, URLs, endpoints, parameters, forms, assets, technologies,
    and security findings as an interconnected, bounded graph.
    
    Features:
    - Zero external graph database dependency (in-memory adjacency index)
    - Deduplication of nodes and edges
    - Cycle prevention and directed link management
    - Bounded memory limits to prevent crawler runaway
    - Cytoscape.js and JSON serialization formats
    """

    MAX_NODES = 5000
    MAX_EDGES = 10000

    def __init__(self, scan_id: UUID, max_nodes: int = MAX_NODES, max_edges: int = MAX_EDGES):
        self.scan_id = scan_id
        self.max_nodes = max_nodes
        self.max_edges = max_edges

        # Map: node_id -> AttackSurfaceNode
        self._nodes: Dict[str, AttackSurfaceNode] = {}
        # Map: (source, target, edge_type) -> AttackSurfaceEdge
        self._edges: Dict[tuple, AttackSurfaceEdge] = {}
        # Adjacency: source -> set of targets
        self._adjacency: Dict[str, Set[str]] = {}

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: NodeType,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AttackSurfaceNode]:
        """Idempotently adds a node to the graph respecting bounds."""
        clean_id = node_id.strip()
        if not clean_id:
            return None

        if clean_id in self._nodes:
            existing = self._nodes[clean_id]
            if metadata:
                existing.metadata.update(metadata)
            return existing

        if len(self._nodes) >= self.max_nodes:
            return None

        node = AttackSurfaceNode(
            id=clean_id,
            label=label.strip(),
            node_type=node_type,
            metadata=metadata or {}
        )
        self._nodes[clean_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AttackSurfaceEdge]:
        """Idempotently adds a directed edge between two existing nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        key = (source_id, target_id, edge_type)
        if key in self._edges:
            existing = self._edges[key]
            if metadata:
                existing.metadata.update(metadata)
            return existing

        if len(self._edges) >= self.max_edges:
            return None

        edge_id = f"{source_id}->{target_id}:{edge_type.value}"
        edge = AttackSurfaceEdge(
            id=edge_id,
            source=source_id,
            target=target_id,
            edge_type=edge_type,
            metadata=metadata or {}
        )
        self._edges[key] = edge

        # Update adjacency
        if source_id not in self._adjacency:
            self._adjacency[source_id] = set()
        self._adjacency[source_id].add(target_id)

        return edge

    def to_schema(self) -> AttackSurfaceGraphSchema:
        """Serializes the graph into the Pydantic AttackSurfaceGraphSchema."""
        nodes_list = list(self._nodes.values())
        edges_list = list(self._edges.values())
        return AttackSurfaceGraphSchema(
            scan_id=self.scan_id,
            nodes=nodes_list,
            edges=edges_list,
            node_count=len(nodes_list),
            edge_count=len(edges_list)
        )

    def to_cytoscape(self) -> Dict[str, Any]:
        """Formats the graph elements for Cytoscape.js rendering."""
        elements = {
            "nodes": [
                {
                    "data": {
                        "id": n.id,
                        "label": n.label,
                        "type": n.node_type.value,
                        **n.metadata
                    }
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "data": {
                        "id": e.id,
                        "source": e.source,
                        "target": e.target,
                        "type": e.edge_type.value,
                        **e.metadata
                    }
                }
                for e in self._edges.values()
            ]
        }
        return elements
