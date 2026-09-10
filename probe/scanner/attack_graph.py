"""
Attack Graph Engine

Models attack paths as a directed graph for:
- Risk path analysis
- Breach simulation
- Lateral movement modeling
- Critical path identification
"""

from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import json
from pathlib import Path


class NodeType(Enum):
    """Types of nodes in attack graph."""
    INTERNET = "internet"
    ASSET = "asset"  # Server, application, etc.
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    DATA = "data"  # Sensitive data store
    SERVICE = "service"  # Running service
    PRIVILEGE = "privilege"  # User privilege level


class EdgeType(Enum):
    """Types of edges in attack graph."""
    EXPOSES = "exposes"  # Internet exposes service
    HAS = "has"  # Asset has vulnerability
    EXPLOITS = "exploits"  # Vulnerability exploits to...
    LEADS_TO = "leads_to"  # Path leads to
    REQUIRES = "requires"  # Action requires credential
    GRANTS = "grants"  # Exploit grants privilege
    ACCESSES = "accesses"  # Privilege accesses data


@dataclass
class AttackNode:
    """Node in attack graph."""
    id: str
    type: NodeType
    name: str
    properties: Dict = field(default_factory=dict)
    risk_score: float = 0.0
    
    def __hash__(self):
        return hash(self.id)


@dataclass
class AttackEdge:
    """Edge in attack graph."""
    source: str
    target: str
    type: EdgeType
    weight: float = 1.0  # Lower is easier/more likely
    conditions: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash(f"{self.source}->{self.target}")


class AttackGraph:
    """
    Directed graph modeling attack paths.
    
    Nodes: Assets, vulnerabilities, credentials, data
    Edges: Relationships and possible transitions
    """
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, List[AttackEdge]] = defaultdict(list)
        self.reverse_edges: Dict[str, List[AttackEdge]] = defaultdict(list)
        
        # Add internet node as starting point
        self.add_node(AttackNode(
            id="internet",
            type=NodeType.INTERNET,
            name="Internet",
            risk_score=0.0
        ))
    
    def add_node(self, node: AttackNode):
        """Add a node to the graph."""
        self.nodes[node.id] = node
    
    def add_edge(self, edge: AttackEdge):
        """Add an edge to the graph."""
        self.edges[edge.source].append(edge)
        self.reverse_edges[edge.target].append(edge)
    
    def get_node(self, node_id: str) -> Optional[AttackNode]:
        """Get node by ID."""
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[Tuple[AttackNode, AttackEdge]]:
        """Get all neighbors of a node with the connecting edge."""
        result = []
        for edge in self.edges.get(node_id, []):
            target = self.nodes.get(edge.target)
            if target:
                result.append((target, edge))
        return result
    
    def get_predecessors(self, node_id: str) -> List[Tuple[AttackNode, AttackEdge]]:
        """Get all predecessors of a node."""
        result = []
        for edge in self.reverse_edges.get(node_id, []):
            source = self.nodes.get(edge.source)
            if source:
                result.append((source, edge))
        return result
    
    def find_paths(
        self,
        start: str,
        end: str,
        max_length: int = 10,
        min_probability: float = 0.0
    ) -> List[List[AttackEdge]]:
        """
        Find all attack paths from start to end node.
        
        Args:
            start: Starting node ID (usually 'internet')
            end: Target node ID (usually sensitive data)
            max_length: Maximum path length
            min_probability: Minimum path probability threshold
        
        Returns:
            List of paths (each path is list of edges)
        """
        paths = []
        visited = set()
        
        def dfs(current: str, path: List[AttackEdge], current_prob: float):
            if len(path) > max_length:
                return
            
            if current == end:
                if current_prob >= min_probability:
                    paths.append(path.copy())
                return
            
            visited.add(current)
            
            for edge in self.edges.get(current, []):
                if edge.target not in visited:
                    # Calculate path probability
                    edge_prob = 1.0 / edge.weight if edge.weight > 0 else 0.5
                    new_prob = current_prob * edge_prob
                    
                    if new_prob >= min_probability:
                        path.append(edge)
                        dfs(edge.target, path, new_prob)
                        path.pop()
            
            visited.remove(current)
        
        dfs(start, [], 1.0)
        
        # Sort by probability (highest first)
        def path_probability(path: List[AttackEdge]) -> float:
            prob = 1.0
            for edge in path:
                prob *= 1.0 / edge.weight if edge.weight > 0 else 0.5
            return prob
        
        paths.sort(key=path_probability, reverse=True)
        
        return paths
    
    def calculate_node_risk(self, node_id: str) -> float:
        """
        Calculate risk score for a node based on:
        - Its own properties
        - Incoming attack paths
        - Exploitability
        """
        node = self.nodes.get(node_id)
        if not node:
            return 0.0
        
        base_risk = node.risk_score
        
        # Find paths from internet to this node
        paths = self.find_paths("internet", node_id, max_length=5)
        
        if not paths:
            return base_risk
        
        # Risk increases with:
        # - Number of paths (more attack vectors)
        # - Shorter paths (easier to reach)
        # - Lower edge weights (easier exploits)
        
        path_risk = 0.0
        for path in paths[:5]:  # Consider top 5 paths
            path_difficulty = sum(edge.weight for edge in path) / len(path)
            path_likelihood = 1.0 / (1.0 + path_difficulty)
            path_risk += path_likelihood
        
        return min(100.0, base_risk + (path_risk * 25))
    
    def get_critical_paths(self, target_type: NodeType = NodeType.DATA) -> List[Dict]:
        """
        Find critical attack paths to sensitive targets.
        
        Returns:
            List of critical paths with risk analysis
        """
        critical_paths = []
        
        # Find all data nodes
        targets = [n for n in self.nodes.values() if n.type == target_type]
        
        for target in targets:
            paths = self.find_paths("internet", target.id, max_length=8)
            
            if paths:
                for i, path in enumerate(paths[:3]):  # Top 3 paths per target
                    probability = 1.0
                    for edge in path:
                        probability *= 1.0 / edge.weight if edge.weight > 0 else 0.5
                    
                    critical_paths.append({
                        "target": target.name,
                        "target_id": target.id,
                        "path": self._format_path(path),
                        "length": len(path),
                        "probability": probability,
                        "risk_score": self.calculate_node_risk(target.id),
                        "attack_vector": self._classify_attack_vector(path),
                    })
        
        # Sort by risk score
        critical_paths.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return critical_paths
    
    def _format_path(self, edges: List[AttackEdge]) -> List[str]:
        """Format path as human-readable list."""
        if not edges:
            return []
        
        result = []
        for edge in edges:
            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)
            
            if source_node and target_node:
                result.append(f"{source_node.name} --[{edge.type.value}]--> {target_node.name}")
        
        return result
    
    def _classify_attack_vector(self, path: List[AttackEdge]) -> str:
        """Classify the type of attack vector."""
        edge_types = [e.type for e in path]
        
        if EdgeType.CREDENTIAL in edge_types:
            return "credential_based"
        elif EdgeType.VULNERABILITY in edge_types:
            return "exploitation"
        elif any(e.type == EdgeType.PRIVILEGE for e in path):
            return "privilege_escalation"
        else:
            return "direct_access"
    
    def simulate_breach(
        self,
        entry_point: str = "internet",
        simulation_depth: int = 5
    ) -> List[Dict]:
        """
        Simulate a breach from entry point.
        
        Returns:
            List of reachable assets and paths
        """
        reachable = []
        visited = set()
        queue = [(entry_point, [], 1.0)]  # (node, path, probability)
        
        while queue and len(reachable) < 100:
            current_id, path, prob = queue.pop(0)
            
            if current_id in visited or len(path) >= simulation_depth:
                continue
            
            visited.add(current_id)
            current = self.nodes.get(current_id)
            
            if current and current.type in [NodeType.DATA, NodeType.CREDENTIAL, NodeType.PRIVILEGE]:
                reachable.append({
                    "node": current,
                    "path": path.copy(),
                    "probability": prob,
                })
            
            # Add neighbors to queue
            for edge in self.edges.get(current_id, []):
                if edge.target not in visited:
                    new_prob = prob * (1.0 / edge.weight if edge.weight > 0 else 0.5)
                    new_path = path + [edge]
                    queue.append((edge.target, new_path, new_prob))
        
        # Sort by probability
        reachable.sort(key=lambda x: x["probability"], reverse=True)
        
        return reachable
    
    def find_lateral_movement_paths(self, compromised_node: str) -> List[Dict]:
        """
        Find lateral movement paths from a compromised node.
        
        Args:
            compromised_node: ID of initially compromised node
        
        Returns:
            List of possible lateral movement targets
        """
        paths = []
        
        # BFS from compromised node
        visited = {compromised_node}
        queue = [(compromised_node, [], 0)]  # (node, path, hops)
        
        while queue:
            current_id, path, hops = queue.pop(0)
            
            if hops > 3:  # Limit lateral movement hops
                continue
            
            current = self.nodes.get(current_id)
            
            # Find valuable targets for lateral movement
            if current and current.type in [NodeType.SERVICE, NodeType.DATA]:
                if current_id != compromised_node:
                    paths.append({
                        "target": current,
                        "path": path.copy(),
                        "hops": hops,
                        "value": current.risk_score,
                    })
            
            # Continue traversal
            for edge in self.edges.get(current_id, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge], hops + 1))
        
        # Sort by value and ease of access
        paths.sort(key=lambda x: (x["value"] / (x["hops"] + 1)), reverse=True)
        
        return paths
    
    def to_dict(self) -> Dict:
        """Export graph to dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "name": n.name,
                    "risk_score": n.risk_score,
                    "properties": n.properties,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.type.value,
                    "weight": e.weight,
                }
                for edges in self.edges.values()
                for e in edges
            ],
        }
    
    def save(self, path: str):
        """Save graph to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def from_findings(cls, findings: List[Dict], target_url: str) -> "AttackGraph":
        """
        Build attack graph from scan findings.
        
        Args:
            findings: List of scan findings
            target_url: Target URL for context
        
        Returns:
            Populated AttackGraph
        """
        graph = cls()
        
        # Add target as main asset
        asset_id = f"asset:{hash(target_url) % 10000}"
        graph.add_node(AttackNode(
            id=asset_id,
            type=NodeType.ASSET,
            name=target_url,
            properties={"url": target_url},
        ))
        
        # Connect internet to asset
        graph.add_edge(AttackEdge(
            source="internet",
            target=asset_id,
            type=EdgeType.EXPOSES,
            weight=1.0,
        ))
        
        for finding in findings:
            # Create vulnerability node
            vuln_id = f"vuln:{hash(finding.get('title', '')) % 10000}"
            severity = finding.get("severity", "medium")
            risk_scores = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}
            risk = risk_scores.get(severity, 50)
            
            graph.add_node(AttackNode(
                id=vuln_id,
                type=NodeType.VULNERABILITY,
                name=finding.get("title", "Unknown"),
                risk_score=risk,
                properties={"severity": severity, "finding": finding},
            ))
            
            # Asset has vulnerability
            graph.add_edge(AttackEdge(
                source=asset_id,
                target=vuln_id,
                type=EdgeType.HAS,
                weight=1.0,
            ))
            
            # Check for credential exposure
            if "credential" in finding.get("title", "").lower() or \
               ".env" in finding.get("title", "").lower():
                cred_id = f"cred:{hash(finding.get('title', '')) % 10000}"
                graph.add_node(AttackNode(
                    id=cred_id,
                    type=NodeType.CREDENTIAL,
                    name="Exposed Credentials",
                    risk_score=95,
                ))
                
                graph.add_edge(AttackEdge(
                    source=vuln_id,
                    target=cred_id,
                    type=EdgeType.GRANTS,
                    weight=1.5,
                ))
                
                # Credentials lead to data access
                data_id = f"data:{hash(finding.get('title', '')) % 10000}"
                graph.add_node(AttackNode(
                    id=data_id,
                    type=NodeType.DATA,
                    name="Application Data",
                    risk_score=80,
                ))
                
                graph.add_edge(AttackEdge(
                    source=cred_id,
                    target=data_id,
                    type=EdgeType.ACCESSES,
                    weight=1.0,
                ))
        
        return graph
