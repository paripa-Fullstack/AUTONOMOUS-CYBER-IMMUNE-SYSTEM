"""Neo4j client for Knowledge Graph operations in AEGIS."""

import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Client for Neo4j graph database operations.
    
    Provides CRUD operations and Cypher query execution for building
    and querying the security knowledge graph containing:
    - IOC (Indicators of Compromise)
    - CVE (Common Vulnerabilities and Exposures)
    - TTP (Tactics, Techniques, and Procedures)
    - Entities (IPs, domains, users, hosts)
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
        database: str = "neo4j",
    ):
        """Initialize Neo4j client.
        
        Args:
            uri: Neo4j connection URI.
            user: Database username.
            password: Database password.
            database: Database name.
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.driver = None
        self.is_connected = False
        
        logger.info(f"Initialized Neo4jClient for {uri}")

    def connect(self) -> bool:
        """Establish connection to Neo4j database.
        
        Returns:
            True if connection successful, False otherwise.
        """
        try:
            from neo4j import GraphDatabase
            
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                database=self.database,
            )
            
            # Verify connection
            with self.driver.session() as session:
                session.run("MATCH (n) RETURN count(n) LIMIT 1")
            
            self.is_connected = True
            logger.info("Connected to Neo4j successfully")
            return True
            
        except ImportError:
            logger.warning("Neo4j driver not installed, running in mock mode")
            self.is_connected = False
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.is_connected = False
            return False

    def disconnect(self) -> None:
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            self.is_connected = False
            logger.info("Disconnected from Neo4j")

    def create_ioc(
        self,
        ioc_type: str,
        value: str,
        severity: str = "medium",
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Create an Indicator of Compromise node.
        
        Args:
            ioc_type: Type of IOC (ip, domain, hash, url).
            value: IOC value.
            severity: Severity level (low/medium/high/critical).
            confidence: Confidence score (0-1).
            tags: List of tags.
        
        Returns:
            Node ID or None if failed.
        """
        query = """
        CREATE (ioc:IOC {
            type: $type,
            value: $value,
            severity: $severity,
            confidence: $confidence,
            tags: $tags,
            first_seen: datetime(),
            last_seen: datetime(),
            created_at: datetime()
        })
        RETURN elementId(ioc) as id
        """
        
        params = {
            "type": ioc_type.lower(),
            "value": value,
            "severity": severity.lower(),
            "confidence": confidence,
            "tags": tags or [],
        }
        
        return self._execute_write(query, params)

    def create_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        affected_products: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Create a CVE node.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234).
            description: Vulnerability description.
            cvss_score: CVSS severity score.
            affected_products: List of affected products.
            references: List of reference URLs.
        
        Returns:
            Node ID or None if failed.
        """
        query = """
        CREATE (cve:CVE {
            cve_id: $cve_id,
            description: $description,
            cvss_score: $cvss_score,
            affected_products: $affected_products,
            references: $references,
            published_date: datetime(),
            created_at: datetime()
        })
        RETURN elementId(cve) as id
        """
        
        params = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "affected_products": affected_products or [],
            "references": references or [],
        }
        
        return self._execute_write(query, params)

    def create_ttp(
        self,
        ttp_id: str,
        name: str,
        tactic: str,
        technique: str,
        description: str,
    ) -> Optional[str]:
        """Create a TTP (MITRE ATT&CK) node.
        
        Args:
            ttp_id: TTP identifier (e.g., T1059).
            name: Technique name.
            tactic: Tactic category.
            technique: Technique name.
            description: Technique description.
        
        Returns:
            Node ID or None if failed.
        """
        query = """
        CREATE (ttp:TTP {
            ttp_id: $ttp_id,
            name: $name,
            tactic: $tactic,
            technique: $technique,
            description: $description,
            created_at: datetime()
        })
        RETURN elementId(ttp) as id
        """
        
        params = {
            "ttp_id": ttp_id,
            "name": name,
            "tactic": tactic,
            "technique": technique,
            "description": description,
        }
        
        return self._execute_write(query, params)

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Create a relationship between two nodes.
        
        Args:
            from_id: Source node ID.
            to_id: Target node ID.
            relationship_type: Type of relationship.
            properties: Relationship properties.
        
        Returns:
            True if successful, False otherwise.
        """
        query = """
        MATCH (a), (b)
        WHERE elementId(a) = $from_id AND elementId(b) = $to_id
        CREATE (a)-[r:`""" + relationship_type + """`]->(b)
        SET r += $properties
        RETURN true
        """
        
        params = {
            "from_id": from_id,
            "to_id": to_id,
            "properties": properties or {},
        }
        
        result = self._execute_write(query, params)
        return result is not None

    def link_ioc_to_ttp(self, ioc_id: str, ttp_id: str) -> bool:
        """Link an IOC to a TTP.
        
        Args:
            ioc_id: IOC node ID.
            ttp_id: TTP node ID.
        
        Returns:
            True if successful.
        """
        return self.create_relationship(ioc_id, ttp_id, "USES_TECHNIQUE")

    def link_ioc_to_cve(self, ioc_id: str, cve_id: str) -> bool:
        """Link an IOC to a CVE.
        
        Args:
            ioc_id: IOC node ID.
            cve_id: CVE node ID.
        
        Returns:
            True if successful.
        """
        return self.create_relationship(ioc_id, cve_id, "EXPLOITS")

    def find_related_iocs(
        self,
        ioc_value: str,
        max_depth: int = 3,
    ) -> List[Dict[str, Any]]:
        """Find IOCs related to a given IOC.
        
        Args:
            ioc_value: IOC value to search for.
            max_depth: Maximum relationship depth.
        
        Returns:
            List of related IOCs with relationship paths.
        """
        query = """
        MATCH (start:IOC {value: $value})
        OPTIONAL MATCH path = (start)-[*1..$max_depth]-(related:IOC)
        RETURN 
            start.value as source,
            collect(DISTINCT related.value) as related_iocs,
            [rel IN relationships(path) | type(rel)] as relationship_types
        """
        
        params = {"value": ioc_value, "max_depth": max_depth}
        result = self._execute_read(query, params)
        
        if result and len(result) > 0:
            return result[0]
        return []

    def search_by_type(
        self,
        node_type: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search nodes by type with optional filters.
        
        Args:
            node_type: Type of node (IOC, CVE, TTP).
            filters: Additional property filters.
            limit: Maximum results to return.
        
        Returns:
            List of matching nodes.
        """
        where_clauses = []
        params = {"limit": limit}
        
        if filters:
            for key, value in filters.items():
                where_clauses.append(f"n.{key} = ${key}")
                params[key] = value
        
        where_str = " AND ".join(where_clauses)
        where_clause = f"WHERE {where_str}" if where_str else ""
        
        query = f"""
        MATCH (n:{node_type})
        {where_clause}
        RETURN n
        LIMIT $limit
        """
        
        result = self._execute_read(query, params)
        return [record["n"] for record in result] if result else []

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the knowledge graph.
        
        Returns:
            Dictionary with graph statistics.
        """
        queries = {
            "ioc_count": "MATCH (n:IOC) RETURN count(n) as count",
            "cve_count": "MATCH (n:CVE) RETURN count(n) as count",
            "ttp_count": "MATCH (n:TTP) RETURN count(n) as count",
            "relationship_count": "MATCH ()-[r]->() RETURN count(r) as count",
        }
        
        stats = {}
        for key, query in queries.items():
            result = self._execute_read(query)
            stats[key] = result[0]["count"] if result else 0
        
        return stats

    def visualize_subgraph(
        self,
        seed_value: str,
        max_nodes: int = 50,
    ) -> Dict[str, Any]:
        """Extract subgraph for visualization.
        
        Args:
            seed_value: Starting IOC value.
            max_nodes: Maximum nodes to include.
        
        Returns:
            Dictionary with nodes and edges for visualization.
        """
        query = """
        MATCH (start:IOC {value: $value})
        OPTIONAL MATCH (start)-[r]-(neighbor)
        WITH start, collect(DISTINCT neighbor) AS neighbors
        UNWIND neighbors AS n
        RETURN 
            start,
            collect(DISTINCT n) as nodes,
            collect(DISTINCT [(start)-[rel]-(n) | rel]) as relationships
        LIMIT 1
        """
        
        params = {"value": seed_value}
        result = self._execute_read(query, params)
        
        if not result:
            return {"nodes": [], "edges": []}
        
        # Format for visualization
        nodes = []
        edges = []
        
        # This would need proper formatting based on Neo4j response
        return {"nodes": nodes, "edges": edges}

    def _execute_write(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Execute a write query.
        
        Args:
            query: Cypher query.
            params: Query parameters.
        
        Returns:
            Query result or None.
        """
        if not self.is_connected or not self.driver:
            logger.debug(f"Mock write: {query[:50]}...")
            return "mock_id_" + datetime.now().strftime("%Y%m%d%H%M%S")
        
        try:
            with self.driver.session() as session:
                result = session.run(query, **(params or {}))
                record = result.single()
                return record["id"] if record else None
        except Exception as e:
            logger.error(f"Write query failed: {e}")
            return None

    def _execute_read(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """Execute a read query.
        
        Args:
            query: Cypher query.
            params: Query parameters.
        
        Returns:
            List of result records or None.
        """
        if not self.is_connected or not self.driver:
            logger.debug(f"Mock read: {query[:50]}...")
            return [{"mock": True}]
        
        try:
            with self.driver.session() as session:
                result = session.run(query, **(params or {}))
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Read query failed: {e}")
            return []

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
