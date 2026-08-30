"""Graph Query Engine for AEGIS Knowledge Graph."""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class GraphQueryEngine:
    """Advanced query engine for the security knowledge graph.
    
    Provides complex graph queries for:
    - Path analysis between IOCs
    - Community detection
    - Centrality analysis
    - Pattern matching
    """

    def __init__(self, neo4j_client=None):
        """Initialize query engine.
        
        Args:
            neo4j_client: Neo4jClient instance.
        """
        self.neo4j_client = neo4j_client
        
        logger.info("Initialized GraphQueryEngine")

    def find_attack_paths(
        self,
        source_ioc: str,
        target_ioc: str,
        max_depth: int = 5,
    ) -> List[Dict[str, Any]]:
        """Find attack paths between two IOCs.
        
        Args:
            source_ioc: Source IOC value.
            target_ioc: Target IOC value.
            max_depth: Maximum path length.
        
        Returns:
            List of paths with nodes and relationships.
        """
        if not self.neo4j_client:
            return []
        
        query = """
        MATCH (start:IOC {value: $source})
        MATCH (end:IOC {value: $target})
        MATCH path = (start)-[*1..$max_depth]-(end)
        RETURN 
            [n IN nodes(path) | n.value] as iocs,
            [r IN relationships(path) | type(r)] as relationships,
            length(path) as path_length
        ORDER BY path_length
        LIMIT 10
        """
        
        params = {"source": source_ioc, "target": target_ioc, "max_depth": max_depth}
        results = self.neo4j_client._execute_read(query, params)
        
        return results if results else []

    def get_ioc_neighbors(
        self,
        ioc_value: str,
        depth: int = 2,
        relationship_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Get all neighbors of an IOC up to specified depth.
        
        Args:
            ioc_value: IOC value to search from.
            depth: Relationship depth.
            relationship_types: Filter by relationship types.
        
        Returns:
            Dictionary with neighbors and relationships.
        """
        if not self.neo4j_client:
            return {"neighbors": [], "count": 0}
        
        rel_filter = ""
        if relationship_types:
            rel_types_str = "|".join([f"`{t}`" for t in relationship_types])
            rel_filter = f"-[:{rel_types_str}]"
        
        query = f"""
        MATCH (start:IOC {{value: $value}})
        OPTIONAL MATCH (start){rel_filter}*(neighbor)
        WHERE neighbor IS NOT NULL
        WITH start, collect(DISTINCT neighbor) as neighbors
        UNWIND neighbors as n
        RETURN 
            n.type as type,
            n.value as value,
            n.severity as severity,
            labels(n) as labels
        """
        
        params = {"value": ioc_value}
        results = self.neo4j_client._execute_read(query, params)
        
        return {
            "source": ioc_value,
            "neighbors": results or [],
            "count": len(results) if results else 0,
        }

    def find_common_ttps(
        self,
        ioc_values: List[str],
        min_occurrences: int = 2,
    ) -> List[Dict[str, Any]]:
        """Find TTPs common to multiple IOCs.
        
        Args:
            ioc_values: List of IOC values.
            min_occurrences: Minimum number of IOCs using the TTP.
        
        Returns:
            List of common TTPs with occurrence counts.
        """
        if not self.neo4j_client:
            return []
        
        query = """
        MATCH (ioc:IOC)-[:USES_TECHNIQUE]->(ttp:TTP)
        WHERE ioc.value IN $values
        WITH ttp, count(DISTINCT ioc) as ioc_count
        WHERE ioc_count >= $min_count
        RETURN 
            ttp.ttp_id as ttp_id,
            ttp.name as name,
            ttp.tactic as tactic,
            ttp.technique as technique,
            ioc_count as occurrence_count
        ORDER BY occurrence_count DESC
        """
        
        params = {"values": ioc_values, "min_count": min_occurrences}
        results = self.neo4j_client._execute_read(query, params)
        
        return results if results else []

    def calculate_centrality(
        self,
        node_type: str = "IOC",
        metric: str = "degree",
    ) -> List[Dict[str, Any]]:
        """Calculate centrality metrics for nodes.
        
        Args:
            node_type: Type of nodes to analyze.
            metric: Centrality metric (degree, betweenness, closeness).
        
        Returns:
            List of nodes with centrality scores.
        """
        if not self.neo4j_client:
            return []
        
        # Note: In production, use Neo4j GDS library
        if metric == "degree":
            query = f"""
            MATCH (n:{node_type})
            WITH n, size((n)--()) as degree
            RETURN 
                n.value as value,
                n.type as type,
                degree
            ORDER BY degree DESC
            LIMIT 20
            """
        elif metric == "pagerank":
            # Simplified PageRank approximation
            query = f"""
            MATCH (n:{node_type})
            WITH n, size((n)<--()) as incoming, size((n)-->()) as outgoing
            RETURN 
                n.value as value,
                n.type as type,
                incoming + outgoing * 0.5 as pagerank
            ORDER BY pagerank DESC
            LIMIT 20
            """
        else:
            query = f"""
            MATCH (n:{node_type})
            RETURN n.value as value, n.type as type, 0 as score
            LIMIT 20
            """
        
        results = self.neo4j_client._execute_read(query)
        return results if results else []

    def detect_clusters(
        self,
        min_size: int = 3,
    ) -> List[Dict[str, Any]]:
        """Detect clusters/communities in the graph.
        
        Args:
            min_size: Minimum cluster size.
        
        Returns:
            List of clusters with member IOCs.
        """
        if not self.neo4j_client:
            return []
        
        # Simplified clustering using connected components
        query = """
        MATCH (ioc:IOC)
        WITH collect(ioc) as iocs
        UNWIND iocs as ioc
        MATCH (ioc)-[*1..3]-(neighbor:IOC)
        WITH ioc, collect(DISTINCT neighbor.value) as cluster
        WHERE size(cluster) >= $min_size
        RETURN 
            ioc.value as seed,
            cluster,
            size(cluster) as cluster_size
        ORDER BY cluster_size DESC
        LIMIT 10
        """
        
        params = {"min_size": min_size}
        results = self.neo4j_client._execute_read(query, params)
        
        return results if results else []

    def pattern_match(
        self,
        pattern_name: str,
    ) -> List[Dict[str, Any]]:
        """Match specific attack patterns in the graph.
        
        Args:
            pattern_name: Name of pattern to match.
        
        Returns:
            List of pattern matches.
        """
        patterns = {
            "lateral_movement": """
                MATCH (ioc1:IOC)-[:USES_TECHNIQUE]->(ttp1:TTP {tactic: 'Lateral Movement'})
                MATCH (ioc1)-[:RELATED_TO*1..2]-(ioc2:IOC)
                MATCH (ioc2)-[:USES_TECHNIQUE]->(ttp2:TTP)
                RETURN 
                    ioc1.value as entry_point,
                    ioc2.value as lateral_target,
                    ttp1.name as initial_technique,
                    ttp2.name as followup_technique
                """,
            
            "data_exfiltration": """
                MATCH (ioc:IOC)-[:USES_TECHNIQUE]->(ttp:TTP {tactic: 'Exfiltration'})
                MATCH (ioc)<-[:EXPLOITS]-(cve:CVE)
                RETURN 
                    ioc.value as exfil_indicator,
                    ttp.name as exfil_method,
                    cve.cve_id as exploited_vulnerability
                """,
            
            "persistence": """
                MATCH (ioc:IOC)-[:USES_TECHNIQUE]->(ttp:TTP {tactic: 'Persistence'})
                WITH ioc, collect(ttp) as persistence_ttps
                WHERE size(persistence_ttps) > 1
                RETURN 
                    ioc.value as indicator,
                    [t IN persistence_ttps | t.name] as techniques
                """,
        }
        
        if not self.neo4j_client:
            return []
        
        query = patterns.get(pattern_name)
        if not query:
            logger.warning(f"Unknown pattern: {pattern_name}")
            return []
        
        results = self.neo4j_client._execute_read(query)
        return results if results else []

    def temporal_analysis(
        self,
        start_date: str,
        end_date: str,
        group_by: str = "day",
    ) -> List[Dict[str, Any]]:
        """Analyze graph changes over time.
        
        Args:
            start_date: Start date (ISO format).
            end_date: End date (ISO format).
            group_by: Time grouping (hour/day/week).
        
        Returns:
            Time series data.
        """
        if not self.neo4j_client:
            return []
        
        # Simplified temporal query
        query = """
        MATCH (ioc:IOC)
        WHERE ioc.first_seen >= datetime($start) 
          AND ioc.first_seen <= datetime($end)
        RETURN 
            date(ioc.first_seen) as date,
            count(ioc) as ioc_count,
            count(DISTINCT ioc.type) as type_count
        ORDER BY date
        """
        
        params = {"start": start_date, "end": end_date}
        results = self.neo4j_client._execute_read(query, params)
        
        return results if results else []

    def export_graph_data(self) -> Dict[str, Any]:
        """Export graph data for external analysis.
        
        Returns:
            Dictionary with nodes and edges.
        """
        if not self.neo4j_client:
            return {"nodes": [], "edges": []}
        
        nodes_query = """
        MATCH (n)
        RETURN 
            elementId(n) as id,
            labels(n) as labels,
            properties(n) as properties
        """
        
        edges_query = """
        MATCH (a)-[r]->(b)
        RETURN 
            elementId(a) as source,
            elementId(b) as target,
            type(r) as type,
            properties(r) as properties
        """
        
        nodes = self.neo4j_client._execute_read(nodes_query) or []
        edges = self.neo4j_client._execute_read(edges_query) or []
        
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
