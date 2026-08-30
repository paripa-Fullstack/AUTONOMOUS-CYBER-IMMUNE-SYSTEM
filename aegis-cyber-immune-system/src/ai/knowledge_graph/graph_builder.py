"""Knowledge Graph Builder for AEGIS."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class KnowledgeGraphBuilder:
    """Builds and maintains the security knowledge graph.
    
    Constructs a graph from various security data sources:
    - Threat intelligence feeds
    - Vulnerability databases (CVE)
    - MITRE ATT&CK framework
    - Internal telemetry and alerts
    """

    def __init__(self, neo4j_client=None):
        """Initialize graph builder.
        
        Args:
            neo4j_client: Neo4jClient instance for database operations.
        """
        self.neo4j_client = neo4j_client
        self.node_cache: Dict[str, str] = {}  # value -> node_id mapping
        
        logger.info("Initialized KnowledgeGraphBuilder")

    def build_from_ioc(
        self,
        ioc_data: Dict[str, Any],
    ) -> Optional[str]:
        """Add IOC to knowledge graph.
        
        Args:
            ioc_data: IOC dictionary with type, value, severity, etc.
        
        Returns:
            Node ID if successful.
        """
        if not self.neo4j_client:
            logger.warning("Neo4j client not available, skipping graph build")
            return None
        
        ioc_type = ioc_data.get("type", "unknown")
        value = ioc_data.get("value", "")
        severity = ioc_data.get("severity", "medium")
        confidence = ioc_data.get("confidence", 0.5)
        tags = ioc_data.get("tags", [])
        
        # Check cache
        cache_key = f"ioc_{ioc_type}_{value}"
        if cache_key in self.node_cache:
            return self.node_cache[cache_key]
        
        # Create IOC node
        node_id = self.neo4j_client.create_ioc(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            confidence=confidence,
            tags=tags,
        )
        
        if node_id:
            self.node_cache[cache_key] = node_id
            logger.info(f"Added IOC to graph: {ioc_type}:{value}")
        
        return node_id

    def build_from_cve(
        self,
        cve_data: Dict[str, Any],
    ) -> Optional[str]:
        """Add CVE to knowledge graph.
        
        Args:
            cve_data: CVE dictionary with cve_id, description, cvss_score, etc.
        
        Returns:
            Node ID if successful.
        """
        if not self.neo4j_client:
            return None
        
        cve_id = cve_data.get("cve_id", "")
        description = cve_data.get("description", "")
        cvss_score = cve_data.get("cvss_score", 5.0)
        affected_products = cve_data.get("affected_products", [])
        references = cve_data.get("references", [])
        
        cache_key = f"cve_{cve_id}"
        if cache_key in self.node_cache:
            return self.node_cache[cache_key]
        
        node_id = self.neo4j_client.create_cve(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            affected_products=affected_products,
            references=references,
        )
        
        if node_id:
            self.node_cache[cache_key] = node_id
            logger.info(f"Added CVE to graph: {cve_id}")
        
        return node_id

    def build_from_ttp(
        self,
        ttp_data: Dict[str, Any],
    ) -> Optional[str]:
        """Add TTP to knowledge graph.
        
        Args:
            ttp_data: TTP dictionary with ttp_id, name, tactic, technique.
        
        Returns:
            Node ID if successful.
        """
        if not self.neo4j_client:
            return None
        
        ttp_id = ttp_data.get("ttp_id", "")
        name = ttp_data.get("name", "")
        tactic = ttp_data.get("tactic", "")
        technique = ttp_data.get("technique", "")
        description = ttp_data.get("description", "")
        
        cache_key = f"ttp_{ttp_id}"
        if cache_key in self.node_cache:
            return self.node_cache[cache_key]
        
        node_id = self.neo4j_client.create_ttp(
            ttp_id=ttp_id,
            name=name,
            tactic=tactic,
            technique=technique,
            description=description,
        )
        
        if node_id:
            self.node_cache[cache_key] = node_id
            logger.info(f"Added TTP to graph: {ttp_id}")
        
        return node_id

    def link_entities(
        self,
        from_node_id: str,
        to_node_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Create relationship between two nodes.
        
        Args:
            from_node_id: Source node ID.
            to_node_id: Target node ID.
            relationship_type: Type of relationship.
            properties: Relationship properties.
        
        Returns:
            True if successful.
        """
        if not self.neo4j_client:
            return False
        
        success = self.neo4j_client.create_relationship(
            from_id=from_node_id,
            to_id=to_node_id,
            relationship_type=relationship_type,
            properties=properties,
        )
        
        if success:
            logger.info(f"Created relationship: {from_node_id}-[{relationship_type}]->{to_node_id}")
        
        return success

    def build_attack_chain(
        self,
        iocs: List[Dict[str, Any]],
        ttps: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build an attack chain from IOCs and TTPs.
        
        Args:
            iocs: List of IOC dictionaries.
            ttps: List of TTP dictionaries.
        
        Returns:
            Attack chain information.
        """
        if not self.neo4j_client:
            return {"chain": [], "message": "Neo4j not available"}
        
        # Add all IOCs
        ioc_ids = []
        for ioc in iocs:
            node_id = self.build_from_ioc(ioc)
            if node_id:
                ioc_ids.append(node_id)
        
        # Add all TTPs
        ttp_ids = []
        for ttp in ttps:
            node_id = self.build_from_ttp(ttp)
            if node_id:
                ttp_ids.append(node_id)
        
        # Link IOCs to TTPs (assuming sequential order)
        for i, ioc_id in enumerate(ioc_ids):
            if i < len(ttp_ids):
                self.link_entities(ioc_id, ttp_ids[i], "USES_TECHNIQUE")
        
        # Link TTPs in sequence
        for i in range(len(ttp_ids) - 1):
            self.link_entities(ttp_ids[i], ttp_ids[i + 1], "FOLLOWED_BY")
        
        return {
            "ioc_count": len(ioc_ids),
            "ttp_count": len(ttp_ids),
            "chain_length": len(ttp_ids),
            "message": "Attack chain built successfully",
        }

    def enrich_with_threat_intel(
        self,
        indicator_value: str,
        threat_intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enrich an indicator with threat intelligence.
        
        Args:
            indicator_value: IOC value to enrich.
            threat_intel: Threat intelligence data.
        
        Returns:
            Enrichment results.
        """
        if not self.neo4j_client:
            return {"enriched": False, "message": "Neo4j not available"}
        
        # Find or create IOC
        existing = self.neo4j_client.search_by_type(
            "IOC",
            filters={"value": indicator_value},
            limit=1,
        )
        
        if existing:
            node_id = existing[0].get("elementId", existing[0].get("id"))
        else:
            node_id = self.build_from_ioc({
                "type": threat_intel.get("type", "ip"),
                "value": indicator_value,
                "severity": threat_intel.get("severity", "medium"),
                "confidence": threat_intel.get("confidence", 0.5),
                "tags": threat_intel.get("tags", []),
            })
        
        # Add related CVEs if present
        cve_ids = []
        for cve in threat_intel.get("related_cves", []):
            cve_id = self.build_from_cve(cve)
            if cve_id and node_id:
                self.link_entities(node_id, cve_id, "EXPLOITS")
                cve_ids.append(cve_id)
        
        # Add related TTPs if present
        ttp_ids = []
        for ttp in threat_intel.get("related_ttps", []):
            ttp_id = self.build_from_ttp(ttp)
            if ttp_id and node_id:
                self.link_entities(node_id, ttp_id, "USES_TECHNIQUE")
                ttp_ids.append(ttp_id)
        
        return {
            "enriched": True,
            "node_id": node_id,
            "linked_cves": len(cve_ids),
            "linked_ttps": len(ttp_ids),
        }

    def get_graph_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the knowledge graph.
        
        Returns:
            Dictionary with graph statistics.
        """
        if not self.neo4j_client:
            return {
                "nodes": 0,
                "relationships": 0,
                "message": "Neo4j not available",
            }
        
        stats = self.neo4j_client.get_graph_statistics()
        
        total_nodes = (
            stats.get("ioc_count", 0) +
            stats.get("cve_count", 0) +
            stats.get("ttp_count", 0)
        )
        
        return {
            "total_nodes": total_nodes,
            "ioc_count": stats.get("ioc_count", 0),
            "cve_count": stats.get("cve_count", 0),
            "ttp_count": stats.get("ttp_count", 0),
            "relationship_count": stats.get("relationship_count", 0),
            "cache_size": len(self.node_cache),
        }

    def clear_cache(self) -> None:
        """Clear the node ID cache."""
        self.node_cache.clear()
        logger.info("Cleared node cache")
