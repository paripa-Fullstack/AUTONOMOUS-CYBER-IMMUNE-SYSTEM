"""STIX (Structured Threat Information eXpression) parser for AEGIS."""

import logging
from typing import Dict, Any, List, Optional

from src.core.exceptions import IngestionError

logger = logging.getLogger(__name__)


class STIXParser:
    """Parser for STIX 2.x threat intelligence data.

    STIX is a standardized language for representing cyber threat information
    including indicators, malware, attack patterns, and threat actors.
    """

    def __init__(self, version: str = "2.1"):
        """Initialize STIX parser.

        Args:
            version: STIX version (2.0, 2.1).
        """
        self.version = version

    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX bundle or object.

        Args:
            raw_data: Raw STIX JSON data.

        Returns:
            Parsed STIX dictionary with normalized fields.

        Raises:
            IngestionError: If parsing fails.
        """
        try:
            if not isinstance(raw_data, dict):
                raise ValueError("STIX data must be a JSON object")

            stix_type = raw_data.get("type", "")

            if stix_type == "bundle":
                return self._parse_bundle(raw_data)
            elif stix_type == "indicator":
                return self._parse_indicator(raw_data)
            elif stix_type == "malware":
                return self._parse_malware(raw_data)
            elif stix_type == "attack-pattern":
                return self._parse_attack_pattern(raw_data)
            elif stix_type == "threat-actor":
                return self._parse_threat_actor(raw_data)
            elif stix_type == "vulnerability":
                return self._parse_vulnerability(raw_data)
            else:
                return self._parse_generic(raw_data)

        except Exception as e:
            logger.error(f"Failed to parse STIX data: {e}")
            raise IngestionError(
                f"STIX parsing error: {e}",
                source="stix",
                raw_data=raw_data,
            )

    def _parse_bundle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX bundle containing multiple objects.

        Args:
            data: STIX bundle dictionary.

        Returns:
            Parsed bundle with objects list.
        """
        objects = []
        for obj in data.get("objects", []):
            parsed_obj = self.parse(obj)
            objects.append(parsed_obj)

        return {
            "type": "bundle",
            "id": data.get("id"),
            "spec_version": data.get("spec_version", self.version),
            "objects_count": len(objects),
            "objects": objects,
        }

    def _parse_indicator(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX indicator object.

        Args:
            data: STIX indicator dictionary.

        Returns:
            Parsed indicator with IOC details.
        """
        pattern = data.get("pattern", "")
        pattern_type = data.get("pattern_type", "stix")

        return {
            "type": "indicator",
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "pattern": pattern,
            "pattern_type": pattern_type,
            "valid_from": data.get("valid_from"),
            "valid_until": data.get("valid_until"),
            "confidence": data.get("confidence", 0),
            "labels": data.get("labels", []),
            "indicator_types": data.get("indicator_types", []),
            "kill_chain_phases": data.get("kill_chain_phases", []),
        }

    def _parse_malware(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX malware object.

        Args:
            data: STIX malware dictionary.

        Returns:
            Parsed malware details.
        """
        return {
            "type": "malware",
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "malware_types": data.get("malware_types", []),
            "is_family": data.get("is_family", False),
            "aliases": data.get("aliases", []),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "operating_system_refs": data.get("operating_system_refs", []),
            "labels": data.get("labels", []),
            "confidence": data.get("confidence", 0),
        }

    def _parse_attack_pattern(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX attack-pattern object (MITRE ATT&CK).

        Args:
            data: STIX attack-pattern dictionary.

        Returns:
            Parsed attack pattern with MITRE mapping.
        """
        return {
            "type": "attack-pattern",
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "external_references": data.get("external_references", []),
            "kill_chain_phases": data.get("kill_chain_phases", []),
            "aliases": data.get("aliases", []),
            "labels": data.get("labels", []),
        }

    def _parse_threat_actor(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX threat-actor object.

        Args:
            data: STIX threat-actor dictionary.

        Returns:
            Parsed threat actor details.
        """
        return {
            "type": "threat-actor",
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "threat_actor_types": data.get("threat_actor_types", []),
            "aliases": data.get("aliases", []),
            "roles": data.get("roles", []),
            "goals": data.get("goals", []),
            "sophistication": data.get("sophistication"),
            "resource_level": data.get("resource_level"),
            "primary_motivation": data.get("primary_motivation"),
            "secondary_motivations": data.get("secondary_motivations", []),
            "labels": data.get("labels", []),
        }

    def _parse_vulnerability(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse STIX vulnerability object (CVE).

        Args:
            data: STIX vulnerability dictionary.

        Returns:
            Parsed vulnerability with CVE details.
        """
        return {
            "type": "vulnerability",
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "external_references": data.get("external_references", []),
            "labels": data.get("labels", []),
        }

    def _parse_generic(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic STIX object.

        Args:
            data: STIX object dictionary.

        Returns:
            Parsed object with common fields.
        """
        return {
            "type": data.get("type", "unknown"),
            "id": data.get("id"),
            "spec_version": data.get("spec_version", self.version),
            "created": data.get("created"),
            "modified": data.get("modified"),
            "data": data,
        }
