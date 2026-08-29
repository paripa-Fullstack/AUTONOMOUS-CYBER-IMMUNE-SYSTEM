"""NetFlow parser for AEGIS."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from src.core.exceptions import IngestionError
from src.core.security import validate_ip_address, validate_port

logger = logging.getLogger(__name__)


class NetFlowParser:
    """Parser for NetFlow v5/v9/IPFIX network flow data.

    Extracts and normalizes fields from NetFlow records including
    source/destination IPs, ports, protocol, bytes, and packets.
    """

    # Protocol number to name mapping
    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        89: "OSPF",
        132: "SCTP",
    }

    def __init__(self, version: str = "v5"):
        """Initialize NetFlow parser.

        Args:
            version: NetFlow version (v5, v9, ipfix).
        """
        self.version = version.lower()
        if self.version not in ["v5", "v9", "ipfix"]:
            logger.warning(f"Unsupported NetFlow version: {version}. Using v5 parsing.")
            self.version = "v5"

    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NetFlow record.

        Args:
            raw_data: Raw NetFlow record as dictionary.

        Returns:
            Normalized telemetry dictionary.

        Raises:
            IngestionError: If parsing fails or data is invalid.
        """
        try:
            if self.version == "v5":
                return self._parse_v5(raw_data)
            elif self.version == "v9":
                return self._parse_v9(raw_data)
            else:  # ipfix
                return self._parse_ipfix(raw_data)

        except Exception as e:
            logger.error(f"Failed to parse NetFlow data: {e}")
            raise IngestionError(
                f"NetFlow parsing error: {e}",
                source="netflow",
                raw_data=raw_data,
            )

    def _parse_v5(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NetFlow v5 record.

        NetFlow v5 fixed format fields:
        - src_addr, dst_addr: IP addresses
        - srcport, dstport: Ports
        - prot: Protocol number
        - dOctets, dPkts: Bytes and packets
        """
        src_ip = data.get("src_addr") or data.get("source_ip")
        dst_ip = data.get("dst_addr") or data.get("destination_ip")
        src_port = data.get("srcport") or data.get("source_port", 0)
        dst_port = data.get("dstport") or data.get("destination_port", 0)
        protocol_num = data.get("prot") or data.get("protocol", 0)
        bytes_count = data.get("dOctets") or data.get("bytes", 0)
        packets = data.get("dPkts") or data.get("packets", 0)

        # Validate fields
        if not src_ip or not dst_ip:
            raise ValueError("Missing required IP address fields")

        # Normalize protocol
        protocol = self._normalize_protocol(protocol_num)

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": int(src_port),
            "destination_port": int(dst_port),
            "protocol": protocol,
            "bytes_sent": int(bytes_count),
            "bytes_received": 0,  # NetFlow v5 doesn't distinguish direction
            "packets": int(packets),
            "timestamp": data.get("first") or datetime.utcnow().isoformat(),
            "flow_version": "v5",
            "raw_data": data,
        }

    def _parse_v9(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NetFlow v9 record.

        NetFlow v9 uses templates, so field names may vary.
        """
        # Try common field names for v9
        src_ip = self._get_field(data, ["src_addr", "sourceIPv4Address", "ipv4_src_addr"])
        dst_ip = self._get_field(data, ["dst_addr", "destinationIPv4Address", "ipv4_dst_addr"])
        src_port = self._get_field(data, ["srcport", "sourceTransportPort", "l4_src_port"], 0)
        dst_port = self._get_field(data, ["dstport", "destinationTransportPort", "l4_dst_port"], 0)
        protocol_num = self._get_field(data, ["prot", "protocol", "ipProtocol"], 0)
        bytes_count = self._get_field(data, ["dOctets", "octetDeltaCount", "bytes"], 0)
        packets = self._get_field(data, ["dPkts", "packetDeltaCount", "packets"], 0)

        if not src_ip or not dst_ip:
            raise ValueError("Missing required IP address fields")

        protocol = self._normalize_protocol(protocol_num)

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": int(src_port),
            "destination_port": int(dst_port),
            "protocol": protocol,
            "bytes_sent": int(bytes_count),
            "bytes_received": 0,
            "packets": int(packets),
            "timestamp": data.get("FIRST_SWITCHED") or data.get("observationTime") or datetime.utcnow().isoformat(),
            "flow_version": "v9",
            "raw_data": data,
        }

    def _parse_ipfix(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IPFIX record.

        IPFIX is similar to NetFlow v9 but with standardized information elements.
        """
        return self._parse_v9(data)  # IPFIX parsing is similar to v9

    def _get_field(self, data: Dict[str, Any], field_names: List[str], default: Any = None) -> Any:
        """Get field value trying multiple possible field names.

        Args:
            data: Data dictionary.
            field_names: List of possible field names to try.
            default: Default value if field not found.

        Returns:
            Field value or default.
        """
        for field in field_names:
            if field in data:
                return data[field]
        return default

    def _normalize_protocol(self, protocol_num: int) -> str:
        """Normalize protocol number to name.

        Args:
            protocol_num: IP protocol number.

        Returns:
            Protocol name string.
        """
        if isinstance(protocol_num, str):
            return protocol_num.upper()

        return self.PROTOCOL_MAP.get(protocol_num, f"PROTO_{protocol_num}")

    def validate(self, parsed_data: Dict[str, Any]) -> bool:
        """Validate parsed NetFlow data.

        Args:
            parsed_data: Parsed telemetry dictionary.

        Returns:
            True if valid, False otherwise.
        """
        try:
            # Validate IP addresses
            if not validate_ip_address(parsed_data.get("source_ip", "")):
                return False
            if not validate_ip_address(parsed_data.get("destination_ip", "")):
                return False

            # Validate ports
            if not validate_port(parsed_data.get("source_port", 0)):
                return False
            if not validate_port(parsed_data.get("destination_port", 0)):
                return False

            # Validate protocol
            if not parsed_data.get("protocol"):
                return False

            return True

        except Exception:
            return False
