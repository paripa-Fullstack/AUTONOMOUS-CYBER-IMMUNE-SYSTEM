"""Syslog parser for AEGIS."""

import logging
import re
from typing import Dict, Any, Optional
from datetime import datetime

from src.core.exceptions import IngestionError

logger = logging.getLogger(__name__)


class SyslogParser:
    """Parser for Syslog messages (RFC 3164 and RFC 5424).

    Extracts timestamp, hostname, severity, facility, and message
    from syslog entries.
    """

    # Syslog severity levels
    SEVERITY_MAP = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG",
    }

    # Syslog facilities
    FACILITY_MAP = {
        0: "KERN",
        1: "USER",
        2: "MAIL",
        3: "DAEMON",
        4: "AUTH",
        5: "SYSLOG",
        6: "LPR",
        7: "NEWS",
        8: "UUCP",
        9: "CRON",
        10: "AUTHPRIV",
        11: "FTP",
        16: "LOCAL0",
        17: "LOCAL1",
        18: "LOCAL2",
        19: "LOCAL3",
        20: "LOCAL4",
        21: "LOCAL5",
        22: "LOCAL6",
        23: "LOCAL7",
    }

    # RFC 3164 pattern
    RFC3164_PATTERN = re.compile(
        r"^<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )

    # RFC 5424 pattern (simplified)
    RFC5424_PATTERN = re.compile(
        r"^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured_data>\[.*?\]|\-)\s*(?P<message>.*)$"
    )

    def __init__(self, version: str = "auto"):
        """Initialize Syslog parser.

        Args:
            version: Syslog version (rfc3164, rfc5424, auto).
        """
        self.version = version.lower()

    def parse(self, raw_data: str) -> Dict[str, Any]:
        """Parse Syslog message.

        Args:
            raw_data: Raw syslog message string.

        Returns:
            Parsed syslog dictionary.

        Raises:
            IngestionError: If parsing fails.
        """
        try:
            if isinstance(raw_data, dict):
                raw_data = raw_data.get("message", str(raw_data))

            if self.version == "rfc5424":
                return self._parse_rfc5424(raw_data)
            elif self.version == "rfc3164":
                return self._parse_rfc3164(raw_data)
            else:  # auto-detect
                return self._parse_auto(raw_data)

        except Exception as e:
            logger.error(f"Failed to parse Syslog data: {e}")
            raise IngestionError(
                f"Syslog parsing error: {e}",
                source="syslog",
                raw_data=raw_data,
            )

    def _parse_auto(self, data: str) -> Dict[str, Any]:
        """Auto-detect syslog format and parse.

        Args:
            data: Raw syslog string.

        Returns:
            Parsed dictionary.
        """
        # Try RFC 5424 first (more specific)
        if data.startswith("<") and len(data) > 3 and data[1:].split(">")[0].isdigit():
            pri_end = data.find(">")
            rest = data[pri_end + 1:]
            if rest.startswith("1 "):  # Version 1 indicates RFC 5424
                return self._parse_rfc5424(data)

        # Default to RFC 3164
        return self._parse_rfc3164(data)

    def _parse_rfc3164(self, data: str) -> Dict[str, Any]:
        """Parse RFC 3164 (BSD) syslog format.

        Args:
            data: Raw syslog string.

        Returns:
            Parsed dictionary.
        """
        match = self.RFC3164_PATTERN.match(data)
        if not match:
            # Fallback: try to extract what we can
            return self._parse_fallback(data)

        groups = match.groupdict()
        pri = int(groups["pri"])
        severity = pri % 8
        facility = pri // 8

        return {
            "timestamp": groups["timestamp"],
            "hostname": groups["hostname"],
            "severity": self.SEVERITY_MAP.get(severity, "INFO"),
            "severity_code": severity,
            "facility": self.FACILITY_MAP.get(facility, "UNKNOWN"),
            "facility_code": facility,
            "tag": groups["tag"],
            "pid": groups.get("pid"),
            "message": groups["message"],
            "format": "rfc3164",
            "raw": data,
        }

    def _parse_rfc5424(self, data: str) -> Dict[str, Any]:
        """Parse RFC 5424 syslog format.

        Args:
            data: Raw syslog string.

        Returns:
            Parsed dictionary.
        """
        match = self.RFC5424_PATTERN.match(data)
        if not match:
            return self._parse_fallback(data)

        groups = match.groupdict()
        pri = int(groups["pri"])
        severity = pri % 8
        facility = pri // 8

        return {
            "version": groups["version"],
            "timestamp": groups["timestamp"],
            "hostname": groups["hostname"],
            "app_name": groups["app_name"],
            "procid": groups["procid"],
            "msgid": groups["msgid"],
            "structured_data": groups["structured_data"],
            "severity": self.SEVERITY_MAP.get(severity, "INFO"),
            "severity_code": severity,
            "facility": self.FACILITY_MAP.get(facility, "UNKNOWN"),
            "facility_code": facility,
            "message": groups["message"],
            "format": "rfc5424",
            "raw": data,
        }

    def _parse_fallback(self, data: str) -> Dict[str, Any]:
        """Fallback parser for non-standard syslog formats.

        Args:
            data: Raw syslog string.

        Returns:
            Best-effort parsed dictionary.
        """
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": "unknown",
            "severity": "INFO",
            "message": data,
            "format": "unknown",
            "raw": data,
        }
