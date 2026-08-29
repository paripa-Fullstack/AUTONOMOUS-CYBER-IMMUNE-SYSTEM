"""CEF (Common Event Format) parser for AEGIS."""

import logging
from typing import Dict, Any

from src.core.exceptions import IngestionError

logger = logging.getLogger(__name__)


class CEFParser:
    """Parser for ArcSight Common Event Format (CEF) logs.

    CEF format: CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    def parse(self, raw_data: str) -> Dict[str, Any]:
        """Parse CEF message.

        Args:
            raw_data: Raw CEF string.

        Returns:
            Parsed CEF dictionary.

        Raises:
            IngestionError: If parsing fails.
        """
        try:
            if isinstance(raw_data, dict):
                raw_data = raw_data.get("message", str(raw_data))

            if not raw_data.startswith("CEF:"):
                raise ValueError("Invalid CEF format - missing CEF prefix")

            parts = raw_data.split("|", 7)
            if len(parts) < 8:
                raise ValueError(f"Invalid CEF format - expected 8 fields, got {len(parts)}")

            version = parts[0].replace("CEF:", "")
            device_vendor = parts[1]
            device_product = parts[2]
            device_version = parts[3]
            signature_id = parts[4]
            name = parts[5]
            severity = parts[6]
            extension_str = parts[7] if len(parts) > 7 else ""

            # Parse extension key-value pairs
            extension = self._parse_extension(extension_str)

            return {
                "version": version,
                "device_vendor": device_vendor,
                "device_product": device_product,
                "device_version": device_version,
                "signature_id": signature_id,
                "name": name,
                "severity": severity,
                "extension": extension,
                "source": extension.get("src", ""),
                "destination": extension.get("dst", ""),
                "source_port": extension.get("spt", ""),
                "destination_port": extension.get("dpt", ""),
                "protocol": extension.get("proto", ""),
                "raw": raw_data,
            }

        except Exception as e:
            logger.error(f"Failed to parse CEF data: {e}")
            raise IngestionError(
                f"CEF parsing error: {e}",
                source="cef",
                raw_data=raw_data,
            )

    def _parse_extension(self, extension_str: str) -> Dict[str, Any]:
        """Parse CEF extension key-value pairs.

        Args:
            extension_str: Extension string from CEF message.

        Returns:
            Dictionary of extension fields.
        """
        extension = {}
        if not extension_str:
            return extension

        # Split by spaces but handle quoted values
        import re
        pairs = re.findall(r'(\w+)=([^\s]+|"[^"]*")', extension_str)

        for key, value in pairs:
            # Remove quotes if present
            value = value.strip('"')
            extension[key] = value

        return extension
