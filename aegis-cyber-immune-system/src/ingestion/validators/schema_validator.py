"""Schema validators for AEGIS data ingestion."""

import logging
from typing import Dict, Any, List, Optional

from src.core.exceptions import IngestionError

logger = logging.getLogger(__name__)


class SchemaValidator:
    """JSON Schema validator for ingested data.

    Validates incoming data against predefined schemas to ensure
    data quality and consistency before processing.
    """

    # Telemetry schema definition
    TELEMETRY_SCHEMA = {
        "required": ["source_ip", "destination_ip", "protocol"],
        "optional": [
            "source_port",
            "destination_port",
            "bytes_sent",
            "bytes_received",
            "packets",
            "timestamp",
        ],
        "types": {
            "source_ip": str,
            "destination_ip": str,
            "source_port": int,
            "destination_port": int,
            "bytes_sent": int,
            "bytes_received": int,
            "packets": int,
            "protocol": str,
            "timestamp": (str, type(None)),
        },
    }

    # Security log schema definition
    SECURITY_LOG_SCHEMA = {
        "required": ["level", "source", "message"],
        "optional": ["timestamp", "event_id", "user", "hostname", "severity"],
        "types": {
            "level": str,
            "source": str,
            "message": str,
            "timestamp": (str, type(None)),
            "event_id": (str, type(None)),
            "user": (str, type(None)),
            "hostname": (str, type(None)),
            "severity": (int, type(None)),
        },
    }

    # IOC schema definition
    IOC_SCHEMA = {
        "required": ["type", "value"],
        "optional": ["severity", "confidence", "tags", "description"],
        "types": {
            "type": str,
            "value": str,
            "severity": str,
            "confidence": (float, int),
            "tags": list,
            "description": str,
        },
    }

    def __init__(self, strict_mode: bool = False):
        """Initialize schema validator.

        Args:
            strict_mode: If True, reject records with unknown fields.
        """
        self.strict_mode = strict_mode
        self.schemas = {
            "telemetry": self.TELEMETRY_SCHEMA,
            "security_log": self.SECURITY_LOG_SCHEMA,
            "ioc": self.IOC_SCHEMA,
        }

    def validate(self, data: Dict[str, Any], schema_name: str = "telemetry") -> bool:
        """Validate data against a schema.

        Args:
            data: Data dictionary to validate.
            schema_name: Name of the schema to use.

        Returns:
            True if valid, False otherwise.
        """
        try:
            schema = self.schemas.get(schema_name)
            if not schema:
                logger.warning(f"Unknown schema: {schema_name}")
                return False

            # Check required fields
            for field in schema["required"]:
                if field not in data:
                    logger.warning(f"Missing required field: {field}")
                    return False

            # Check types
            for field, expected_type in schema.get("types", {}).items():
                if field in data:
                    value = data[field]
                    if isinstance(expected_type, tuple):
                        if not isinstance(value, expected_type):
                            logger.warning(
                                f"Invalid type for {field}: expected {expected_type}, got {type(value)}"
                            )
                            return False
                    else:
                        if not isinstance(value, expected_type):
                            logger.warning(
                                f"Invalid type for {field}: expected {expected_type}, got {type(value)}"
                            )
                            return False

            # Strict mode: check for unknown fields
            if self.strict_mode:
                allowed_fields = set(schema["required"] + schema.get("optional", []))
                for field in data.keys():
                    if field not in allowed_fields:
                        logger.warning(f"Unknown field in strict mode: {field}")
                        return False

            return True

        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False

    def validate_and_raise(
        self, data: Dict[str, Any], schema_name: str = "telemetry"
    ) -> None:
        """Validate data and raise exception if invalid.

        Args:
            data: Data dictionary to validate.
            schema_name: Name of the schema to use.

        Raises:
            IngestionError: If validation fails.
        """
        if not self.validate(data, schema_name):
            raise IngestionError(
                f"Data validation failed for schema: {schema_name}",
                source="validator",
                raw_data=data,
            )

    def add_schema(self, name: str, schema: Dict[str, Any]) -> None:
        """Add a custom schema.

        Args:
            name: Schema name.
            schema: Schema definition with 'required', 'optional', and 'types' keys.
        """
        self.schemas[name] = schema
        logger.info(f"Added custom schema: {name}")

    def get_schema(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a schema by name.

        Args:
            name: Schema name.

        Returns:
            Schema dictionary or None if not found.
        """
        return self.schemas.get(name)
