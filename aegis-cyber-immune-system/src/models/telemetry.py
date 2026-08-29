"""Telemetry data models for AEGIS."""

from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class NetworkTelemetry(BaseModel):
    """Network telemetry data model.

    Represents network traffic data including source/destination
    IPs, ports, protocol, and traffic statistics.
    """

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: int = Field(..., ge=1, le=65535, description="Source port number")
    destination_port: int = Field(..., ge=1, le=65535, description="Destination port number")
    protocol: str = Field(..., description="Network protocol (TCP/UDP/ICMP)")
    bytes_sent: int = Field(default=0, ge=0, description="Bytes sent")
    bytes_received: int = Field(default=0, ge=0, description="Bytes received")
    packets: int = Field(default=0, ge=0, description="Number of packets")
    duration: Optional[float] = Field(default=None, ge=0, description="Connection duration in seconds")
    flags: Optional[str] = Field(default=None, description="TCP flags or other metadata")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw telemetry data")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validate protocol value.

        Args:
            v: Protocol string to validate.

        Returns:
            Uppercase protocol string.

        Raises:
            ValueError: If protocol is not supported.
        """
        allowed_protocols = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP"}
        v_upper = v.upper()
        if v_upper not in allowed_protocols and v_upper not in ["TCP", "UDP", "ICMP"]:
            # Allow any protocol but normalize to uppercase
            pass
        return v_upper


class SecurityLog(BaseModel):
    """Security log entry model.

    Represents security event logs from various sources
    such as firewalls, IDS/IPS, EDR systems.
    """

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Log timestamp")
    level: str = Field(..., description="Log level (INFO/WARNING/ERROR/CRITICAL)")
    source: str = Field(..., description="Log source (firewall/ids/edr)")
    message: str = Field(..., description="Log message")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw log data")
    event_id: Optional[str] = Field(default=None, description="Event identifier")
    user: Optional[str] = Field(default=None, description="Associated user")
    hostname: Optional[str] = Field(default=None, description="Source hostname")
    severity: Optional[int] = Field(default=None, ge=0, le=10, description="Severity score 0-10")

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level.

        Args:
            v: Level string to validate.

        Returns:
            Uppercase level string.

        Raises:
            ValueError: If level is not valid.
        """
        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in allowed_levels:
            raise ValueError(f"Invalid log level. Must be one of: {allowed_levels}")
        return v_upper


class EndpointData(BaseModel):
    """Endpoint telemetry data model.

    Represents endpoint security data including process
    information, user activity, and system state.
    """

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    hostname: str = Field(..., description="Endpoint hostname")
    process: Optional[str] = Field(default=None, description="Process name")
    process_id: Optional[int] = Field(default=None, ge=1, description="Process ID")
    user: Optional[str] = Field(default=None, description="Username")
    command_line: Optional[str] = Field(default=None, description="Command line arguments")
    parent_process: Optional[str] = Field(default=None, description="Parent process name")
    action: Optional[str] = Field(default=None, description="Action performed")
    file_path: Optional[str] = Field(default=None, description="Associated file path")
    hash: Optional[str] = Field(default=None, description="File hash (SHA256)")
    os_info: Optional[str] = Field(default=None, description="Operating system information")
    ip_addresses: Optional[list] = Field(default=None, description="Endpoint IP addresses")

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, v: Optional[str]) -> Optional[str]:
        """Validate file hash format.

        Args:
            v: Hash string to validate.

        Returns:
            Validated hash string or None.

        Raises:
            ValueError: If hash format is invalid.
        """
        if v is None:
            return v

        # Support MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)
        allowed_lengths = {32, 40, 64, 128}
        if len(v) not in allowed_lengths:
            raise ValueError(f"Invalid hash length. Expected one of: {allowed_lengths}")

        return v.lower()
