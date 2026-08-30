"""Indicator of Compromise (IOC) model for AEGIS."""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator


class IOC(BaseModel):
    """Indicator of Compromise model.

    Represents a security indicator that may suggest a system
    has been compromised or attacked.
    """

    type: str = Field(..., description="IOC type (ip/domain/hash/url/email/file_path)")
    value: str = Field(..., description="IOC value")
    severity: str = Field(default="medium", description="Severity level (low/medium/high/critical)")
    confidence: float = Field(default=0.5, ge=0, le=1, description="Confidence score 0-1")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="First observation time")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Last observation time")
    tags: Optional[List[str]] = Field(default=None, description="Classification tags")
    source: Optional[str] = Field(default=None, description="IOC source")
    description: Optional[str] = Field(default=None, description="IOC description")
    active: bool = Field(default=True, description="Whether IOC is still active")

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate IOC type.

        Args:
            v: Type string to validate.

        Returns:
            Lowercase type string.

        Raises:
            ValueError: If type is not valid.
        """
        allowed_types = {"ip", "domain", "hash", "url", "email", "file_path", "registry_key", "mutex"}
        v_lower = v.lower()
        if v_lower not in allowed_types:
            raise ValueError(f"Invalid IOC type. Must be one of: {allowed_types}")
        return v_lower

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity level."""
        allowed_severities = {"low", "medium", "high", "critical"}
        v_lower = v.lower()
        if v_lower not in allowed_severities:
            raise ValueError(f"Invalid severity. Must be one of: {allowed_severities}")
        return v_lower

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Validate IOC value based on type.

        Args:
            v: IOC value to validate.

        Returns:
            Validated IOC value.

        Raises:
            ValueError: If value format is invalid for its type.
        """
        if not v or len(v.strip()) == 0:
            raise ValueError("IOC value cannot be empty")
        return v.strip()
