"""Threat models for AEGIS."""

from datetime import datetime
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, field_validator


class Threat(BaseModel):
    """Threat detection model.

    Represents a detected security threat with associated metadata,
    severity, and status information.
    """

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    threat_type: str = Field(..., description="Type of threat (malware/intrusion/phishing/etc)")
    severity: str = Field(..., description="Severity level (low/medium/high/critical)")
    status: str = Field(default="active", description="Threat status (active/mitigated/false_positive)")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    description: Optional[str] = Field(default=None, description="Threat description")
    indicators: Optional[List[str]] = Field(default=None, description="Indicators of compromise")
    confidence: Optional[float] = Field(default=None, ge=0, le=1, description="Detection confidence 0-1")
    mitre_attack: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK technique IDs")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw threat data")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity level.

        Args:
            v: Severity string to validate.

        Returns:
            Lowercase severity string.

        Raises:
            ValueError: If severity is not valid.
        """
        allowed_severities = {"low", "medium", "high", "critical"}
        v_lower = v.lower()
        if v_lower not in allowed_severities:
            raise ValueError(f"Invalid severity. Must be one of: {allowed_severities}")
        return v_lower

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate threat status.

        Args:
            v: Status string to validate.

        Returns:
            Lowercase status string.

        Raises:
            ValueError: If status is not valid.
        """
        allowed_statuses = {"active", "mitigated", "false_positive", "investigating"}
        v_lower = v.lower()
        if v_lower not in allowed_statuses:
            raise ValueError(f"Invalid status. Must be one of: {allowed_statuses}")
        return v_lower


class Incident(BaseModel):
    """Security incident model.

    Represents a security incident that may involve multiple
    threats and requires coordinated response.
    """

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Incident start time")
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    severity: str = Field(..., description="Incident severity (low/medium/high/critical)")
    status: str = Field(default="open", description="Incident status (open/in_progress/resolved/closed)")
    priority: int = Field(default=3, ge=1, le=5, description="Priority level 1-5 (1=highest)")
    assigned_to: Optional[str] = Field(default=None, description="Assigned analyst")
    threat_ids: Optional[List[str]] = Field(default=None, description="Associated threat IDs")
    affected_systems: Optional[List[str]] = Field(default=None, description="Affected system hostnames")
    iocs: Optional[List[str]] = Field(default=None, description="Related indicators of compromise")
    timeline: Optional[List[Dict[str, Any]]] = Field(default=None, description="Incident timeline events")
    resolution: Optional[str] = Field(default=None, description="Resolution notes")
    closed_at: Optional[datetime] = Field(default=None, description="Incident closure timestamp")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity level."""
        allowed_severities = {"low", "medium", "high", "critical"}
        v_lower = v.lower()
        if v_lower not in allowed_severities:
            raise ValueError(f"Invalid severity. Must be one of: {allowed_severities}")
        return v_lower

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate incident status."""
        allowed_statuses = {"open", "in_progress", "resolved", "closed"}
        v_lower = v.lower()
        if v_lower not in allowed_statuses:
            raise ValueError(f"Invalid status. Must be one of: {allowed_statuses}")
        return v_lower
