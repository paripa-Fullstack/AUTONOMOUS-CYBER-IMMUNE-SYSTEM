"""CVE (Common Vulnerabilities and Exposures) model for AEGIS."""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator


class CVE(BaseModel):
    """CVE vulnerability model.

    Represents a Common Vulnerabilities and Exposures entry
    with severity, affected products, and references.
    """

    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    description: str = Field(..., description="Vulnerability description")
    severity: str = Field(default="medium", description="Severity level (low/medium/high/critical)")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS score 0-10")
    published_date: datetime = Field(default_factory=datetime.utcnow, description="Publication date")
    modified_date: Optional[datetime] = Field(default=None, description="Last modification date")
    affected_products: Optional[List[str]] = Field(default=None, description="Affected product names")
    references: Optional[List[str]] = Field(default=None, description="Reference URLs")
    cwe_ids: Optional[List[str]] = Field(default=None, description="Associated CWE IDs")
    has_exploit: bool = Field(default=False, description="Whether exploit is available")
    patch_available: bool = Field(default=False, description="Whether patch is available")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        """Validate CVE ID format.

        Args:
            v: CVE ID string to validate.

        Returns:
            Uppercase CVE ID.

        Raises:
            ValueError: If CVE ID format is invalid.
        """
        import re

        # CVE format: CVE-YYYY-NNNN (or more digits)
        pattern = r"^CVE-\d{4}-\d{4,}$"
        if not re.match(pattern, v.upper()):
            raise ValueError(
                f"Invalid CVE ID format: {v}. Expected format: CVE-YYYY-NNNN"
            )
        return v.upper()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity level based on CVSS score ranges.

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

    @field_validator("references")
    @classmethod
    def validate_references(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate reference URLs.

        Args:
            v: List of URL strings to validate.

        Returns:
            Validated list of URLs.

        Raises:
            ValueError: If any URL is invalid.
        """
        if v is None:
            return v

        from urllib.parse import urlparse

        validated_urls = []
        for url in v:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError(f"Invalid URL format: {url}")
            validated_urls.append(url)

        return validated_urls
