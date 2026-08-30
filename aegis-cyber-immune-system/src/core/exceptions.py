"""Custom exceptions for AEGIS."""

from typing import Any, Optional


class AEGISException(Exception):
    """Base exception class for AEGIS.

    All custom exceptions in AEGIS should inherit from this class.
    """

    def __init__(
        self,
        message: str = "An error occurred in AEGIS",
        details: Optional[dict] = None,
    ):
        """Initialize AEGIS exception.

        Args:
            message: Human-readable error message.
            details: Optional dictionary with additional error details.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(AEGISException):
    """Exception raised for configuration errors.

    This exception is raised when there are issues with application
    configuration, such as missing environment variables or invalid settings.
    """

    def __init__(self, message: str, setting_name: Optional[str] = None):
        """Initialize configuration error.

        Args:
            message: Error message describing the configuration issue.
            setting_name: Name of the problematic setting (optional).
        """
        details = {"setting_name": setting_name} if setting_name else {}
        super().__init__(message=message, details=details)


class IngestionError(AEGISException):
    """Exception raised during data ingestion.

    This exception is raised when there are issues parsing or validating
    incoming data from various sources.
    """

    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        raw_data: Optional[Any] = None,
    ):
        """Initialize ingestion error.

        Args:
            message: Error message describing the ingestion issue.
            source: Data source that caused the error (optional).
            raw_data: Raw data that caused the error (optional).
        """
        details = {
            "source": source,
            "has_raw_data": raw_data is not None,
        }
        super().__init__(message=message, details=details)


class DetectionError(AEGISException):
    """Exception raised during threat detection.

    This exception is raised when there are issues in the detection engine,
    such as model loading failures or prediction errors.
    """

    def __init__(self, message: str, model_name: Optional[str] = None):
        """Initialize detection error.

        Args:
            message: Error message describing the detection issue.
            model_name: Name of the model that caused the error (optional).
        """
        details = {"model_name": model_name} if model_name else {}
        super().__init__(message=message, details=details)


class GraphDatabaseError(AEGISException):
    """Exception raised for graph database operations.

    This exception is raised when there are issues with Neo4j operations,
    such as connection failures or query errors.
    """

    def __init__(self, message: str, query: Optional[str] = None):
        """Initialize graph database error.

        Args:
            message: Error message describing the database issue.
            query: Cypher query that caused the error (optional).
        """
        details = {"query": query} if query else {}
        super().__init__(message=message, details=details)


class ResponseError(AEGISException):
    """Exception raised during automated response.

    This exception is raised when there are issues executing response
    playbooks or remediation actions.
    """

    def __init__(
        self,
        message: str,
        playbook_name: Optional[str] = None,
        action: Optional[str] = None,
    ):
        """Initialize response error.

        Args:
            message: Error message describing the response issue.
            playbook_name: Name of the playbook that failed (optional).
            action: Specific action that failed (optional).
        """
        details = {
            "playbook_name": playbook_name,
            "action": action,
        }
        super().__init__(message=message, details=details)
