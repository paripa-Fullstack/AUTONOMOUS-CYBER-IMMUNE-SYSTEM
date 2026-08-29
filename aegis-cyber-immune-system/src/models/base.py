"""Base model for AEGIS data models."""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel as PydanticBaseModel, Field


class BaseModel(PydanticBaseModel):
    """Base model class for all AEGIS data models.

    Provides common fields and functionality for all models.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")

    class Config:
        """Pydantic model configuration."""

        from_attributes = True
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }

    def update(self, **kwargs) -> None:
        """Update model fields.

        Args:
            **kwargs: Fields to update with new values.
        """
        for field, value in kwargs.items():
            if hasattr(self, field):
                setattr(self, field, value)
        self.updated_at = datetime.utcnow()
