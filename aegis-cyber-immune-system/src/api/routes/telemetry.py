"""Telemetry data endpoints for AEGIS."""

from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


# In-memory storage for demo purposes (will be replaced with database)
telemetry_store: Dict[str, Dict[str, Any]] = {}


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_telemetry(telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest telemetry data into the system.

    Args:
        telemetry_data: Network telemetry data including source/destination IPs,
                       ports, protocol, bytes, and packets.

    Returns:
        Dict containing ingestion status and telemetry ID.

    Raises:
        HTTPException: If required fields are missing.
    """
    required_fields = ["source_ip", "destination_ip", "protocol"]

    for field in required_fields:
        if field not in telemetry_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required field: {field}",
            )

    # Generate unique ID and timestamp
    telemetry_id = str(uuid4())
    telemetry_data["id"] = telemetry_id
    telemetry_data["timestamp"] = datetime.utcnow().isoformat()

    # Store telemetry (in production, this would go to database)
    telemetry_store[telemetry_id] = telemetry_data

    return {
        "status": "success",
        "message": "Telemetry data ingested successfully",
        "telemetry_id": telemetry_id,
    }


@router.get("", response_model=List[Dict[str, Any]])
async def get_telemetry(
    limit: int = 100,
    offset: int = 0,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve telemetry data from the system.

    Args:
        limit: Maximum number of records to return.
        offset: Number of records to skip.
        source_ip: Filter by source IP address.
        destination_ip: Filter by destination IP address.

    Returns:
        List of telemetry records matching the filters.
    """
    results = list(telemetry_store.values())

    # Apply filters
    if source_ip:
        results = [t for t in results if t.get("source_ip") == source_ip]
    if destination_ip:
        results = [t for t in results if t.get("destination_ip") == destination_ip]

    # Apply pagination
    return results[offset : offset + limit]


@router.get("/{telemetry_id}")
async def get_telemetry_by_id(telemetry_id: str) -> Dict[str, Any]:
    """Retrieve detailed telemetry information by ID.

    Args:
        telemetry_id: Unique identifier of the telemetry record.

    Returns:
        Telemetry record details.

    Raises:
        HTTPException: If telemetry record is not found.
    """
    if telemetry_id not in telemetry_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry record {telemetry_id} not found",
        )

    return telemetry_store[telemetry_id]
