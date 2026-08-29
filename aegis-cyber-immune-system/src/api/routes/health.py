"""Health check endpoints for AEGIS."""

from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, status

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """Basic health check endpoint.

    Returns:
        Dict containing health status and timestamp.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/api/v1/health", status_code=status.HTTP_200_OK)
async def api_health_check() -> Dict[str, Any]:
    """API version health check endpoint.

    Returns:
        Dict containing API health status, version, and timestamp.
    """
    return {
        "status": "healthy",
        "api_version": "v1",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/api/v1/info", status_code=status.HTTP_200_OK)
async def system_info() -> Dict[str, Any]:
    """System information endpoint.

    Returns:
        Dict containing system information including name, version,
        environment, and available components.
    """
    from config.settings import settings

    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "debug": settings.debug,
        "components": {
            "neo4j": "connected" if settings.neo4j_uri else "not configured",
            "elasticsearch": "connected" if settings.elasticsearch_url else "not configured",
            "redis": "connected" if settings.redis_url else "not configured",
            "kafka": "connected" if settings.kafka_bootstrap_servers else "not configured",
        },
        "timestamp": datetime.utcnow().isoformat(),
    }
