"""Middleware modules for AEGIS API."""

from src.api.middleware.auth import AuthMiddleware

__all__ = ["AuthMiddleware"]
