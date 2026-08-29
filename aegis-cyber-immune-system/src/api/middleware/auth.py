"""Authentication middleware for AEGIS API."""

import logging
from typing import Optional, Callable

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """JWT Authentication middleware for protecting API endpoints.

    This middleware validates JWT tokens in the Authorization header
    and attaches user information to the request state.
    """

    def __init__(
        self,
        app,
        secret_key: str = "your-secret-key-here",
        algorithm: str = "HS256",
        exclude_paths: Optional[list] = None,
    ):
        """Initialize auth middleware.

        Args:
            app: FastAPI application instance.
            secret_key: JWT secret key for token verification.
            algorithm: JWT algorithm (default: HS256).
            exclude_paths: List of paths to exclude from authentication.
        """
        super().__init__(app)
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.exclude_paths = exclude_paths or [
            "/health",
            "/api/v1/health",
            "/api/v1/info",
            "/docs",
            "/openapi.json",
        ]
        self.security = HTTPBearer(auto_error=False)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process incoming requests and validate JWT tokens.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware/handler in the chain.

        Returns:
            HTTP response.

        Raises:
            HTTPException: If authentication fails.
        """
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Get authorization header
        credentials: Optional[HTTPAuthorizationCredentials] = await self.security(request)

        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            # Validate JWT token (simplified for demo - will use python-jose in production)
            token = credentials.credentials

            # In production, decode and validate the JWT token here
            # from jose import jwt
            # payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            # request.state.user = payload

            # For demo purposes, accept any non-empty token
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.debug(f"Authenticated request to {request.url.path}")

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)
