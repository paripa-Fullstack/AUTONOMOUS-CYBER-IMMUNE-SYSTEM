"""Security utilities for AEGIS."""

import hashlib
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash a password using SHA-256 with optional salt.

    Note: In production, use bcrypt or argon2 via passlib.

    Args:
        password: Plain text password to hash.
        salt: Optional salt value. If not provided, generates a random one.

    Returns:
        Tuple of (hashed_password, salt).
    """
    import secrets

    if salt is None:
        salt = secrets.token_hex(16)

    # Combine password and salt
    salted_password = f"{password}{salt}"

    # Hash using SHA-256
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()

    return hashed, salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """Verify a password against its hash.

    Args:
        password: Plain text password to verify.
        hashed_password: Stored hash to compare against.
        salt: Salt used in hashing.

    Returns:
        True if password matches, False otherwise.
    """
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == hashed_password


def verify_token(token: str, secret_key: str, algorithm: str = "HS256") -> Optional[Dict[str, Any]]:
    """Verify a JWT token and return its payload.

    Args:
        token: JWT token string to verify.
        secret_key: Secret key for token verification.
        algorithm: JWT algorithm (default: HS256).

    Returns:
        Token payload if valid, None otherwise.
    """
    try:
        from jose import jwt

        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        logger.debug("Token verified successfully")
        return payload

    except Exception as e:
        logger.warning(f"Token verification failed: {str(e)}")
        return None


def create_token(data: Dict[str, Any], secret_key: str, algorithm: str = "HS256", expires_in_minutes: int = 30) -> str:
    """Create a JWT token with the given data.

    Args:
        data: Payload data to include in the token.
        secret_key: Secret key for token signing.
        algorithm: JWT algorithm (default: HS256).
        expires_in_minutes: Token expiration time in minutes.

    Returns:
        Encoded JWT token string.
    """
    from datetime import datetime, timedelta
    from jose import jwt

    expire = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    payload = data.copy()
    payload.update({"exp": expire})

    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    logger.debug("Token created successfully")
    return token


def sanitize_input(input_string: str) -> str:
    """Sanitize user input to prevent injection attacks.

    Args:
        input_string: Raw user input string.

    Returns:
        Sanitized string safe for processing.
    """
    if not isinstance(input_string, str):
        return str(input_string)

    # Remove potentially dangerous characters
    sanitized = input_string.strip()
    sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
    sanitized = sanitized.replace("'", "\\'").replace('"', '\\"')

    return sanitized


def validate_ip_address(ip: str) -> bool:
    """Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate.

    Returns:
        True if valid IP address, False otherwise.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate a port number.

    Args:
        port: Port number to validate.

    Returns:
        True if valid port (1-65535), False otherwise.
    """
    return isinstance(port, int) and 1 <= port <= 65535
