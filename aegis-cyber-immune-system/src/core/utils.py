"""Utility functions for AEGIS."""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def generate_uuid() -> str:
    """Generate a unique UUID string.

    Returns:
        String representation of a UUID version 4.
    """
    return str(uuid.uuid4())


def format_timestamp(dt: Optional[datetime] = None, format_string: str = "%Y-%m-%dT%H:%M:%S.%fZ") -> str:
    """Format a datetime object as ISO 8601 string.

    Args:
        dt: Datetime object to format. If None, uses current UTC time.
        format_string: Format string (default: ISO 8601).

    Returns:
        Formatted timestamp string.
    """
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime(format_string)


def parse_timestamp(timestamp_str: str, format_string: str = "%Y-%m-%dT%H:%M:%S.%fZ") -> Optional[datetime]:
    """Parse a timestamp string into a datetime object.

    Args:
        timestamp_str: Timestamp string to parse.
        format_string: Expected format of the timestamp.

    Returns:
        Datetime object or None if parsing fails.
    """
    try:
        return datetime.strptime(timestamp_str, format_string)
    except ValueError as e:
        logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return None


def deep_merge(base_dict: Dict[str, Any], override_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries.

    Args:
        base_dict: Base dictionary.
        override_dict: Dictionary with values to override.

    Returns:
        Merged dictionary.
    """
    result = base_dict.copy()

    for key, value in override_dict.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value

    return result


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Flatten a nested dictionary.

    Args:
        d: Dictionary to flatten.
        parent_key: Parent key prefix.
        sep: Separator between nested keys.

    Returns:
        Flattened dictionary with dot-notation keys.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        s: String to truncate.
        max_length: Maximum length of the string.
        suffix: Suffix to add if truncation occurs.

    Returns:
        Truncated string.
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def calculate_hash(data: Any, algorithm: str = "sha256") -> str:
    """Calculate hash of data.

    Args:
        data: Data to hash (will be converted to string).
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512).

    Returns:
        Hexadecimal hash string.
    """
    import hashlib

    data_str = str(data).encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(data_str).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data_str).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data_str).hexdigest()
    else:  # default to sha256
        return hashlib.sha256(data_str).hexdigest()


def retry_async(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator for async function retry logic.

    Args:
        max_retries: Maximum number of retry attempts.
        delay: Initial delay between retries in seconds.
        backoff: Multiplier for delay after each retry.

    Returns:
        Decorated async function with retry logic.
    """
    import asyncio
    from functools import wraps

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None

            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger.warning(
                            f"Attempt {attempt + 1} failed: {e}. Retrying in {current_delay}s..."
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(f"All {max_retries} attempts failed")

            raise last_exception

        return wrapper

    return decorator
