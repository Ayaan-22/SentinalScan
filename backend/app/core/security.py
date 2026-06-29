import secrets

from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from app.core.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

KNOWN_DEFAULT_KEYS = {
    "changeme",
    "changeme_in_production",
    "changeme_in_production_secret",
    "dev_api_key_12345",
    "your_api_key_here",
    "generate_a_64_character_hex_key_here",
}


def validate_configured_api_key(api_key: str | None = None) -> None:
    configured_key = api_key if api_key is not None else settings.API_KEY
    if (
        not configured_key
        or len(configured_key) < 32
        or configured_key.lower() in KNOWN_DEFAULT_KEYS
    ):
        raise RuntimeError(
            "API_KEY must be at least 32 characters and must not be a known "
            "default. Set SENTINAL_API_KEY to a strong random value."
        )


def is_valid_api_key(candidate: str | None) -> bool:
    try:
        validate_configured_api_key()
    except RuntimeError:
        return False

    if not candidate:
        return False
    return secrets.compare_digest(candidate, settings.API_KEY)


async def get_api_key(api_key_header: str = Security(api_key_header)):
    try:
        validate_configured_api_key()
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key is not configured securely. Set SENTINAL_API_KEY."
        )
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header."
        )
    if not is_valid_api_key(api_key_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return api_key_header
