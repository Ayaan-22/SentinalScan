"""Versioned authorization contracts. Endpoint permissions are exact paths, never globs."""

import re
from datetime import UTC, datetime
from enum import Enum
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ScanMode(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe-active"
    CUSTOM_ACTIVE = "custom-active"


SENSITIVE_WORKFLOWS = (
    "logout", "signout", "checkout", "purchase", "payment", "pay", "billing",
    "delete", "remove", "destroy", "reset", "recover", "recovery", "password",
    "account", "register", "signup", "user", "settings", "email", "send", "transfer",
)


def canonical_url(value: str) -> str:
    """Keep path, duplicate query keys, ordering and values intact."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Expected an HTTP(S) URL with a hostname")
    if parsed.username or parsed.password or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("Credentials, backslashes and control characters are forbidden in URLs")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    authority = host if port == (443 if parsed.scheme == "https" else 80) else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}{parsed.path or '/'}" + (f"?{parsed.query}" if parsed.query else "")


def origin(url: str) -> str:
    parsed = urlsplit(canonical_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def exact_path(value: str) -> str:
    if (
        not value.startswith("/") or value.startswith("//")
        or any(c in value for c in "%\\;?#*")
        or any(c.isspace() or ord(c) < 32 for c in value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("Use a literal absolute path without encoding, query, wildcard or dot segments")
    return value


def sensitive_url(url: str) -> bool:
    parsed = urlsplit(url)
    decoded = parsed.path + "?" + parsed.query
    for _ in range(4):
        decoded = unquote(decoded)
    # Check query operations too: /api?action=delete is a sensitive workflow.
    decoded = re.sub(r"([a-z])([A-Z])", r"\1 \2", decoded)
    words = re.split(r"[^a-z]+", decoded.lower())
    return any(word in SENSITIVE_WORKFLOWS or word.rstrip("s") in SENSITIVE_WORKFLOWS for word in words) or bool(
        re.search(r"sign[\W_]*out", decoded, re.IGNORECASE)
    )


class EndpointPermission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    methods: tuple[str, ...] = Field(min_length=1, max_length=7)

    _path = field_validator("path")(exact_path)

    @field_validator("methods")
    @classmethod
    def methods_allowed(cls, methods):
        if not set(methods) <= {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Unsupported HTTP method")
        return methods


class PolicyAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: ScanMode
    scope_origin: str
    allowed_endpoints: tuple[EndpointPermission, ...] = Field(min_length=1, max_length=100)
    excluded_paths: tuple[str, ...] = Field(default=(), max_length=100)
    expires_at: datetime
    authorization_confirmed: bool = Field(strict=True)

    @field_validator("scope_origin")
    @classmethod
    def validate_origin(cls, value):
        normalized = canonical_url(value)
        if urlsplit(normalized).path != "/" or urlsplit(normalized).query:
            raise ValueError("Scope must be an origin without a path or query")
        return origin(normalized)

    @field_validator("excluded_paths")
    @classmethod
    def validate_exclusions(cls, paths):
        return tuple(exact_path(path) for path in paths)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value):
        if value.tzinfo is None:
            raise ValueError("Expiry must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_authorization(self):
        if self.mode == ScanMode.PASSIVE or not self.authorization_confirmed:
            raise ValueError("Active policies require explicit authorization confirmation")
        if self.mode == ScanMode.SAFE_ACTIVE and any(
            not set(endpoint.methods) <= {"GET", "HEAD"} for endpoint in self.allowed_endpoints
        ):
            raise ValueError("safe-active permits only GET and HEAD; these can still change application state")
        if any(sensitive_url(endpoint.path) for endpoint in self.allowed_endpoints):
            raise ValueError("Sensitive workflows cannot be authorized")
        return self


class StoredPolicy(PolicyAuthorization):
    policy_id: str
    version: int = 1
    authorized_by: str
    authorized_at: datetime
    sensitive_workflow_exclusions: tuple[str, ...] = SENSITIVE_WORKFLOWS

    def require_request(self, mode: ScanMode, method: str, url: str, now: datetime | None = None):
        if mode != self.mode or self.version != 1:
            raise PermissionError("Authorization mode or version mismatch")
        if self.expires_at <= (now or datetime.now(UTC)):
            raise PermissionError("Authorization has expired")
        normalized = canonical_url(url)
        path = urlsplit(normalized).path
        if origin(normalized) != self.scope_origin:
            raise PermissionError("Request outside authorized origin")
        try:
            exact_path(path)
        except ValueError as exc:
            raise PermissionError("Ambiguous request path") from exc
        if sensitive_url(normalized) or any(path.startswith(p) for p in self.excluded_paths):
            raise PermissionError("Sensitive or excluded workflow")
        if not any(path == endpoint.path and method in endpoint.methods for endpoint in self.allowed_endpoints):
            raise PermissionError("Endpoint/method is not authorized")
