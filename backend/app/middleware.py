"""
Security middleware stack for SentinalScan API.

SecurityHeadersMiddleware  — adds defensive response headers, strips server fingerprints.
SensitiveDataSanitizer     — masks secrets in log output.
sanitize_log_message()     — escapes HTML-special chars from scan payloads before
                             WebSocket streaming (prevents XSS in devtools / extensions).
"""

import html
import re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add defensive headers and strip stack fingerprints from every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["X-XSS-Protection"] = "0"  # disable broken legacy auditor
        # Remove server fingerprints safely
        if "server" in h:
            del h["server"]
        if "x-powered-by" in h:
            del h["x-powered-by"]
        return response


class SensitiveDataSanitizer(BaseHTTPMiddleware):
    """Mask secrets that might leak into log output or error responses."""

    _MASK = re.compile(
        r'("(?:auth_token|password|cookie|secret|api_key|authorization)[^"]*":\s*")([^"]+)(")',
        re.IGNORECASE,
    )

    @classmethod
    def sanitize(cls, text: str) -> str:
        return cls._MASK.sub(r"\1[REDACTED]\3", text)

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Only sanitize if it's a JSON response where secrets might leak
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            # We need to read the body to sanitize it
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            try:
                text = body.decode("utf-8")
                sanitized_text = self.sanitize(text)
                sanitized_body = sanitized_text.encode("utf-8")
                
                from starlette.responses import Response
                return Response(
                    content=sanitized_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
            except Exception:
                # If decoding fails, return original response
                from starlette.responses import Response
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
                
        return response


# ── Payload sanitizer for WebSocket log stream ────────────────────────────────
_UNSAFE_CHARS = re.compile(r'[<>"\'`&]')


def sanitize_log_message(msg: str) -> str:
    """Escape HTML-special chars from scan payloads before WebSocket streaming.

    React JSX escapes by default, but the raw WebSocket JSON is accessible to
    browser extensions and developer tools. This prevents XSS in those contexts.
    """
    return _UNSAFE_CHARS.sub(
        lambda m: html.escape(m.group(), quote=True), msg
    )
