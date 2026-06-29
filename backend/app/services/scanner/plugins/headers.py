from typing import List, Set
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import logging
import httpx

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = {
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": 4.0,
        "level": SeverityLevel.MEDIUM,
        "icon": "🟡",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "expected": ["DENY", "SAMEORIGIN"],
        "severity": 5.0,
        "level": SeverityLevel.MEDIUM,
        "icon": "🟡",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Strict-Transport-Security": {
        "expected": None,
        "severity": 6.0,
        "level": SeverityLevel.MEDIUM,
        "icon": "🟡",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "expected": None,
        "severity": 5.5,
        "level": SeverityLevel.MEDIUM,
        "icon": "🟡",
        "remediation": "Implement a Content-Security-Policy header to prevent XSS and data injection attacks",
    },
    "X-XSS-Protection": {
        "expected": None,
        "severity": 1.0,
        "level": SeverityLevel.LOW,
        "icon": "🔵",
        "remediation": "X-XSS-Protection is deprecated; rely on a strong Content-Security-Policy instead.",
    },
    "Referrer-Policy": {
        "expected": None,
        "severity": 3.0,
        "level": SeverityLevel.LOW,
        "icon": "🔵",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "expected": None,
        "severity": 3.0,
        "level": SeverityLevel.LOW,
        "icon": "🔵",
        "remediation": "Add Permissions-Policy header to restrict browser feature access",
    },
}


class SecurityHeaders(BaseCheck):
    """Check for missing or misconfigured security headers (Async).
    
    Deduplication: reports each missing header once per scan.
    """

    def __init__(self, client: httpx.AsyncClient):
        super().__init__(client)
        # Scan-level dedup: track which header names have already been reported
        self._reported_headers: Set[str] = set()

    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SECURITY_HEADERS

    async def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []

        try:
            resp = await self.client.get(url, timeout=5)
            headers = resp.headers

            for header_name, config in REQUIRED_HEADERS.items():
                # Skip if we already reported this missing header for this scan
                if header_name in self._reported_headers:
                    continue

                header_value = headers.get(header_name)
                issue = self._header_issue(url, header_name, header_value, config)

                if issue:
                    # Mark as reported at the scan level
                    self._reported_headers.add(header_name)

                    vuln = self._create_vuln(
                        url=url,
                        description=issue["description"],
                        evidence=issue["evidence"],
                        severity_score=config["severity"],
                        severity_level=config["level"],  # type: ignore
                        severity_icon=config["icon"],
                        remediation=config["remediation"],
                        confidence="High"
                    )
                    vulns.append(vuln)

        except Exception as e:
            logger.debug(f"Security headers check failed for {url}: {e}")

        return vulns

    def _header_issue(self, url: str, header_name: str, value: str | None, config: dict) -> dict | None:
        if header_name == "Strict-Transport-Security" and not url.lower().startswith("https://"):
            return None

        if not value:
            return {
                "description": f"Missing security header: {header_name}",
                "evidence": (
                    f"Response at {url} does not include the '{header_name}' header. "
                    "This misconfiguration likely affects the entire site."
                ),
            }

        normalized = value.strip().lower()

        if header_name == "X-Content-Type-Options" and normalized != "nosniff":
            return {
                "description": "Misconfigured security header: X-Content-Type-Options",
                "evidence": f"Expected 'nosniff', observed '{value}'.",
            }

        if header_name == "X-Frame-Options" and normalized not in {"deny", "sameorigin"}:
            return {
                "description": "Misconfigured security header: X-Frame-Options",
                "evidence": f"Expected DENY or SAMEORIGIN, observed '{value}'.",
            }

        if header_name == "Strict-Transport-Security" and "max-age=" not in normalized:
            return {
                "description": "Weak Strict-Transport-Security header",
                "evidence": f"HSTS header must include max-age, observed '{value}'.",
            }

        if header_name == "Content-Security-Policy":
            weak_tokens = ["default-src *", "script-src *", "unsafe-inline", "unsafe-eval"]
            if any(token in normalized for token in weak_tokens):
                return {
                    "description": "Weak Content-Security-Policy header",
                    "evidence": f"CSP contains unsafe broad source or script policy: '{value}'.",
                }

        if header_name == "Referrer-Policy":
            acceptable = {
                "no-referrer",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            }
            if normalized not in acceptable:
                return {
                    "description": "Weak Referrer-Policy header",
                    "evidence": f"Observed '{value}', expected one of {sorted(acceptable)}.",
                }

        return None
