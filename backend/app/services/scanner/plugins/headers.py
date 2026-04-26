from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import logging

logger = logging.getLogger(__name__)

# Essential security headers that should be present
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
        "expected": None,  # Just needs to be present
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
        "severity": 3.0,
        "level": SeverityLevel.LOW,
        "icon": "🔵",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block (legacy browsers)",
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
    """Check for missing or misconfigured security headers"""
    
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SECURITY_HEADERS

    def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []
        
        try:
            resp = self.session.get(url, timeout=5)
            headers = resp.headers
            
            for header_name, config in REQUIRED_HEADERS.items():
                header_value = headers.get(header_name)
                
                if not header_value:
                    vuln = self._create_vuln(
                        url=url,
                        description=f"Missing security header: {header_name}",
                        evidence=f"Response does not include '{header_name}' header",
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
