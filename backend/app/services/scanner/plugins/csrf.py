from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import logging

logger = logging.getLogger(__name__)


class CSRFCheck(BaseCheck):
    """Check for missing CSRF protection on forms"""
    
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.CSRF

    def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []
        
        for form in forms:
            method = form.get("method", "get").lower()
            
            # CSRF is primarily a concern for state-changing requests (POST)
            if method != "post":
                continue
                
            # Look for common CSRF token field names
            csrf_indicators = [
                "csrf", "token", "_token", "csrfmiddlewaretoken",
                "authenticity_token", "__RequestVerificationToken",
                "antiforgery", "xsrf", "_csrf_token"
            ]
            
            has_csrf_token = False
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            
            for hidden in hidden_inputs:
                name = (hidden.get("name") or "").lower()
                if any(indicator in name for indicator in csrf_indicators):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                action = form.get("action", url)
                vuln = self._create_vuln(
                    url=url,
                    description=f"POST form missing CSRF token (action: {action})",
                    evidence=f"Form with method=POST at {url} has no CSRF token hidden field",
                    severity_score=6.0,
                    severity_level=SeverityLevel.MEDIUM,  # type: ignore
                    severity_icon="🟡",
                    remediation=(
                        "1. Add a CSRF token to all state-changing forms\n"
                        "2. Validate the token server-side on every POST request\n"
                        "3. Use SameSite=Strict or Lax cookie attribute\n"
                        "4. Consider implementing double-submit cookie pattern"
                    ),
                    confidence="Medium"
                )
                vulns.append(vuln)
                
        return vulns
