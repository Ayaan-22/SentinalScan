import logging
import urllib.parse

from bs4 import BeautifulSoup

from app.models.vulnerability import SeverityLevel, Vulnerability, VulnType

from .base import BaseCheck
from .forms import probe_forms, submit_probe

logger = logging.getLogger(__name__)

class ReflectedXSS(BaseCheck):
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.XSS

    async def check(self, url: str, content: str, forms: list[BeautifulSoup]) -> list[Vulnerability]:
        vulns = []
        payloads = [
            ("<script>alert('XSS')</script>", "script tag injection"),
            ("<img src=x onerror=alert(1)>", "img onerror handler"),
            ("<svg onload=alert(1)>", "svg onload handler"),
            ("'><script>alert(1)</script>", "attribute breakout"),
            ('"><img src=x onerror=alert(1)>', "double-quote breakout"),
            ("javascript:alert(1)", "javascript URI"),
        ]
        
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target_url = urllib.parse.urljoin(url, action)
            
            for name, index, baseline in probe_forms(form):
                for payload, desc in payloads:
                    try:
                        resp = await submit_probe(self.client, method, target_url, baseline, index, payload)

                        if payload in resp.text:
                            vuln = self._create_vuln(
                                url=target_url,
                                description=f"Reflected XSS via '{name}' field ({desc})",
                                evidence=f"Payload reflected in response: {payload[:80]}",
                                severity_score=7.5,
                                severity_level=SeverityLevel.HIGH,  # type: ignore
                                severity_icon="🟠",
                                remediation=(
                                    "1. Sanitize all user input using context-aware encoding\n"
                                    "2. Implement Content Security Policy (CSP) headers\n"
                                    "3. Use HttpOnly and Secure flags on cookies\n"
                                    "4. Consider using a templating engine with auto-escaping"
                                )
                            )
                            vulns.append(vuln)
                            break  # Found XSS in this field, move to next
                    except Exception as e:
                        logger.debug(f"XSS test failed on {target_url}: {e}", exc_info=True)
                        
        return vulns
