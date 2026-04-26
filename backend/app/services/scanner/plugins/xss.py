from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import urllib.parse
import logging

logger = logging.getLogger(__name__)

class ReflectedXSS(BaseCheck):
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.XSS

    def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
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
            
            inputs = form.find_all("input")
            textareas = form.find_all("textarea")
            all_fields = inputs + textareas
            
            for field in all_fields:
                name = field.get("name")
                if not name or field.get("type") in ["submit", "image", "hidden", "button"]:
                    continue
                
                for payload, desc in payloads:
                    data = {}
                    for i in all_fields:
                        field_name = i.get("name")
                        if not field_name:
                            continue
                        if field_name == name:
                            data[field_name] = payload
                        else:
                            data[field_name] = "test"
                            
                    try:
                        if method == "post":
                            resp = self.session.post(target_url, data=data, timeout=5)
                        else:
                            resp = self.session.get(target_url, params=data, timeout=5)
                            
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
                        logger.debug(f"XSS test failed on {target_url}: {e}")
                        
        return vulns
