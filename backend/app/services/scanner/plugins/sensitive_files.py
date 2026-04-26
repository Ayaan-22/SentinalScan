from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import logging

logger = logging.getLogger(__name__)

# Common sensitive files and directories to probe
SENSITIVE_PATHS = [
    (".env", "Environment configuration file"),
    (".git/HEAD", "Git repository metadata"),
    (".git/config", "Git repository configuration"),
    ("wp-config.php", "WordPress configuration"),
    ("phpinfo.php", "PHP information page"),
    (".htaccess", "Apache configuration file"),
    ("web.config", "IIS configuration file"),
    ("robots.txt", "Robots file (informational)"),
    (".DS_Store", "macOS directory metadata"),
    ("backup.sql", "Database backup file"),
    ("dump.sql", "Database dump file"),
    ("database.sql", "Database export file"),
    (".env.bak", "Environment backup file"),
    ("config.yml", "YAML configuration file"),
    ("config.json", "JSON configuration file"),
    ("composer.json", "PHP dependency manifest"),
    ("package.json", "Node.js dependency manifest"),
    ("Dockerfile", "Docker configuration"),
    ("docker-compose.yml", "Docker Compose configuration"),
]


class SensitiveFiles(BaseCheck):
    """Check for exposed sensitive files and directories"""
    
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SENSITIVE_FILES

    def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []
        base_url = url.rstrip("/")
        
        for path, description in SENSITIVE_PATHS:
            try:
                probe_url = f"{base_url}/{path}"
                resp = self.session.get(probe_url, timeout=5, follow_redirects=False)
                
                # Only flag if we get a 200 OK with actual content
                if resp.status_code == 200 and len(resp.text) > 0:
                    # Avoid false positives — skip if it's a generic error/404 page
                    if self._looks_like_real_content(path, resp.text):
                        severity = self._get_severity(path)
                        vuln = self._create_vuln(
                            url=probe_url,
                            description=f"Sensitive file exposed: {path} ({description})",
                            evidence=f"HTTP 200 returned for /{path} ({len(resp.text)} bytes)",
                            severity_score=severity[0],
                            severity_level=severity[1],  # type: ignore
                            severity_icon=severity[2],
                            remediation=(
                                f"1. Remove or restrict access to /{path}\n"
                                "2. Configure web server to deny access to sensitive files\n"
                                "3. Add rules to .htaccess or nginx config to block these paths\n"
                                "4. Move sensitive files outside the web root"
                            ),
                            confidence="Medium"
                        )
                        vulns.append(vuln)
                        
            except Exception as e:
                logger.debug(f"Sensitive file probe failed for {path}: {e}")
                
        return vulns

    def _looks_like_real_content(self, path: str, text: str) -> bool:
        """Basic heuristic to avoid false positives from custom 404 pages."""
        if len(text) < 10:
            return False
        lower = text.lower()
        # If the response contains typical 404/error page indicators, skip
        if any(indicator in lower for indicator in ["page not found", "404", "not found"]):
            return False
        # For specific file types, check for expected content markers
        if path.endswith(".env") and "=" in text:
            return True
        if "git" in path and ("ref:" in text or "[core]" in text):
            return True
        return True

    def _get_severity(self, path: str) -> tuple:
        """Return (score, level, icon) based on file sensitivity."""
        high_risk = [".env", ".git/", "wp-config", "backup.sql", "dump.sql", "database.sql"]
        if any(h in path for h in high_risk):
            return (8.0, SeverityLevel.HIGH, "🟠")
        return (5.0, SeverityLevel.MEDIUM, "🟡")
