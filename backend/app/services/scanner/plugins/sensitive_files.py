from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import logging
import httpx
from urllib.parse import urlparse, urlunparse

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

# Paths that must NOT return JSON — if they do it's a framework error page
_NON_JSON_PATHS = {p for p, _ in SENSITIVE_PATHS if p not in ("config.json",)}


class SensitiveFiles(BaseCheck):
    """Check for exposed sensitive files and directories (Async)."""

    def __init__(self, client: httpx.AsyncClient):
        super().__init__(client)
        self._probed_origins: set[str] = set()
        self._reported_paths: set[tuple[str, str]] = set()

    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SENSITIVE_FILES

    async def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []
        parsed = urlparse(url)
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
        if origin in self._probed_origins:
            return vulns
        self._probed_origins.add(origin)

        for path, description in SENSITIVE_PATHS:
            try:
                probe_url = f"{origin}/{path}"
                fingerprint = (origin, path)
                if fingerprint in self._reported_paths:
                    continue
                # We don't follow redirects to avoid false positives on login pages
                resp = await self.client.get(probe_url, timeout=5, follow_redirects=False)

                # Only flag HTTP 200 with actual content
                if resp.status_code == 200 and len(resp.text) > 0:
                    if self._looks_like_real_content(path, resp):
                        self._reported_paths.add(fingerprint)
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

    def _looks_like_real_content(self, path: str, resp: httpx.Response) -> bool:
        """
        Heuristic to avoid false positives from custom 404 pages.
        """
        text = resp.text

        if len(text) < 10:
            return False

        # Layer 1: Content-type gating
        content_type = resp.headers.get("content-type", "").lower()
        if "json" in content_type and path in _NON_JSON_PATHS:
            return False

        # Layer 2: HTML error-page string matching
        lower = text.lower()
        if any(indicator in lower for indicator in [
            "page not found", "404 not found", "not found", "error 404",
            "route not found", "cannot get /", "no such file",
            "sign in", "log in", "login required", "authentication required",
        ]):
            return False

        if "text/html" in content_type:
            if "<!doctype html" in lower and ("<div id=\"root\"" in lower or "<div id=\"app\"" in lower):
                return False
            if path in {".env", ".git/HEAD", ".git/config"} and "<html" in lower:
                return False

        # Layer 3: File-specific content validation
        if path.endswith(".env") and not re_search_env(text):
            return False
        if "git" in path and "ref:" not in text and "[core]" not in text:
            return False
        if path.endswith(".sql") and not any(token in lower for token in ["create table", "insert into", "dump", "database"]):
            return False

        return True

    def _get_severity(self, path: str) -> tuple:
        """Return (score, level, icon) based on file sensitivity."""
        high_risk = [".env", ".git/", "wp-config", "backup.sql", "dump.sql", "database.sql"]
        if any(h in path for h in high_risk):
            return (8.0, SeverityLevel.HIGH, "🟠")
        return (5.0, SeverityLevel.MEDIUM, "🟡")


def re_search_env(text: str) -> bool:
    for line in text.splitlines()[:50]:
        if "=" in line and not line.strip().startswith(("<", "{", "[")):
            key = line.split("=", 1)[0].strip()
            if key and key.replace("_", "").replace("-", "").isalnum():
                return True
    return False
