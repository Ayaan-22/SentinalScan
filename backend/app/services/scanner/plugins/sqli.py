import logging
import re
import urllib.parse
from typing import ClassVar

from bs4 import BeautifulSoup

from app.models.vulnerability import SeverityLevel, Vulnerability, VulnType

from .base import BaseCheck
from .forms import probe_forms, submit_probe

logger = logging.getLogger(__name__)

class SQLInjection(BaseCheck):
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SQLI

    # SQL error patterns by database engine
    SQL_ERRORS: ClassVar[dict[str, list[str]]] = {
        "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException"],
        "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"PSQLException"],
        "MSSQL": [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"SQLServerException"],
        "Oracle": [r"ORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver"],
        "SQLite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite"],
        "Generic": [r"SQL syntax", r"mysql_fetch", r"Unclosed quotation mark"],
    }

    def _has_sql_error(self, text: str) -> str | None:
        """Check response text for SQL error patterns. Returns DB name if found."""
        for db, patterns in self.SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db
        return None

    async def check(self, url: str, content: str, forms: list[BeautifulSoup]) -> list[Vulnerability]:
        vulns = []
        
        # Payloads require active authorization: submitting any form may change state.
        error_payloads = [
            ("'", "Single quote injection"),
            ('"', "Double quote injection"),
            ("' OR '1'='1", "Boolean-based OR injection"),
            ("' OR '1'='1' --", "OR injection with comment"),
            ("' UNION SELECT NULL--", "UNION-based injection"),
        ]
        
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target_url = urllib.parse.urljoin(url, action)
            
            for name, index, baseline in probe_forms(form):
                for payload, desc in error_payloads:
                    try:
                        resp = await submit_probe(self.client, method, target_url, baseline, index, payload)

                        db_type = self._has_sql_error(resp.text)
                        if db_type:
                            vuln = self._create_vuln(
                                url=target_url,
                                description=f"SQL Injection ({db_type}) in '{name}' field — {desc}",
                                evidence=f"Payload '{payload}' triggered {db_type} SQL error in response",
                                severity_score=9.0,
                                severity_level=SeverityLevel.CRITICAL,  # type: ignore
                                severity_icon="🔴",
                                remediation=(
                                    "1. Use parameterized queries (prepared statements) exclusively\n"
                                    "2. Apply input validation with allowlists\n"
                                    "3. Use an ORM with parameterized query support\n"
                                    "4. Implement least-privilege database accounts\n"
                                    "5. Enable WAF rules for SQL injection detection"
                                )
                            )
                            vulns.append(vuln)
                            break  # Found SQLi in this field, move to next
                    except Exception as e:
                        logger.debug(f"SQLi test failed on {target_url}: {e}", exc_info=True)
                        
        return vulns
