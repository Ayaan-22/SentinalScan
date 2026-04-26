from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck
from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel
import urllib.parse
import re
import time
import logging

logger = logging.getLogger(__name__)

class SQLInjection(BaseCheck):
    @property
    def vuln_type(self) -> VulnType:
        return VulnType.SQLI

    # SQL error patterns by database engine
    SQL_ERRORS = {
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

    def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        vulns = []
        
        # Error-based payloads
        error_payloads = [
            ("'", "Single quote injection"),
            ('"', "Double quote injection"),
            ("' OR '1'='1", "Boolean-based OR injection"),
            ("' OR '1'='1' --", "OR injection with comment"),
            ("1; DROP TABLE test --", "Stacked query attempt"),
            ("' UNION SELECT NULL--", "UNION-based injection"),
        ]
        
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target_url = urllib.parse.urljoin(url, action)
            
            inputs = form.find_all("input")
            for inp in inputs:
                name = inp.get("name")
                if not name or inp.get("type") in ["submit", "image", "button"]:
                    continue
                
                for payload, desc in error_payloads:
                    data = {}
                    for i in inputs:
                        field_name = i.get("name")
                        if not field_name:
                            continue
                        if field_name == name:
                            data[field_name] = payload
                        else:
                            data[field_name] = "1"
                            
                    try:
                        if method == "post":
                            resp = self.session.post(target_url, data=data, timeout=5)
                        else:
                            resp = self.session.get(target_url, params=data, timeout=5)
                            
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
                        logger.debug(f"SQLi test failed on {target_url}: {e}")
                        
        return vulns
