"""
Production-Ready Web Security Scanner
Educational/Professional Vulnerability Assessment Tool
Version: 2.0.0
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import time
import json
import logging
import argparse
import sys
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Set, List, Tuple, Optional, Dict, Any
import urllib3
import urllib.robotparser as robotparser
from datetime import datetime
import hashlib

# Constants
VERSION = "2.0.0"
DEFAULT_MAX_PAGES = 50
DEFAULT_REQUEST_DELAY = 0.5
DEFAULT_WORKERS = 5
HTTP_TIMEOUT = 15
TIME_BASED_SQLI_THRESHOLD = 3.0
MIN_TIME_DELAY_DETECTION = 2.5
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 1.0

BANNER = """
╔════════════════════════════════════════════════════════════════╗
║  Professional Web Security Scanner v{version:<26}              ║
║  ⚠️ FOR AUTHORIZED SECURITY TESTING ONLY                       ║
║  Unauthorized scanning is illegal and unethical                ║
╚════════════════════════════════════════════════════════════════╝
""".format(version=VERSION)


class SeverityLevel(Enum):
    """Vulnerability severity levels with CVSS-like scoring"""
    CRITICAL = (9.0, "Critical", "🔴")
    HIGH = (7.0, "High", "🟠")
    MEDIUM = (5.0, "Medium", "🟡")
    LOW = (3.0, "Low", "🟢")
    INFO = (0.0, "Info", "🔵")


class VulnType(Enum):
    """Supported vulnerability types"""
    XSS = "Cross-Site Scripting (XSS)"
    SQLI = "SQL Injection"
    CSRF = "Cross-Site Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    PATH_TRAVERSAL = "Path Traversal"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    INFO_DISCLOSURE = "Information Disclosure"
    SECURITY_HEADERS = "Missing Security Headers"
    SENSITIVE_FILES = "Sensitive File Exposure"
    COOKIE_SECURITY = "Insecure Cookie Settings"
    CLICKJACKING = "Clickjacking"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    url: str
    vuln_type: str
    description: str
    severity_score: float
    severity_level: str
    severity_icon: str
    evidence: str
    timestamp: float
    remediation: str
    confidence: str  # High, Medium, Low
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        return asdict(self)


@dataclass
class ScanConfig:
    """Configuration for vulnerability scanner"""
    target_url: str
    max_pages: int = DEFAULT_MAX_PAGES
    request_delay: float = DEFAULT_REQUEST_DELAY
    verify_ssl: bool = True
    obey_robots: bool = True
    workers: int = DEFAULT_WORKERS
    user_agent: str = f"SecurityScanner/{VERSION}"
    timeout: int = HTTP_TIMEOUT
    max_retries: int = MAX_RETRIES
    scope_domains: Optional[List[str]] = None
    exclude_paths: Optional[List[str]] = None
    auth_token: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    verbose: bool = False
    skip_auth_check: bool = False


class ScannerLogger:
    """Enhanced logging with multiple output formats"""
    
    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        self.verbose = verbose
        self.logger = logging.getLogger("SecurityScanner")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
    
    def info(self, msg: str):
        self.logger.info(msg)
    
    def debug(self, msg: str):
        self.logger.debug(msg)
    
    def warning(self, msg: str):
        self.logger.warning(msg)
    
    def error(self, msg: str):
        self.logger.error(msg)
    
    def critical(self, msg: str):
        self.logger.critical(msg)


class RateLimiter:
    """Rate limiting to avoid overwhelming target"""
    
    def __init__(self, delay: float = DEFAULT_REQUEST_DELAY):
        self.delay = delay
        self.last_request = 0
        self.consecutive_errors = 0
    
    def wait(self):
        """Wait if necessary to respect rate limit"""
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request = time.time()
    
    def backoff(self):
        """Exponential backoff on errors"""
        self.consecutive_errors += 1
        backoff_time = min(30, 2 ** self.consecutive_errors)
        time.sleep(backoff_time)
    
    def reset_errors(self):
        """Reset error counter on success"""
        self.consecutive_errors = 0


class WebCrawler:
    """Intelligent web crawler with scope management"""
    
    def __init__(self, config: ScanConfig, logger: ScannerLogger):
        self.config = config
        self.logger = logger
        self.base_url = self._normalize_url(config.target_url)
        self.base_domain = urlparse(config.target_url).netloc
        self.visited: Set[str] = set()
        self.to_visit: deque = deque([self.base_url])
        self.robots_parser: Optional[robotparser.RobotFileParser] = None
        self.rate_limiter = RateLimiter(config.request_delay)
        
        # Initialize session
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        
        if self.config.headers:
            session.headers.update(self.config.headers)
        
        if self.config.cookies:
            session.cookies.update(self.config.cookies)
        
        if self.config.auth_token:
            session.headers["Authorization"] = f"Bearer {self.config.auth_token}"
        
        session.verify = self.config.verify_ssl
        
        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure retries
        adapter = requests.adapters.HTTPAdapter(
            max_retries=requests.adapters.Retry(
                total=self.config.max_retries,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for consistent comparison"""
        url = url.rstrip('/')
        parsed = urlparse(url)
        # Remove default ports
        netloc = parsed.netloc
        if netloc.endswith(':80') and parsed.scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and parsed.scheme == 'https':
            netloc = netloc[:-4]
        return f"{parsed.scheme}://{netloc}{parsed.path}"
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within scan scope"""
        parsed = urlparse(url)
        
        # Check domain scope
        if self.config.scope_domains:
            if parsed.netloc not in self.config.scope_domains:
                return False
        elif parsed.netloc != self.base_domain:
            return False
        
        # Check excluded paths
        if self.config.exclude_paths:
            for excluded in self.config.exclude_paths:
                if parsed.path.startswith(excluded):
                    self.logger.debug(f"Excluded path: {url}")
                    return False
        
        return True
    
    def _is_valid_link(self, url: str, href: str) -> bool:
        """Validate if link should be crawled"""
        # Skip special protocols
        if href.startswith(("mailto:", "tel:", "javascript:", "data:", "ftp:", "file:")):
            return False
        
        # Skip common static resources
        static_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', 
                            '.woff', '.woff2', '.ttf', '.eot', '.ico', '.pdf', 
                            '.zip', '.tar', '.gz', '.mp4', '.mp3', '.avi')
        if any(href.lower().endswith(ext) for ext in static_extensions):
            return False
        
        try:
            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return False
            
            # Check scope
            if not self._is_in_scope(full_url):
                return False
            
            # Check robots.txt
            if self.robots_parser and not self.robots_parser.can_fetch("*", full_url):
                self.logger.debug(f"Blocked by robots.txt: {full_url}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Invalid link {href}: {e}")
            return False
    
    def _load_robots_txt(self) -> None:
        """Load and parse robots.txt"""
        if not self.config.obey_robots:
            return
        
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200 and response.text.strip():
                self.robots_parser = robotparser.RobotFileParser()
                self.robots_parser.parse(response.text.splitlines())
                self.logger.info(f"Loaded robots.txt from {robots_url}")
            else:
                self.logger.debug(f"No robots.txt found (status {response.status_code})")
        except Exception as e:
            self.logger.warning(f"Failed to load robots.txt: {e}")
    
    def _extract_links(self, url: str, html_content: str) -> Set[str]:
        """Extract all valid links from HTML content"""
        links: Set[str] = set()
        
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Extract from <a> tags
            for tag in soup.find_all("a", href=True):
                href = tag['href'].strip()
                if self._is_valid_link(url, href):
                    full_url = urljoin(url, href).split('#')[0]
                    links.add(full_url)
            
            # Extract from <form> actions
            for form in soup.find_all("form", action=True):
                action = form['action'].strip()
                if self._is_valid_link(url, action):
                    full_url = urljoin(url, action).split('#')[0]
                    links.add(full_url)
            
        except Exception as e:
            self.logger.error(f"Error extracting links from {url}: {e}")
        
        return links
    
    def crawl_page(self, url: str) -> Tuple[str, Set[str], bool]:
        """Crawl a single page and return links"""
        self.rate_limiter.wait()
        
        try:
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            
            self.rate_limiter.reset_errors()
            
            # Only process HTML content
            content_type = response.headers.get('Content-Type', '').lower()
            if 'html' not in content_type:
                self.logger.debug(f"Skipping non-HTML: {url}")
                return url, set(), True
            
            links = self._extract_links(url, response.text)
            self.logger.info(f"Crawled: {url} ({len(links)} links)")
            
            return url, links, True
            
        except requests.Timeout:
            self.logger.warning(f"Timeout: {url}")
            return url, set(), False
        except requests.HTTPError as e:
            if e.response.status_code == 429:
                self.logger.warning("Rate limited by server, backing off...")
                self.rate_limiter.backoff()
            else:
                self.logger.error(f"HTTP {e.response.status_code}: {url}")
            return url, set(), False
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return url, set(), False
        except Exception as e:
            self.logger.error(f"Unexpected error crawling {url}: {e}")
            return url, set(), False
    
    def crawl(self) -> List[str]:
        """Crawl website and return discovered pages"""
        self.logger.info(f"Starting crawl of {self.base_url}")
        self._load_robots_txt()
        
        pages: List[str] = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
                futures = {}
                
                while (self.to_visit or futures) and len(self.visited) < self.config.max_pages:
                    # Submit new crawl tasks
                    while self.to_visit and len(futures) < self.config.workers:
                        url = self.to_visit.popleft()
                        if url not in self.visited:
                            self.visited.add(url)
                            pages.append(url)
                            future = executor.submit(self.crawl_page, url)
                            futures[future] = url
                    
                    # Process completed tasks
                    if futures:
                        done, _ = as_completed(futures, timeout=1), None
                        for future in list(futures.keys()):
                            if future.done():
                                url, links, success = future.result()
                                del futures[future]
                                
                                if success:
                                    # Add new links to queue
                                    for link in links:
                                        if link not in self.visited:
                                            self.to_visit.append(link)
                    
                    if not self.to_visit and not futures:
                        break
        
        except KeyboardInterrupt:
            self.logger.warning("Crawling interrupted by user")
        except Exception as e:
            self.logger.error(f"Crawling error: {e}")
        
        self.logger.info(f"Crawl complete: {len(pages)} pages discovered")
        return pages


class VulnerabilityTester:
    """Vulnerability testing engine"""
    
    SEVERITY_MAP = {
        VulnType.SQLI: SeverityLevel.CRITICAL,
        VulnType.XSS: SeverityLevel.HIGH,
        VulnType.XXE: SeverityLevel.HIGH,
        VulnType.SSRF: SeverityLevel.HIGH,
        VulnType.PATH_TRAVERSAL: SeverityLevel.HIGH,
        VulnType.CSRF: SeverityLevel.MEDIUM,
        VulnType.OPEN_REDIRECT: SeverityLevel.MEDIUM,
        VulnType.INFO_DISCLOSURE: SeverityLevel.LOW,
        VulnType.SECURITY_HEADERS: SeverityLevel.LOW,
        VulnType.SENSITIVE_FILES: SeverityLevel.HIGH,
        VulnType.COOKIE_SECURITY: SeverityLevel.LOW,
        VulnType.CLICKJACKING: SeverityLevel.MEDIUM,
    }
    
    REMEDIATION = {
        VulnType.XSS: "Sanitize user input, use Content Security Policy, encode output",
        VulnType.SQLI: "Use parameterized queries, input validation, least privilege DB access",
        VulnType.CSRF: "Implement CSRF tokens, SameSite cookies, verify Origin/Referer headers",
        VulnType.OPEN_REDIRECT: "Validate redirect URLs against whitelist, avoid user-controlled redirects",
        VulnType.PATH_TRAVERSAL: "Validate file paths, use whitelists, avoid direct file access",
        VulnType.XXE: "Disable external entity processing, use secure XML parsers",
        VulnType.SSRF: "Validate URLs, use allowlists, disable unnecessary protocols",
        VulnType.INFO_DISCLOSURE: "Remove sensitive information from responses, proper error handling",
        VulnType.SECURITY_HEADERS: "Configure security headers (HSTS, CSP, etc.)",
        VulnType.SENSITIVE_FILES: "Remove sensitive files from public access, configure access controls",
        VulnType.COOKIE_SECURITY: "Set Secure and HttpOnly flags on cookies",
        VulnType.CLICKJACKING: "Implement X-Frame-Options or CSP frame-ancestors",
    }
    
    def __init__(self, session: requests.Session, config: ScanConfig, logger: ScannerLogger):
        self.session = session
        self.config = config
        self.logger = logger
        self.rate_limiter = RateLimiter(config.request_delay)
    
    def _get_vulnerability_details(self, vuln_type: VulnType) -> Tuple[float, str, str]:
        """Get severity and remediation for vulnerability type"""
        severity = self.SEVERITY_MAP.get(vuln_type, SeverityLevel.LOW)
        score, level, icon = severity.value
        remediation = self.REMEDIATION.get(vuln_type, "Follow security best practices")
        return score, level, icon, remediation
    
    def extract_forms(self, url: str) -> List[BeautifulSoup]:
        """Extract forms from page"""
        try:
            self.rate_limiter.wait()
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")
            
            self.logger.debug(f"Found {len(forms)} forms on {url}")
            return forms
            
        except Exception as e:
            self.logger.error(f"Failed to extract forms from {url}: {e}")
            return []
    
    def _extract_csrf_token(self, form: BeautifulSoup, soup: BeautifulSoup) -> Optional[Tuple[str, str]]:
        """Extract CSRF token from form or page"""
        # Check form inputs
        for inp in form.find_all("input"):
            name = inp.get("name", "").lower()
            if any(token in name for token in ["csrf", "token", "_token", "xsrf"]):
                value = inp.get("value")
                if value:
                    return inp["name"], value
        
        # Check meta tags
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            if "csrf" in name or "token" in name:
                value = meta.get("content")
                if value:
                    return name, value
        
        return None
    
    def submit_form(self, form: BeautifulSoup, url: str, payload: Optional[str] = None, 
                   include_csrf: bool = True) -> Optional[requests.Response]:
        """Submit form with payload"""
        try:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action) if action else url
            
            form_data = {}
            
            # Extract all form inputs
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                
                input_type = inp.get("type", "text").lower()
                if input_type == "submit":
                    continue
                
                # Use payload for text inputs, default value otherwise
                if payload and input_type in ("text", "search", "email", "url", "tel", "password"):
                    form_data[name] = payload
                else:
                    form_data[name] = inp.get("value", "")
            
            # Handle select dropdowns
            for select in form.find_all("select"):
                name = select.get("name")
                if name:
                    option = select.find("option")
                    form_data[name] = option.get("value", "") if option else ""
            
            # Add CSRF token if needed
            if include_csrf:
                response = self.session.get(url, timeout=self.config.timeout)
                soup = BeautifulSoup(response.content, "html.parser")
                csrf_token = self._extract_csrf_token(form, soup)
                if csrf_token:
                    form_data[csrf_token[0]] = csrf_token[1]
            
            self.rate_limiter.wait()
            
            if method == "post":
                return self.session.post(form_url, data=form_data, timeout=self.config.timeout)
            else:
                return self.session.get(form_url, params=form_data, timeout=self.config.timeout)
                
        except Exception as e:
            self.logger.debug(f"Form submission failed: {e}")
            return None
    
    def test_xss(self, form: BeautifulSoup, url: str) -> Optional[Vulnerability]:
        """Test for XSS vulnerabilities"""
        payloads = [
            ("<script>alert('XSS')</script>", "script tag"),
            ("<img src=x onerror=alert(1)>", "img onerror"),
            ("<svg onload=alert(1)>", "svg onload"),
            ("'><script>alert(String.fromCharCode(88,83,83))</script>", "quote break"),
            ("<iframe src=javascript:alert(1)>", "javascript protocol"),
        ]
        
        for payload, desc in payloads:
            response = self.submit_form(form, url, payload)
            
            if response and payload in response.text:
                score, level, icon, remediation = self._get_vulnerability_details(VulnType.XSS)
                
                return Vulnerability(
                    url=url,
                    vuln_type=VulnType.XSS.value,
                    description=f"Reflected XSS via {desc}",
                    severity_score=score,
                    severity_level=level,
                    severity_icon=icon,
                    evidence=f"Payload reflected: {payload[:50]}...",
                    timestamp=time.time(),
                    remediation=remediation,
                    confidence="High"
                )
        
        return None
    
    def test_sqli(self, form: BeautifulSoup, url: str) -> Optional[Vulnerability]:
        """Test for SQL injection vulnerabilities"""
        # Measure baseline
        baseline_start = time.time()
        baseline_response = self.submit_form(form, url, "test_baseline_value")
        baseline_time = time.time() - baseline_start
        
        if not baseline_response:
            return None
        
        # Error-based detection
        error_payloads = [
            ("' OR '1'='1'-- -", "OR condition"),
            ("\" OR \"\"=\"\"-- -", "double quote OR"),
            ("' UNION SELECT NULL-- -", "UNION injection"),
            ("1' AND '1'='2", "AND condition"),
        ]
        
        error_patterns = [
            (r"SQL syntax.*MySQL", "MySQL"),
            (r"Warning: mysql_", "MySQL"),
            (r"ORA-\d{5}", "Oracle"),
            (r"PostgreSQL.*ERROR", "PostgreSQL"),
            (r"SQLite3::", "SQLite"),
            (r"Microsoft SQL Native Client", "MSSQL"),
            (r"ODBC SQL Server Driver", "MSSQL"),
        ]
        
        for payload, desc in error_payloads:
            response = self.submit_form(form, url, payload)
            if not response:
                continue
            
            for pattern, db_type in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    score, level, icon, remediation = self._get_vulnerability_details(VulnType.SQLI)
                    
                    return Vulnerability(
                        url=url,
                        vuln_type=VulnType.SQLI.value,
                        description=f"SQL Injection ({db_type}) - {desc}",
                        severity_score=score,
                        severity_level=level,
                        severity_icon=icon,
                        evidence=f"SQL error detected with payload: {payload}",
                        timestamp=time.time(),
                        remediation=remediation,
                        confidence="High"
                    )
        
        # Time-based detection
        time_payloads = [
            "' AND SLEEP(3)-- -",
            "'; WAITFOR DELAY '0:0:3'-- -",
            "' AND pg_sleep(3)-- -",
        ]
        
        for payload in time_payloads:
            start = time.time()
            response = self.submit_form(form, url, payload)
            elapsed = time.time() - start
            
            if response and elapsed > (baseline_time + MIN_TIME_DELAY_DETECTION):
                score, level, icon, remediation = self._get_vulnerability_details(VulnType.SQLI)
                
                return Vulnerability(
                    url=url,
                    vuln_type=VulnType.SQLI.value,
                    description="Time-based SQL Injection",
                    severity_score=score,
                    severity_level=level,
                    severity_icon=icon,
                    evidence=f"Delay detected: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                    timestamp=time.time(),
                    remediation=remediation,
                    confidence="Medium"
                )
        
        return None
    
    def test_csrf(self, form: BeautifulSoup, url: str) -> Optional[Vulnerability]:
        """Test for CSRF vulnerabilities"""
        method = form.get("method", "get").lower()
        
        # Only test POST forms
        if method != "post":
            return None
        
        # Check if form has CSRF protection
        response = self.session.get(url, timeout=self.config.timeout)
        soup = BeautifulSoup(response.content, "html.parser")
        csrf_token = self._extract_csrf_token(form, soup)
        
        if csrf_token:
            return None  # Has CSRF protection
        
        # Try submitting without CSRF token
        response = self.submit_form(form, url, None, include_csrf=False)
        
        if response and 200 <= response.status_code < 300:
            score, level, icon, remediation = self._get_vulnerability_details(VulnType.CSRF)
            
            return Vulnerability(
                url=url,
                vuln_type=VulnType.CSRF.value,
                description="Missing CSRF protection on state-changing operation",
                severity_score=score,
                severity_level=level,
                severity_icon=icon,
                evidence="POST form accepts requests without CSRF token",
                timestamp=time.time(),
                remediation=remediation,
                confidence="High"
            )
        
        return None
    
    def test_open_redirect(self, url: str) -> Optional[Vulnerability]:
        """Test for open redirect vulnerabilities"""
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'continue', 'dest']
        test_url = "https://evil.com"
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param in redirect_params:
            if param in query_params or param.lower() in [k.lower() for k in query_params.keys()]:
                # Test redirect
                test_params = query_params.copy()
                test_params[param] = [test_url]
                
                test_query = "&".join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    self.rate_limiter.wait()
                    response = self.session.get(test_full_url, timeout=self.config.timeout, allow_redirects=False)
                    
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get('Location', '')
                        if test_url in location:
                            score, level, icon, remediation = self._get_vulnerability_details(VulnType.OPEN_REDIRECT)
                            
                            return Vulnerability(
                                url=url,
                                vuln_type=VulnType.OPEN_REDIRECT.value,
                                description=f"Open redirect via '{param}' parameter",
                                severity_score=score,
                                severity_level=level,
                                severity_icon=icon,
                                evidence=f"Redirects to: {location}",
                                timestamp=time.time(),
                                remediation=remediation,
                                confidence="High"
                            )
                except Exception:
                    pass
        
        return None
    
    def test_path_traversal(self, url: str) -> Optional[Vulnerability]:
        """Test for path traversal vulnerabilities"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        path_params = ['file', 'path', 'page', 'template', 'doc', 'document']
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ]
        
        indicators = [
            "root:x:",  # Unix /etc/passwd
            "[extensions]",  # Windows win.ini
        ]
        
        for param_key in query_params.keys():
            if any(p in param_key.lower() for p in path_params):
                for payload in payloads:
                    test_params = query_params.copy()
                    test_params[param_key] = [payload]
                    
                    test_query = "&".join([f"{k}={v[0]}" for k, v in test_params.items()])
                    test_full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        self.rate_limiter.wait()
                        response = self.session.get(test_full_url, timeout=self.config.timeout)
                        
                        for indicator in indicators:
                            if indicator in response.text:
                                score, level, icon, remediation = self._get_vulnerability_details(VulnType.PATH_TRAVERSAL)
                                
                                return Vulnerability(
                                    url=url,
                                    vuln_type=VulnType.PATH_TRAVERSAL.value,
                                    description=f"Path traversal via '{param_key}' parameter",
                                    severity_score=score,
                                    severity_level=level,
                                    severity_icon=icon,
                                    evidence=f"File content exposed: {indicator}",
                                    timestamp=time.time(),
                                    remediation=remediation,
                                    confidence="High"
                                )
                    except Exception:
                        pass
        
        return None
    
    def test_info_disclosure(self, url: str, content: str) -> List[Vulnerability]:
        """Test for information disclosure"""
        vulnerabilities = []
        
        patterns = [
            (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key"),
            (r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret Key"),
            (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{3,})", "Password"),
            (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([^'\"]{20,})", "Private Key"),
            (r"(?i)(access[_-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})", "Access Token"),
            (r"mysql://[^:]+:[^@]+@", "MySQL Credentials"),
            (r"postgres://[^:]+:[^@]+@", "PostgreSQL Credentials"),
        ]
        
        for pattern, desc in patterns:
            matches = re.findall(pattern, content)
            if matches:
                score, level, icon, remediation = self._get_vulnerability_details(VulnType.INFO_DISCLOSURE)
                
                vulnerabilities.append(Vulnerability(
                    url=url,
                    vuln_type=VulnType.INFO_DISCLOSURE.value,
                    description=f"Exposed {desc} in page source",
                    severity_score=score if "password" in desc.lower() or "key" in desc.lower() else 2.0,
                    severity_level=level if "password" in desc.lower() else "Low",
                    severity_icon=icon,
                    evidence=f"Pattern matched: {desc}",
                    timestamp=time.time(),
                    remediation=remediation,
                    confidence="Medium"
                ))
        
        return vulnerabilities

    def test_security_headers(self, url: str, response: requests.Response) -> List[Vulnerability]:
        """Test for missing or weak security headers"""
        vulnerabilities = []
        headers = response.headers
        
        # Check HSTS
        if 'Strict-Transport-Security' not in headers and url.startswith("https://"):
            score, level, icon, remediation = self._get_vulnerability_details(VulnType.SECURITY_HEADERS)
            vulnerabilities.append(Vulnerability(
                url=url,
                vuln_type=VulnType.SECURITY_HEADERS.value,
                description="Missing Strict-Transport-Security Header",
                severity_score=score,
                severity_level=level,
                severity_icon=icon,
                evidence="Header not found",
                timestamp=time.time(),
                remediation=remediation,
                confidence="High"
            ))
            
        # Check CSP
        if 'Content-Security-Policy' not in headers:
            score, level, icon, remediation = self._get_vulnerability_details(VulnType.SECURITY_HEADERS)
            vulnerabilities.append(Vulnerability(
                url=url,
                vuln_type=VulnType.SECURITY_HEADERS.value,
                description="Missing Content-Security-Policy Header",
                severity_score=score,
                severity_level=level,
                severity_icon=icon,
                evidence="Header not found",
                timestamp=time.time(),
                remediation=remediation,
                confidence="High"
            ))
            
        # Check X-Frame-Options (Clickjacking)
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers: # CSP can handle this too
            score, level, icon, remediation = self._get_vulnerability_details(VulnType.CLICKJACKING)
            vulnerabilities.append(Vulnerability(
                url=url,
                vuln_type=VulnType.CLICKJACKING.value,
                description="Missing Anti-Clickjacking Header",
                severity_score=score,
                severity_level=level,
                severity_icon=icon,
                evidence="X-Frame-Options and CSP frame-ancestors incorrect",
                timestamp=time.time(),
                remediation=remediation,
                confidence="High"
            ))
            
        # Check X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            score, level, icon, remediation = self._get_vulnerability_details(VulnType.SECURITY_HEADERS)
            vulnerabilities.append(Vulnerability(
                url=url,
                vuln_type=VulnType.SECURITY_HEADERS.value,
                description="Missing X-Content-Type-Options Header",
                severity_score=score,
                severity_level=level,
                severity_icon=icon,
                evidence="Header not found",
                timestamp=time.time(),
                remediation=remediation,
                confidence="High"
            ))

        return vulnerabilities

    def test_cookie_security(self, url: str, response: requests.Response) -> List[Vulnerability]:
        """Test for insecure cookie attributes"""
        vulnerabilities = []
        
        for cookie in response.cookies:
            if not cookie.secure and url.startswith("https://"):
                score, level, icon, remediation = self._get_vulnerability_details(VulnType.COOKIE_SECURITY)
                vulnerabilities.append(Vulnerability(
                    url=url,
                    vuln_type=VulnType.COOKIE_SECURITY.value,
                    description=f"Cookie '{cookie.name}' missing Secure flag",
                    severity_score=score,
                    severity_level=level,
                    severity_icon=icon,
                    evidence=f"Cookie: {cookie.name}",
                    timestamp=time.time(),
                    remediation=remediation,
                    confidence="High"
                ))
            
            if not cookie.has_nonstandard_attr('HttpOnly'):
                score, level, icon, remediation = self._get_vulnerability_details(VulnType.COOKIE_SECURITY)
                vulnerabilities.append(Vulnerability(
                    url=url,
                    vuln_type=VulnType.COOKIE_SECURITY.value,
                    description=f"Cookie '{cookie.name}' missing HttpOnly flag",
                    severity_score=score,
                    severity_level=level,
                    severity_icon=icon,
                    evidence=f"Cookie: {cookie.name}",
                    timestamp=time.time(),
                    remediation=remediation,
                    confidence="High"
                ))
                
        return vulnerabilities

    def test_sensitive_files(self, url: str) -> List[Vulnerability]:
        """Test for exposed sensitive files"""
        vulnerabilities = []
        common_files = [
            '.env',
            '.git/config',
            '.git/HEAD',
            'backup.zip',
            'backup.sql',
            'wp-config.php.bak',
            '.htaccess'
        ]
        
        for file in common_files:
            target_url = urljoin(url, file)
            try:
                self.rate_limiter.wait()
                response = self.session.get(target_url, timeout=self.config.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    # Verify it's not a custom 404 page by checking length/content
                    # Ideally we compare with a known 404, but here we do simple checks
                    if len(response.text) < 5000 and "html" not in response.headers.get('Content-Type', '').lower():
                         score, level, icon, remediation = self._get_vulnerability_details(VulnType.SENSITIVE_FILES)
                         vulnerabilities.append(Vulnerability(
                            url=target_url,
                            vuln_type=VulnType.SENSITIVE_FILES.value,
                            description=f"Exposed sensitive file: {file}",
                            severity_score=score,
                            severity_level=level,
                            severity_icon=icon,
                            evidence=f"Ref: {target_url} - Status: 200",
                            timestamp=time.time(),
                            remediation=remediation,
                            confidence="Medium"
                        ))
            except Exception:
                pass
                
        return vulnerabilities


class VulnerabilityScanner:
    """Main vulnerability scanner orchestrator"""
    
    def __init__(self, config: ScanConfig, logger: Optional[ScannerLogger] = None):
        self.config = config
        if logger:
            self.logger = logger
        else:
            self.logger = ScannerLogger(
                verbose=config.verbose,
                log_file=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
        self.vulnerabilities: List[Vulnerability] = []
        self.start_time: Optional[float] = None
        self.crawler: Optional[WebCrawler] = None
        self.tester: Optional[VulnerabilityTester] = None
        self._scan_active = True
    
    def _verify_authorization(self) -> None:
        """Verify user has authorization to scan"""
        if self.config.skip_auth_check:
            self.logger.info("Skipping manual authorization check (API mode)")
            return
            
        print(BANNER)
        print(f"Target: {self.config.target_url}\n")
        print("⚠️  CRITICAL WARNING:")
        print("    • Scanning without authorization is ILLEGAL")
        print("    • You may face criminal prosecution")
        print("    • Only scan systems you own or have written permission to test")
        print("    • Ensure you have a signed authorization letter\n")
        
        response = input("Do you have EXPLICIT written AUTHORIZATION to scan this target? (type 'YES' in capitals): ")
        
        if response.strip() != "YES":
            raise PermissionError("Authorization not confirmed. Exiting.")
        
        print("\n✓ Authorization confirmed\n")
        self.logger.info(f"Scan authorized for {self.config.target_url}")
    
    def _validate_target(self) -> None:
        """Validate target URL"""
        parsed = urlparse(self.config.target_url)
        
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        if parsed.scheme not in ('http', 'https'):
            raise ValueError("Only HTTP/HTTPS protocols supported")
        
        # Warn about scanning localhost/private IPs
        if parsed.netloc in ('localhost', '127.0.0.1', '0.0.0.0'):
            self.logger.warning("Scanning localhost - ensure this is intentional")
        
        # Check for private IP ranges
        import ipaddress
        try:
            hostname = parsed.netloc.split(':')[0]
            ip = ipaddress.ip_address(hostname)
            if ip.is_private:
                self.logger.warning(f"Scanning private IP: {hostname}")
        except ValueError:
            pass  # Not an IP address
    
    def stop_scan(self) -> None:
        """Stop the scan gracefully"""
        self._scan_active = False
        self.logger.warning("Scan stop requested")
    
    def scan(self) -> List[Vulnerability]:
        """Execute full vulnerability scan"""
        try:
            self._verify_authorization()
            self._validate_target()
            
            self.start_time = time.time()
            self.logger.info("="*70)
            self.logger.info("VULNERABILITY SCAN STARTED")
            self.logger.info("="*70)
            self.logger.info(f"Target: {self.config.target_url}")
            self.logger.info(f"Max Pages: {self.config.max_pages}")
            self.logger.info(f"Workers: {self.config.workers}")
            self.logger.info(f"SSL Verify: {self.config.verify_ssl}")
            self.logger.info(f"Obey robots.txt: {self.config.obey_robots}")
            self.logger.info("="*70)
            
            # Phase 1: Crawling
            self.logger.info("\n[PHASE 1] Website Crawling")
            self.logger.info("-"*70)
            self.crawler = WebCrawler(self.config, self.logger)
            pages = self.crawler.crawl()
            
            if not pages:
                self.logger.error("No pages discovered. Scan cannot continue.")
                return []
            
            # Phase 2: Vulnerability Testing
            self.logger.info(f"\n[PHASE 2] Vulnerability Testing ({len(pages)} pages)")
            self.logger.info("-"*70)
            
            session = self.crawler.session
            self.tester = VulnerabilityTester(session, self.config, self.logger)
            
            for i, page in enumerate(pages, 1):
                if not self._scan_active:
                    self.logger.warning("Scan stopped by user")
                    break
                
                self.logger.info(f"\n[{i}/{len(pages)}] Testing: {page}")
                
                # Test URL-based vulnerabilities
                open_redirect = self.tester.test_open_redirect(page)
                if open_redirect:
                    self.vulnerabilities.append(open_redirect)
                
                path_traversal = self.tester.test_path_traversal(page)
                if path_traversal:
                    self.vulnerabilities.append(path_traversal)
                
                # Get page content for info disclosure check
                # Get page content for info disclosure check
                response = None
                try:
                    response = session.get(page, timeout=self.config.timeout)
                    info_disclosures = self.tester.test_info_disclosure(page, response.text)
                    self.vulnerabilities.extend(info_disclosures)
                except Exception:
                    pass

                if response:
                    # Test Security Headers
                    self.vulnerabilities.extend(self.tester.test_security_headers(page, response))
                    
                    # Test Cookie Security
                    self.vulnerabilities.extend(self.tester.test_cookie_security(page, response))

                # Test Sensitive Files (Only on base URL or directory roots to save time/requests)
                if page.count('/') <= 3: # Approximation for root/near-root pages
                     self.vulnerabilities.extend(self.tester.test_sensitive_files(page))
                
                # Test forms
                forms = self.tester.extract_forms(page)
                for j, form in enumerate(forms, 1):
                    if not self._scan_active:
                        break
                    
                    self.logger.debug(f"  Testing form {j}/{len(forms)}")
                    
                    xss = self.tester.test_xss(form, page)
                    if xss:
                        self.vulnerabilities.append(xss)
                    
                    sqli = self.tester.test_sqli(form, page)
                    if sqli:
                        self.vulnerabilities.append(sqli)
                    
                    csrf = self.tester.test_csrf(form, page)
                    if csrf:
                        self.vulnerabilities.append(csrf)
            
            # Deduplicate vulnerabilities
            self._deduplicate_vulnerabilities()
            
            # Summary
            duration = time.time() - self.start_time
            self.logger.info("\n" + "="*70)
            self.logger.info("SCAN COMPLETE")
            self.logger.info("="*70)
            self.logger.info(f"Duration: {duration:.2f} seconds")
            self.logger.info(f"Pages Scanned: {len(pages)}")
            self.logger.info(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
            
            if self.vulnerabilities:
                self._print_vulnerability_summary()
            else:
                self.logger.info("\n✓ No vulnerabilities detected")
            
            return self.vulnerabilities
            
        except PermissionError as e:
            self.logger.critical(f"Authorization failed: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            self.logger.warning("\nScan interrupted by user")
            return self.vulnerabilities
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
    
    def _deduplicate_vulnerabilities(self) -> None:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in self.vulnerabilities:
            # Create hash of vulnerability
            key = hashlib.md5(
                f"{vuln.url}{vuln.vuln_type}{vuln.description}".encode()
            ).hexdigest()
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        removed = len(self.vulnerabilities) - len(unique)
        if removed > 0:
            self.logger.debug(f"Removed {removed} duplicate vulnerabilities")
        
        self.vulnerabilities = unique
    
    def _print_vulnerability_summary(self) -> None:
        """Print summary of found vulnerabilities"""
        self.logger.info("\n" + "="*70)
        self.logger.info("VULNERABILITIES FOUND")
        self.logger.info("="*70)
        
        # Group by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            by_severity.setdefault(vuln.severity_level, []).append(vuln)
        
        for level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulns = by_severity.get(level, [])
            if vulns:
                self.logger.info(f"\n{level.upper()}: {len(vulns)}")
                for vuln in vulns:
                    self.logger.info(f"  {vuln.severity_icon} [{vuln.vuln_type}] {vuln.url}")
                    self.logger.info(f"     {vuln.description}")
    
    def generate_text_report(self, output_dir: str = "reports") -> Optional[str]:
        """Generate detailed text report"""
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.txt"
            filepath = Path(output_dir) / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("VULNERABILITY ASSESSMENT REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Target URL:        {self.config.target_url}\n")
                f.write(f"Scan Date:         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Duration:     {time.time() - self.start_time:.2f} seconds\n")
                f.write(f"Scanner Version:   {VERSION}\n")
                f.write(f"Pages Scanned:     {len(self.crawler.visited) if self.crawler else 0}\n")
                f.write(f"Total Findings:    {len(self.vulnerabilities)}\n\n")
                
                # Executive Summary
                f.write("-"*80 + "\n")
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-"*80 + "\n\n")
                
                by_severity = {}
                for vuln in self.vulnerabilities:
                    by_severity.setdefault(vuln.severity_level, []).append(vuln)
                
                f.write(f"Critical: {len(by_severity.get('Critical', []))}\n")
                f.write(f"High:     {len(by_severity.get('High', []))}\n")
                f.write(f"Medium:   {len(by_severity.get('Medium', []))}\n")
                f.write(f"Low:      {len(by_severity.get('Low', []))}\n")
                f.write(f"Info:     {len(by_severity.get('Info', []))}\n\n")
                
                # Detailed Findings
                if self.vulnerabilities:
                    f.write("="*80 + "\n")
                    f.write("DETAILED FINDINGS\n")
                    f.write("="*80 + "\n\n")
                    
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        f.write(f"[{i}] {vuln.vuln_type}\n")
                        f.write("-"*80 + "\n")
                        f.write(f"Severity:      {vuln.severity_level} ({vuln.severity_score})\n")
                        f.write(f"Confidence:    {vuln.confidence}\n")
                        f.write(f"URL:           {vuln.url}\n")
                        f.write(f"Description:   {vuln.description}\n")
                        f.write(f"Evidence:      {vuln.evidence}\n")
                        f.write(f"Remediation:   {vuln.remediation}\n")
                        f.write(f"Detected:      {datetime.fromtimestamp(vuln.timestamp).strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("\n")
                else:
                    f.write("No vulnerabilities detected.\n\n")
                
                # Recommendations
                f.write("="*80 + "\n")
                f.write("RECOMMENDATIONS\n")
                f.write("="*80 + "\n\n")
                f.write("1. Address all Critical and High severity findings immediately\n")
                f.write("2. Implement security best practices (input validation, output encoding)\n")
                f.write("3. Conduct regular security assessments\n")
                f.write("4. Keep all software and dependencies up to date\n")
                f.write("5. Implement Web Application Firewall (WAF)\n")
                f.write("6. Enable security headers (CSP, HSTS, X-Frame-Options, etc.)\n\n")
            
            self.logger.info(f"✓ Text report saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate text report: {e}")
            return None
    
    def generate_json_report(self, output_dir: str = "reports") -> Optional[str]:
        """Generate JSON report"""
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
            filepath = Path(output_dir) / filename
            
            report = {
                "scan_info": {
                    "target": self.config.target_url,
                    "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                    "duration_seconds": round(time.time() - self.start_time, 2),
                    "scanner_version": VERSION,
                    "pages_scanned": len(self.crawler.visited) if self.crawler else 0,
                },
                "summary": {
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "by_severity": {
                        "critical": len([v for v in self.vulnerabilities if v.severity_level == "Critical"]),
                        "high": len([v for v in self.vulnerabilities if v.severity_level == "High"]),
                        "medium": len([v for v in self.vulnerabilities if v.severity_level == "Medium"]),
                        "low": len([v for v in self.vulnerabilities if v.severity_level == "Low"]),
                        "info": len([v for v in self.vulnerabilities if v.severity_level == "Info"]),
                    },
                    "by_type": {}
                },
                "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities]
            }
            
            # Count by type
            for vuln in self.vulnerabilities:
                vuln_type = vuln.vuln_type
                report["summary"]["by_type"][vuln_type] = report["summary"]["by_type"].get(vuln_type, 0) + 1
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"✓ JSON report saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            return None
    
    def generate_html_report(self, output_dir: str = "reports") -> Optional[str]:
        """Generate HTML report"""
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.html"
            filepath = Path(output_dir) / filename
            
            # Count by severity
            by_severity = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Info": []
            }
            for vuln in self.vulnerabilities:
                by_severity[vuln.severity_level].append(vuln)
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {self.config.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 3px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #333; font-size: 2em; margin-bottom: 10px; }}
        .header .meta {{ color: #666; font-size: 0.9em; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .summary-card.critical {{ background: #ff4444; color: white; }}
        .summary-card.high {{ background: #ff8800; color: white; }}
        .summary-card.medium {{ background: #ffcc00; color: #333; }}
        .summary-card.low {{ background: #88cc00; color: white; }}
        .summary-card.info {{ background: #0088ff; color: white; }}
        .summary-card .number {{ font-size: 3em; font-weight: bold; }}
        .summary-card .label {{ font-size: 1em; margin-top: 10px; }}
        .vulnerability {{ background: #f9f9f9; border-left: 5px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 4px; }}
        .vulnerability.critical {{ border-left-color: #ff4444; }}
        .vulnerability.high {{ border-left-color: #ff8800; }}
        .vulnerability.medium {{ border-left-color: #ffcc00; }}
        .vulnerability.low {{ border-left-color: #88cc00; }}
        .vulnerability.info {{ border-left-color: #0088ff; }}
        .vulnerability .header {{ border: none; padding: 0; margin: 0 0 15px 0; display: flex; justify-content: space-between; align-items: center; }}
        .vulnerability .title {{ font-size: 1.3em; font-weight: bold; color: #333; }}
        .vulnerability .badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
        .vulnerability .badge.critical {{ background: #ff4444; color: white; }}
        .vulnerability .badge.high {{ background: #ff8800; color: white; }}
        .vulnerability .badge.medium {{ background: #ffcc00; color: #333; }}
        .vulnerability .badge.low {{ background: #88cc00; color: white; }}
        .vulnerability .badge.info {{ background: #0088ff; color: white; }}
        .vulnerability .detail {{ margin: 10px 0; }}
        .vulnerability .detail strong {{ color: #555; display: inline-block; width: 120px; }}
        .vulnerability .url {{ color: #0066cc; word-break: break-all; }}
        .vulnerability .evidence {{ background: #fff; padding: 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; margin-top: 10px; }}
        .vulnerability .remediation {{ background: #e8f5e9; padding: 15px; border-radius: 4px; margin-top: 10px; border-left: 3px solid #4caf50; }}
        .section-title {{ font-size: 1.8em; color: #333; margin: 30px 0 20px 0; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self.config.target_url}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {time.time() - self.start_time:.2f} seconds</p>
                <p><strong>Pages Scanned:</strong> {len(self.crawler.visited) if self.crawler else 0}</p>
                <p><strong>Scanner Version:</strong> {VERSION}</p>
            </div>
        </div>

        <h2 class="section-title">Executive Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <div class="number">{len(by_severity['Critical'])}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{len(by_severity['High'])}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{len(by_severity['Medium'])}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{len(by_severity['Low'])}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="number">{len(by_severity['Info'])}</div>
                <div class="label">Info</div>
            </div>
        </div>
"""
            
            if self.vulnerabilities:
                html_content += '<h2 class="section-title">Detailed Findings</h2>\n'
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    severity_class = vuln.severity_level.lower()
                    html_content += f'''
        <div class="vulnerability {severity_class}">
            <div class="header">
                <div class="title">{i}. {vuln.vuln_type}</div>
                <span class="badge {severity_class}">{vuln.severity_icon} {vuln.severity_level}</span>
            </div>
            <div class="detail"><strong>URL:</strong> <span class="url">{vuln.url}</span></div>
            <div class="detail"><strong>Description:</strong> {vuln.description}</div>
            <div class="detail"><strong>Confidence:</strong> {vuln.confidence}</div>
            <div class="evidence"><strong>Evidence:</strong> {vuln.evidence}</div>
            <div class="remediation"><strong>💡 Remediation:</strong> {vuln.remediation}</div>
        </div>
'''
            else:
                html_content += '<p>✅ No vulnerabilities detected during this scan.</p>\n'
            
            html_content += """
        <div class="footer">
            <p>Generated by Security Scanner v""" + VERSION + """</p>
            <p>This report is confidential and for authorized use only.</p>
        </div>
    </div>
</body>
</html>"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"✓ HTML report saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return None


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Production-Ready Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --max-pages 100 --workers 10
  %(prog)s -u https://example.com --no-verify-ssl --verbose
  %(prog)s -u https://example.com --exclude /admin /api/private
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=DEFAULT_MAX_PAGES, help=f'Maximum pages to crawl (default: {DEFAULT_MAX_PAGES})')
    parser.add_argument('--delay', type=float, default=DEFAULT_REQUEST_DELAY, help=f'Delay between requests in seconds (default: {DEFAULT_REQUEST_DELAY})')
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS, help=f'Number of concurrent workers (default: {DEFAULT_WORKERS})')
    parser.add_argument('--timeout', type=int, default=HTTP_TIMEOUT, help=f'HTTP timeout in seconds (default: {HTTP_TIMEOUT})')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    parser.add_argument('--exclude', nargs='+', help='Paths to exclude from scan')
    parser.add_argument('--cookie', help='Cookies in format "name1=value1; name2=value2"')
    parser.add_argument('--header', action='append', help='Custom headers in format "Name: Value"')
    parser.add_argument('--auth-token', help='Authorization bearer token')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports (default: reports)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    try:
        args = parse_arguments()
        
        # Parse cookies
        cookies = None
        if args.cookie:
            cookies = {}
            for pair in args.cookie.split(';'):
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookies[key] = value
        
        # Parse headers
        headers = None
        if args.header:
            headers = {}
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Create configuration
        config = ScanConfig(
            target_url=args.url,
            max_pages=args.max_pages,
            request_delay=args.delay,
            verify_ssl=not args.no_verify_ssl,
            obey_robots=not args.no_robots,
            workers=args.workers,
            timeout=args.timeout,
            exclude_paths=args.exclude,
            cookies=cookies,
            headers=headers,
            auth_token=args.auth_token,
            verbose=args.verbose
        )
        
        # Initialize and run scanner
        scanner = VulnerabilityScanner(config)
        vulnerabilities = scanner.scan()
        
        # Generate reports
        print("\n" + "="*70)
        print("GENERATING REPORTS")
        print("="*70)
        
        scanner.generate_text_report(args.output_dir)
        scanner.generate_json_report(args.output_dir)
        scanner.generate_html_report(args.output_dir)
        
        print("\n✓ All reports generated successfully")
        print(f"✓ Reports saved to: {args.output_dir}/")
        
        # Exit code based on findings
        if any(v.severity_level in ['Critical', 'High'] for v in vulnerabilities):
            sys.exit(1)  # Critical/High findings
        elif vulnerabilities:
            sys.exit(2)  # Medium/Low findings
        else:
            sys.exit(0)  # No findings
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except PermissionError as e:
        print(f"\n❌ Authorization Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n❌ Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()