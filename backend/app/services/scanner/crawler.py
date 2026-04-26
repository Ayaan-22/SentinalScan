import httpx
import uuid
from urllib.parse import urljoin, urlparse
from typing import Set, List, Optional, Deque, Dict
from collections import deque
import logging
from bs4 import BeautifulSoup
import urllib.robotparser as robotparser
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ipaddress
from app.models.scan import ScanRequest
from app.core.config import settings

logger = logging.getLogger(__name__)

# SSRF Protection — hard block on private/internal CIDRs
BLOCKED_CIDRS = [
    "10.0.0.0/8",        # RFC-1918 private
    "172.16.0.0/12",     # RFC-1918 private
    "192.168.0.0/16",    # RFC-1918 private
    "127.0.0.0/8",       # loopback
    "169.254.0.0/16",    # link-local / AWS/GCP/Azure metadata
    "100.64.0.0/10",     # shared address space (CGNAT)
    "0.0.0.0/8",         # "this" network
    "::1/128",           # IPv6 loopback
    "fc00::/7",          # IPv6 private
    "fe80::/10",         # IPv6 link-local
]
_BLOCKED_NETS = [ipaddress.ip_network(c) for c in BLOCKED_CIDRS]


class WebCrawler:
    """Secure Web Crawler with SSRF protection and httpx client"""
    
    def __init__(self, config: ScanRequest):
        self.config = config
        self.base_url = self._normalize_url(config.target_url)
        self.base_domain = urlparse(config.target_url).netloc
        self.visited: Set[str] = set()
        self.to_visit: Deque[str] = deque([self.base_url])
        self.robots_parser: Optional[robotparser.RobotFileParser] = None
        self.response_cache: Dict[str, str] = {}
        self.session = self._create_session()
        
    def _create_session(self) -> httpx.Client:
        headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        if self.config.headers:
            headers.update(self.config.headers)
            
        cookies = None
        if self.config.cookies:
            cookies = self.config.cookies

        client = httpx.Client(
            headers=headers,
            cookies=cookies,
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            follow_redirects=True,
        )
            
        if self.config.auth_token:
            client.headers["Authorization"] = f"Bearer {self.config.auth_token}"
            
        return client

    def _normalize_url(self, url: str) -> str:
        return url.rstrip('/')

    def _is_safe_ip(self, hostname: str) -> bool:
        """Prevent SSRF by blocking private/loopback/metadata IPs.
        
        SECURITY: Returns False (block) on DNS resolution failure.
        This prevents DNS rebinding and ensures only resolvable public hosts are scanned.
        """
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            for net in _BLOCKED_NETS:
                if ip in net:
                    logger.warning(f"SSRF blocked: {hostname} resolves to {ip_str} in {net}")
                    return False
            return True
        except socket.gaierror:
            logger.warning(f"SSRF blocked: cannot resolve hostname '{hostname}'")
            return False
        except Exception as e:
            logger.warning(f"SSRF blocked: IP validation error for '{hostname}': {e}")
            return False

    def _is_valid_link(self, url: str, href: str) -> bool:
        try:
            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            
            if parsed.scheme not in ('http', 'https'):
                return False
                
            # Scope check — stay on the same domain
            if parsed.netloc != self.base_domain:
                return False
                
            # SSRF check on the resolved IP
            if not self._is_safe_ip(parsed.hostname or ""):
                return False

            # Exclude paths
            if self.config.exclude_paths:
                for excluded in self.config.exclude_paths:
                    if parsed.path.startswith(excluded):
                        return False
            
            # Skip static assets
            static_exts = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                          '.css', '.js', '.pdf', '.zip', '.tar', '.gz',
                          '.mp3', '.mp4', '.avi', '.mov', '.woff', '.woff2',
                          '.ttf', '.eot')
            if any(parsed.path.lower().endswith(ext) for ext in static_exts):
                return False
                
            return True
        except Exception:
            return False

    def validate_target(self) -> None:
        """Validate the scan target before crawling. Raises ValueError if blocked."""
        parsed = urlparse(self.config.target_url)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Cannot extract hostname from target URL")
        if not self._is_safe_ip(hostname):
            raise ValueError(
                f"Target '{hostname}' resolves to a blocked IP range. "
                "Scanning internal/private addresses is not permitted."
            )

    def crawl(self) -> List[str]:
        """Crawl the target, returning a list of discovered page URLs."""
        # Validate target before starting
        self.validate_target()
        
        logger.info(f"Starting crawl of {self.base_url}")
        pages = []
        
        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            while self.to_visit and len(self.visited) < self.config.max_pages:
                batch = []
                while self.to_visit and len(batch) < self.config.workers:
                    url = self.to_visit.popleft()
                    if url not in self.visited:
                        self.visited.add(url)
                        batch.append(url)
                
                if not batch:
                    break
                
                futures = {executor.submit(self._fetch_page, u): u for u in batch}
                
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        new_links = future.result()
                        if new_links is not None:
                            pages.append(url)
                            for link in new_links:
                                if link not in self.visited and len(self.visited) < self.config.max_pages:
                                    self.to_visit.append(link)
                    except Exception as e:
                        logger.error(f"Error crawling {url}: {e}")
                        
        logger.info(f"Crawl complete: {len(pages)} pages discovered")
        return pages

    def _fetch_page(self, url: str) -> Optional[Set[str]]:
        try:
            resp = self.session.get(url)
            content_type = resp.headers.get('Content-Type', '').lower()
            if 'html' not in content_type:
                return None
            
            # Cache the response for later vulnerability testing
            self.response_cache[url] = resp.text
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            
            # Extract links from anchors
            for a in soup.find_all('a', href=True):
                href = a['href']
                if self._is_valid_link(url, href):
                    links.add(urljoin(url, href).split('#')[0])
            
            # Extract links from forms
            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action and self._is_valid_link(url, action):
                    links.add(urljoin(url, action).split('#')[0])
                    
            return links
        except httpx.HTTPStatusError as e:
            logger.debug(f"HTTP error fetching {url}: {e.response.status_code}")
            return None
        except httpx.RequestError as e:
            logger.debug(f"Request error fetching {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error fetching {url}: {e}")
            return None

    def close(self):
        """Close the HTTP client session."""
        if self.session:
            self.session.close()
