import httpx
import asyncio
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from typing import Set, List, Optional, Dict
import logging
from bs4 import BeautifulSoup
import urllib.robotparser as robotparser
import socket
import ipaddress
from app.models.scan import ScanRequest
from app.core.config import settings

logger = logging.getLogger(__name__)

# SSRF Protection. RFC1918/private networks are allowed only with explicit
# operator opt-in; loopback, link-local, metadata, CGNAT, and reserved networks
# are always blocked.
PRIVATE_CIDRS = [
    "10.0.0.0/8",        # RFC-1918 private
    "172.16.0.0/12",     # RFC-1918 private
    "192.168.0.0/16",    # RFC-1918 private
    "fc00::/7",          # IPv6 private
]
ALWAYS_BLOCKED_CIDRS = [
    "127.0.0.0/8",       # loopback
    "169.254.0.0/16",    # link-local / AWS/GCP/Azure metadata
    "100.64.0.0/10",     # shared address space (CGNAT)
    "0.0.0.0/8",         # "this" network
    "240.0.0.0/4",       # reserved
    "::1/128",           # IPv6 loopback
    "fe80::/10",         # IPv6 link-local
]
_PRIVATE_NETS = [ipaddress.ip_network(c) for c in PRIVATE_CIDRS]
_ALWAYS_BLOCKED_NETS = [ipaddress.ip_network(c) for c in ALWAYS_BLOCKED_CIDRS]


class WebCrawler:
    """Secure Async Web Crawler with SSRF protection and robots.txt compliance."""

    def __init__(self, config: ScanRequest):
        self.config = config
        self.base_url = self._normalize_url(config.target_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.base_origin = f"{urlparse(self.base_url).scheme}://{self.base_domain}"
        self.visited: Set[str] = set()
        self.robots_parser: Optional[robotparser.RobotFileParser] = None
        self.response_cache: Dict[str, str] = {}
        self.client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(config.workers)
        self._stopped = False
        self.max_response_bytes = 2_000_000

    async def _get_client(self) -> httpx.AsyncClient:
        if self.client is None:
            headers = {
                "User-Agent": settings.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }

            if self.config.headers:
                headers.update(self.config.headers)

            cookies = self.config.cookies if self.config.cookies else None

            self.client = httpx.AsyncClient(
                headers=headers,
                cookies=cookies,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
                follow_redirects=False,
            )

            if self.config.auth_token:
                self.client.headers["Authorization"] = f"Bearer {self.config.auth_token}"

        return self.client

    def stop(self) -> None:
        self._stopped = True

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        netloc = hostname
        if parsed.port and not (
            (scheme == "http" and parsed.port == 80)
            or (scheme == "https" and parsed.port == 443)
        ):
            netloc = f"{hostname}:{parsed.port}"
        path = parsed.path or "/"
        path = path.rstrip("/") or "/"
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return urlunparse((scheme, netloc, path, "", query, ""))

    async def _is_safe_ip(self, hostname: str) -> bool:
        """Prevent SSRF by blocking private/loopback/metadata IPs.

        SECURITY: Returns False (block) on DNS resolution failure.
        """
        try:
            # We use asyncio's getaddrinfo to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(hostname, None)
            
            for family, type, proto, canonname, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)

                for net in _ALWAYS_BLOCKED_NETS:
                    if ip in net:
                        logger.warning(f"SSRF blocked: {hostname} resolves to {ip_str} in {net}")
                        return False
                for net in _PRIVATE_NETS:
                    if ip in net:
                        if self.config.allow_private_targets:
                            logger.warning(
                                "Private target allowed by explicit operator opt-in: "
                                f"{hostname} resolves to {ip_str} in {net}"
                            )
                            continue
                        logger.warning(f"SSRF blocked: {hostname} resolves to {ip_str} in {net}")
                        return False
            return True
        except socket.gaierror:
            logger.warning(f"SSRF blocked: cannot resolve hostname '{hostname}'")
            return False
        except Exception as e:
            logger.warning(f"SSRF blocked: IP validation error for '{hostname}': {e}")
            return False

    async def _is_valid_link(self, url: str, href: str) -> bool:
        try:
            full_url = self._normalize_url(urljoin(url, href))
            parsed = urlparse(full_url)

            if parsed.scheme not in ('http', 'https'):
                return False

            # Scope check — stay on the same domain
            if parsed.netloc.lower() != self.base_domain:
                return False

            # SSRF check on the resolved IP
            if not await self._is_safe_ip(parsed.hostname or ""):
                return False

            # robots.txt compliance check
            if self.config.obey_robots and self.robots_parser:
                if not self.robots_parser.can_fetch(settings.USER_AGENT, full_url):
                    logger.debug(f"robots.txt disallows: {full_url}")
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

    async def validate_target(self) -> None:
        """Validate the scan target before crawling. Raises ValueError if blocked."""
        parsed = urlparse(self.config.target_url)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Cannot extract hostname from target URL")
        if not await self._is_safe_ip(hostname):
            raise ValueError(
                f"Target '{hostname}' resolves to a blocked IP range. "
                "Scanning internal/private addresses requires explicit authorization "
                "and allow_private_targets=true."
            )

    async def _validate_request_url(self, url: str) -> str:
        normalized = self._normalize_url(url)
        parsed = urlparse(normalized)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported URL scheme")
        if parsed.netloc.lower() != self.base_domain:
            raise ValueError("Blocked cross-origin request")
        if not parsed.hostname or not await self._is_safe_ip(parsed.hostname):
            raise ValueError(f"Blocked unsafe request host: {parsed.hostname}")
        if self.config.exclude_paths:
            for excluded in self.config.exclude_paths:
                if parsed.path.startswith(excluded):
                    raise ValueError(f"Blocked excluded path: {parsed.path}")
        return normalized

    async def safe_get(self, url: str, **kwargs) -> httpx.Response:
        """GET with per-request SSRF and manual redirect validation."""
        client = await self._get_client()
        current_url = await self._validate_request_url(url)
        for _ in range(5):
            if self._stopped:
                raise asyncio.CancelledError("Crawler stopped")
            resp = await client.get(current_url, follow_redirects=False, **kwargs)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp

            location = resp.headers.get("location")
            if not location:
                return resp
            next_url = self._normalize_url(urljoin(current_url, location))
            next_parsed = urlparse(next_url)
            if next_parsed.netloc.lower() != self.base_domain:
                raise ValueError(f"Blocked redirect outside scan origin: {next_url}")
            current_url = await self._validate_request_url(next_url)

        raise ValueError("Too many redirects")

    async def _load_robots_txt(self) -> None:
        """Fetch and parse robots.txt for the target domain."""
        if not self.config.obey_robots:
            return

        robots_url = f"{self.base_url}/robots.txt"
        try:
            resp = await self.safe_get(robots_url, timeout=5)
            if resp.status_code == 200:
                parser = robotparser.RobotFileParser()
                parser.set_url(robots_url)
                parser.parse(resp.text.splitlines())
                self.robots_parser = parser
                logger.info(f"robots.txt loaded from {robots_url}")
            else:
                logger.debug(f"robots.txt not found at {robots_url} (HTTP {resp.status_code})")
        except Exception as e:
            logger.debug(f"Could not fetch robots.txt from {robots_url}: {e}")

    async def crawl(self) -> List[str]:
        """Crawl the target using an async queue-based approach."""
        await self.validate_target()
        await self._load_robots_txt()

        logger.info(f"Starting async crawl of {self.base_url}")
        
        queue = asyncio.Queue()
        await queue.put(self.base_url)
        self.visited.add(self.base_url)
        
        pages = []
        
        async def worker():
            while True:
                url = await queue.get()
                try:
                    if self._stopped:
                        return
                    if len(pages) >= self.config.max_pages:
                        return

                    async with self._semaphore:
                        new_links = await self._fetch_page(url)
                    
                    if new_links is not None:
                        pages.append(url)
                        for link in new_links:
                            if link not in self.visited and len(pages) + queue.qsize() < self.config.max_pages:
                                self.visited.add(link)
                                await queue.put(link)
                except Exception as e:
                    logger.error(f"Worker error crawling {url}: {e}")
                finally:
                    queue.task_done()

        # Start workers
        workers = [asyncio.create_task(worker()) for _ in range(self.config.workers)]
        
        # Wait for queue to be empty or max_pages reached
        try:
            while not self._stopped and not queue.empty() and len(pages) < self.config.max_pages:
                await asyncio.sleep(0.1)
            
            # Wait for remaining tasks with timeout
            await asyncio.wait_for(queue.join(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("Crawl queue join timed out")
        finally:
            # Cancel all workers
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        logger.info(f"Async crawl complete: {len(pages)} pages discovered")
        return pages

    async def _fetch_page(self, url: str) -> Optional[Set[str]]:
        try:
            resp = await self.safe_get(url)
            
            content_type = resp.headers.get('Content-Type', '').lower()
            if 'html' not in content_type:
                return None

            if len(resp.content) > self.max_response_bytes:
                logger.warning(f"Skipping oversized response from {url}")
                return None

            # Cache the response for later vulnerability testing
            self.response_cache[url] = resp.text

            # Parsing is CPU-bound, but for small pages BS4 is okay.
            # In Phase 3, we could offload this to a ProcessPool if needed.
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()

            for a in soup.find_all('a', href=True):
                href = a['href']
                if await self._is_valid_link(url, href):
                    links.add(self._normalize_url(urljoin(url, href)))

            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action and await self._is_valid_link(url, action):
                    links.add(self._normalize_url(urljoin(url, action)))

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

    async def close(self):
        """Close the Async HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None
