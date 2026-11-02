import asyncio
import ipaddress
import logging
import socket
from urllib import robotparser
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings
from app.models.policy import ScanMode, canonical_url, origin
from app.models.scan import ScanRequest
from app.services.scanner.authorization import AuthorizationStore

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

    def __init__(self, config: ScanRequest, *, store: AuthorizationStore | None = None,
                 scan_id: str = "standalone"):
        self.config = config
        self.store = store or AuthorizationStore()
        self.scan_id = scan_id
        self.base_url = self._normalize_url(config.target_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.base_origin = f"{urlparse(self.base_url).scheme}://{self.base_domain}"
        self.visited: set[str] = set()
        self.robots_parser: robotparser.RobotFileParser | None = None
        self.response_cache: dict[str, str] = {}
        self.client: httpx.AsyncClient | None = None
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
                trust_env=False,
            )

            if self.config.auth_token:
                self.client.headers["Authorization"] = f"Bearer {self.config.auth_token}"

        return self.client

    def stop(self) -> None:
        self._stopped = True

    def _normalize_url(self, url: str) -> str:
        return canonical_url(url)

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
            logger.warning(f"SSRF blocked: IP validation error for '{hostname}': {e}", exc_info=True)
            return False

    async def _is_valid_link(self, url: str, href: str) -> bool:
        try:
            full_url = self._normalize_url(urljoin(url, href))
            parsed = urlparse(full_url)

            if parsed.scheme not in ('http', 'https'):
                return False

            # Scope check — stay on the same domain
            if origin(full_url) != self.base_origin:
                return False

            self.store.require(self.config.policy_id, self.config.mode, "GET", full_url)

            # SSRF check on the resolved IP
            if not await self._is_safe_ip(parsed.hostname or ""):
                return False

            # robots.txt compliance check
            if (
                self.config.obey_robots
                and self.robots_parser
                and not self.robots_parser.can_fetch(settings.USER_AGENT, full_url)
            ):
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
            return not any(parsed.path.lower().endswith(ext) for ext in static_exts)
        except Exception:
            logger.debug("Link validation failed", exc_info=True)
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
        if origin(normalized) != self.base_origin:
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
        current_url = self._normalize_url(url)
        for _ in range(5):
            if self._stopped:
                raise asyncio.CancelledError("Crawler stopped")
            resp = await self.request("GET", current_url, **kwargs)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp

            location = resp.headers.get("location")
            if not location:
                return resp
            next_url = self._normalize_url(urljoin(current_url, location))
            if origin(next_url) != self.base_origin:
                raise ValueError(f"Blocked redirect outside scan origin: {next_url}")
            current_url = next_url

        raise ValueError("Too many redirects")

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Only outbound send route. A policy denial happens before client/DNS access."""
        if self._stopped:
            raise asyncio.CancelledError("Crawler stopped")
        # HTTPX redirect/auth flows can perform additional sends without returning
        # to this validator. Only safe_get may follow redirects, one checked hop
        # at a time; plugins may retain their existing follow_redirects=False.
        if kwargs.pop("follow_redirects", False) is not False:
            raise PermissionError("Automatic redirects are forbidden")
        if "auth" in kwargs:
            raise PermissionError("Per-request authentication flows are forbidden")
        method = method.upper()
        # Apply query parameters before checking sensitive operations and recording scope.
        params = kwargs.pop("params", None)
        request_url = canonical_url(url)
        if params is not None:
            query = str(httpx.QueryParams(params))
            request_url += ("&" if "?" in request_url else "?") + query
        prepared = httpx.Request(method, request_url)
        final_url = str(prepared.url)
        self.store.require(self.config.policy_id, self.config.mode, method, final_url)
        for headers in (self.config.headers or {}, kwargs.get("headers") or {}):
            if any(name.lower() in {"host", "x-http-method-override", "x-method-override", "x-http-method"} for name in headers):
                raise PermissionError("Host and HTTP method overrides are forbidden")
        final_url = await self._validate_request_url(final_url)
        client = await self._get_client()
        # Recheck expiry immediately before send, including time spent resolving DNS.
        policy = self.store.require(self.config.policy_id, self.config.mode, method, final_url)
        if self._stopped:
            raise asyncio.CancelledError("Crawler stopped")
        request_id = self.store.record_request(self.scan_id, policy, method, final_url)
        try:
            policy.require_request(self.config.mode, method, final_url)
        except PermissionError:
            self.store.finish_request(request_id, "blocked")
            raise
        try:
            response = await client.request(method, final_url, follow_redirects=False, **kwargs)
        except BaseException:
            self.store.finish_request(request_id, "uncertain")
            raise
        self.store.finish_request(request_id, "responded", response.status_code)
        return response

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def _load_robots_txt(self) -> None:
        """Fetch and parse robots.txt for the target domain."""
        if not self.config.obey_robots:
            return

        robots_url = f"{self.base_origin}/robots.txt"
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
            logger.debug(f"Could not fetch robots.txt from {robots_url}: {e}", exc_info=True)

    async def crawl(self) -> list[str]:
        """Crawl the target using an async queue-based approach."""
        if self.config.mode == ScanMode.PASSIVE:
            for page in self.config.captured_pages[:self.config.max_pages]:
                self.response_cache[page.url] = page.content
            return list(self.response_cache)
        self.store.require(self.config.policy_id, self.config.mode, "GET", self.base_url)
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
                except Exception:
                    logger.exception("Worker error crawling %s", url)
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
        except TimeoutError:
            logger.warning("Crawl queue join timed out")
        finally:
            # Cancel all workers
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        logger.info(f"Async crawl complete: {len(pages)} pages discovered")
        return pages

    async def _fetch_page(self, url: str) -> set[str] | None:
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

            return links
        except httpx.HTTPStatusError as e:
            logger.debug(f"HTTP error fetching {url}: {e.response.status_code}")
            return None
        except httpx.RequestError as e:
            logger.debug(f"Request error fetching {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error fetching {url}: {e}", exc_info=True)
            return None

    async def close(self):
        """Close the Async HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None
