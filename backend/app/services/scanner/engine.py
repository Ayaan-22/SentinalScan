import logging
import asyncio
import time
from typing import List, Set, Tuple
from bs4 import BeautifulSoup
from app.models.scan import ScanRequest
from app.models.vulnerability import Vulnerability
from app.services.scanner.crawler import WebCrawler
from app.services.scanner.plugins.base import BaseCheck
from app.services.scanner.plugins.xss import ReflectedXSS
from app.services.scanner.plugins.sqli import SQLInjection
from app.services.scanner.plugins.headers import SecurityHeaders
from app.services.scanner.plugins.sensitive_files import SensitiveFiles
from app.services.scanner.plugins.csrf import CSRFCheck

logger = logging.getLogger(__name__)

class ScannerEngine:
    """Core scanning engine — Async crawl + parallel test pipeline"""
    
    def __init__(self, config: ScanRequest):
        self.config = config
        self.crawler = WebCrawler(config)
        self.vulnerabilities: List[Vulnerability] = []
        self._stop_event = False
        self._pages_scanned = 0
        self.plugins: List[BaseCheck] = []

    async def _init_plugins(self):
        """Initialize plugins with the crawler's async client."""
        client = await self.crawler._get_client()
        self.plugins = [
            ReflectedXSS(client),
            SQLInjection(client),
            SecurityHeaders(client),
            SensitiveFiles(client),
            CSRFCheck(client),
        ]

    def stop(self):
        self._stop_event = True
        self.crawler.stop() if hasattr(self.crawler, 'stop') else None

    @property
    def pages_scanned(self) -> int:
        return self._pages_scanned

    def _extract_forms(self, content: str) -> List[BeautifulSoup]:
        try:
            # CPU-bound, but BS4 is relatively fast for individual pages
            return BeautifulSoup(content, 'html.parser').find_all('form')
        except Exception:
            return []

    def _deduplicate_vulnerabilities(self) -> None:
        """Remove duplicate vulnerabilities based on (url, vuln_type, description) fingerprint."""
        seen: Set[Tuple[str, str, str]] = set()
        unique = []
        for vuln in self.vulnerabilities:
            fingerprint = (
                vuln.url,
                vuln.vuln_type.value if hasattr(vuln.vuln_type, 'value') else str(vuln.vuln_type),
                vuln.description,
            )
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(vuln)
        
        removed = len(self.vulnerabilities) - len(unique)
        if removed > 0:
            logger.info(f"Deduplication removed {removed} duplicate findings")
        self.vulnerabilities = unique

    async def run(self) -> List[Vulnerability]:
        """Execute the full async scan pipeline."""
        start_time = time.time()
        logger.info('=' * 60)
        logger.info("VULNERABILITY SCAN STARTED (ASYNC ENGINE)")
        logger.info(f"Target: {self.config.target_url}")
        logger.info(f"Max Pages: {self.config.max_pages} | Workers: {self.config.workers}")
        logger.info('=' * 60)
        
        try:
            await self._init_plugins()
            
            # Phase 1: Crawl
            logger.info("[PHASE 1] Crawling target...")
            pages = await self.crawler.crawl()
            logger.info(f"[PHASE 1] Complete — {len(pages)} pages discovered")
            
            if self._stop_event:
                logger.info("Scan stopped by user after crawl phase")
                return self.vulnerabilities
            
            # Phase 2: Test each page
            logger.info(f"[PHASE 2] Testing {len(pages)} pages with {len(self.plugins)} plugins...")
            
            # Use a semaphore to limit concurrent page scans if workers > 1
            sem = asyncio.Semaphore(self.config.workers)
            
            async def scan_page(page: str, index: int):
                async with sem:
                    if self._stop_event:
                        return
                    
                    logger.info(f"[{index+1}/{len(pages)}] Scanning: {page}")
                    try:
                        content = self.crawler.response_cache.get(page)
                        if not content:
                            client = await self.crawler._get_client()
                            resp = await client.get(page, timeout=self.config.timeout)
                            content = resp.text
                        
                        forms = self._extract_forms(content)
                        
                        # Run all plugins concurrently for this page
                        tasks = [plugin.check(page, content, forms) for plugin in self.plugins]
                        plugin_results = await asyncio.gather(*tasks, return_exceptions=True)
                        
                        for i, result in enumerate(plugin_results):
                            if isinstance(result, Exception):
                                logger.error(f"  Plugin {self.plugins[i].vuln_type.value} failed on {page}: {result}")
                            elif result:
                                logger.info(f"  ⚠ {self.plugins[i].vuln_type.value}: {len(result)} finding(s)")
                                self.vulnerabilities.extend(result)
                                
                    except Exception as e:
                        logger.error(f"  Failed to scan {page}: {e}")
                    finally:
                        self._pages_scanned += 1

            # Run page scans concurrently
            await asyncio.gather(*[scan_page(p, i) for i, p in enumerate(pages)])
            
            # Phase 3: Deduplicate
            self._deduplicate_vulnerabilities()
            
            # Summary
            duration = time.time() - start_time
            logger.info('=' * 60)
            logger.info(f"SCAN COMPLETE in {duration:.1f}s")
            logger.info(f"Pages scanned: {self._pages_scanned}")
            logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
            
            severity_counts = {}
            for v in self.vulnerabilities:
                level = v.severity_level.value if hasattr(v.severity_level, 'value') else str(v.severity_level)
                severity_counts[level] = severity_counts.get(level, 0) + 1
            for level, count in sorted(severity_counts.items()):
                logger.info(f"  {level}: {count}")
            logger.info('=' * 60)
            
        finally:
            await self.crawler.close()
        
        return self.vulnerabilities
