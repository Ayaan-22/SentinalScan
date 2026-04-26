import logging
import time
from typing import List, Optional, Set, Tuple
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from app.models.scan import ScanRequest, ScanStatus
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
    """Core scanning engine — crawl + test pipeline"""
    
    def __init__(self, config: ScanRequest):
        self.config = config
        self.crawler = WebCrawler(config)
        self.plugins: List[BaseCheck] = [
            ReflectedXSS(self.crawler.session),
            SQLInjection(self.crawler.session),
            SecurityHeaders(self.crawler.session),
            SensitiveFiles(self.crawler.session),
            CSRFCheck(self.crawler.session),
        ]
        self.vulnerabilities: List[Vulnerability] = []
        self._stop_event = False
        self._pages_scanned = 0

    def stop(self):
        self._stop_event = True

    @property
    def pages_scanned(self) -> int:
        return self._pages_scanned

    def _extract_forms(self, content: str) -> List[BeautifulSoup]:
        try:
            soup = BeautifulSoup(content, 'html.parser')
            return soup.find_all('form')
        except Exception:
            return []

    def _deduplicate_vulnerabilities(self) -> None:
        """Remove duplicate vulnerabilities based on (url, vuln_type, description) fingerprint."""
        seen: Set[Tuple[str, str, str]] = set()
        unique = []
        for vuln in self.vulnerabilities:
            # Create a fingerprint from the key fields
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

    def run(self) -> List[Vulnerability]:
        """Execute the full scan pipeline: crawl → test → deduplicate."""
        start_time = time.time()
        logger.info(f"{'='*60}")
        logger.info(f"VULNERABILITY SCAN STARTED")
        logger.info(f"Target: {self.config.target_url}")
        logger.info(f"Max Pages: {self.config.max_pages} | Workers: {self.config.workers}")
        logger.info(f"Plugins: {', '.join(p.vuln_type.value for p in self.plugins)}")
        logger.info(f"{'='*60}")
        
        try:
            # Phase 1: Crawl
            logger.info("[PHASE 1] Crawling target...")
            pages = self.crawler.crawl()
            logger.info(f"[PHASE 1] Complete — {len(pages)} pages discovered")
            
            if self._stop_event:
                logger.info("Scan stopped by user after crawl phase")
                return self.vulnerabilities
            
            # Phase 2: Test each page
            logger.info(f"[PHASE 2] Testing {len(pages)} pages with {len(self.plugins)} plugins...")
            
            for i, page in enumerate(pages):
                if self._stop_event:
                    logger.info("Scan stopped by user during testing phase")
                    break
                    
                logger.info(f"[{i+1}/{len(pages)}] Scanning: {page}")
                
                try:
                    # Use cached response from crawler if available
                    content = self.crawler.response_cache.get(page)
                    if not content:
                        resp = self.crawler.session.get(page, timeout=self.config.timeout)
                        content = resp.text
                    
                    forms = self._extract_forms(content)
                    
                    # Run all plugins on this page
                    for plugin in self.plugins:
                        if self._stop_event:
                            break
                        try:
                            vulns = plugin.check(page, content, forms)
                            if vulns:
                                logger.info(f"  ⚠ {plugin.vuln_type.value}: {len(vulns)} finding(s)")
                            self.vulnerabilities.extend(vulns)
                        except Exception as e:
                            logger.error(f"  Plugin {plugin.vuln_type.value} failed on {page}: {e}")
                            
                except Exception as e:
                    logger.error(f"  Failed to fetch {page} for testing: {e}")
                
                self._pages_scanned = i + 1
            
            # Phase 3: Deduplicate
            self._deduplicate_vulnerabilities()
            
            # Summary
            duration = time.time() - start_time
            logger.info(f"{'='*60}")
            logger.info(f"SCAN COMPLETE in {duration:.1f}s")
            logger.info(f"Pages scanned: {self._pages_scanned}")
            logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
            
            # Breakdown by severity
            severity_counts = {}
            for v in self.vulnerabilities:
                level = v.severity_level.value if hasattr(v.severity_level, 'value') else str(v.severity_level)
                severity_counts[level] = severity_counts.get(level, 0) + 1
            for level, count in sorted(severity_counts.items()):
                logger.info(f"  {level}: {count}")
            logger.info(f"{'='*60}")
            
        finally:
            # Always close the crawler session
            self.crawler.close()
        
        return self.vulnerabilities
