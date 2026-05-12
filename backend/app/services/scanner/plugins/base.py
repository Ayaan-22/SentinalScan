from abc import ABC, abstractmethod
from typing import List
from app.models.vulnerability import Vulnerability, VulnType
from bs4 import BeautifulSoup
import httpx
import logging
import time

logger = logging.getLogger(__name__)

class BaseCheck(ABC):
    """Base class for all vulnerability check plugins (Asynchronous)"""
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @property
    @abstractmethod
    def vuln_type(self) -> VulnType:
        pass

    @abstractmethod
    async def check(self, url: str, content: str, forms: List[BeautifulSoup]) -> List[Vulnerability]:
        """
        Perform the vulnerability check asynchronously.
        :param url: The URL being scanned
        :param content: The HTML content of the page
        :param forms: List of forms found on the page
        :return: List of discovered vulnerabilities
        """
        pass
    
    def _create_vuln(self, url: str, description: str, evidence: str, 
                     severity_score: float, severity_level: str, 
                     severity_icon: str, remediation: str, confidence: str = "High") -> Vulnerability:
        return Vulnerability(
            url=url,
            vuln_type=self.vuln_type,
            description=description,
            severity_level=severity_level,  # type: ignore
            severity_score=severity_score,
            severity_icon=severity_icon,
            evidence=evidence,
            remediation=remediation,
            confidence=confidence,
            timestamp=time.time()
        )
