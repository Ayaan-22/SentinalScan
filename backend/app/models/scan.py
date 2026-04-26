from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict
from enum import Enum
from datetime import datetime
from .vulnerability import Vulnerability

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    max_pages: int = Field(50, ge=1, le=500, description="Maximum pages to crawl")
    workers: int = Field(5, ge=1, le=20, description="Concurrent workers")
    verify_ssl: bool = True
    obey_robots: bool = True
    timeout: int = Field(15, ge=1, le=60)
    
    # Optional advanced config
    auth_token: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    exclude_paths: Optional[List[str]] = None

    @field_validator("target_url")
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")

class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    pages_scanned: int = 0
    vulnerabilities_count: int = 0
    results: List[Vulnerability] = []
