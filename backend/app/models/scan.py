from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .policy import ScanMode, StoredPolicy, canonical_url, origin
from .vulnerability import Vulnerability


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

class CapturedPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    content: str = Field(max_length=2_000_000)
    headers: dict[str, str] | None = None

    _url = field_validator("url")(canonical_url)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_url: str = Field(..., description="Target scope for capture analysis or authorized active requests")
    mode: ScanMode = Field(ScanMode.PASSIVE, description="Passive analyzes supplied captures without any target requests")
    policy_id: str | None = Field(None, description="Server-recorded active authorization ID; required for either active mode")
    captured_pages: list[CapturedPage] = Field(default_factory=list, max_length=50)
    max_pages: int = Field(50, ge=1, le=500, description="Maximum pages to crawl")
    workers: int = Field(5, ge=1, le=20, description="Concurrent workers")
    verify_ssl: bool = True
    obey_robots: bool = True
    allow_private_targets: bool = False
    timeout: int = Field(15, ge=1, le=60)
    
    # Optional advanced config
    auth_token: str | None = None
    cookies: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    exclude_paths: list[str] = Field(default_factory=list)

    @field_validator("target_url")
    def validate_url(cls, v: str) -> str:
        return canonical_url(v)

    @model_validator(mode="after")
    def validate_policy_selection(self):
        if self.mode == ScanMode.PASSIVE and self.policy_id:
            raise ValueError("Passive scans do not use an active authorization")
        if self.mode != ScanMode.PASSIVE and not self.policy_id:
            raise ValueError("Active scans require a stored policy_id")
        if self.mode != ScanMode.PASSIVE and self.captured_pages:
            raise ValueError("Captured pages are accepted only in passive mode")
        for page in self.captured_pages:
            if origin(page.url) != origin(self.target_url) or any(
                urlsplit(page.url).path.startswith(path) for path in self.exclude_paths
            ):
                raise ValueError("Captured page outside selected scope")
        return self

class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    start_time: datetime
    mode: ScanMode = ScanMode.PASSIVE
    policy: StoredPolicy | None = None
    policy_description: str = "Passive: captured traffic only; no target requests or form submissions."
    end_time: datetime | None = None
    pages_scanned: int = 0
    vulnerabilities_count: int = 0
    results: list[Vulnerability] = Field(default_factory=list)
    recent_logs: list[dict[str, Any]] = Field(default_factory=list)
