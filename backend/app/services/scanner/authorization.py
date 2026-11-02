"""Local durable authorization and request audit store (single-operator deployment)."""

import hashlib
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import settings
from app.models.policy import PolicyAuthorization, ScanMode, StoredPolicy, origin


def principal_for_key(key: str) -> str:
    return "api-key-sha256:" + hashlib.sha256(key.encode()).hexdigest()


class AuthorizationStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or settings.SCAN_POLICY_DB)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, document TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, policy_id TEXT NOT NULL,
            policy_version INTEGER NOT NULL, method TEXT NOT NULL, origin TEXT NOT NULL,
            path TEXT NOT NULL, authorized_at TEXT NOT NULL, outcome TEXT NOT NULL,
            status_code INTEGER)""")
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, authorization: PolicyAuthorization, principal: str) -> StoredPolicy:
        now = datetime.now(UTC)
        if not now < authorization.expires_at <= now + timedelta(days=7):
            raise ValueError("Authorization expiry must be in the next seven days")
        policy = StoredPolicy(
            **authorization.model_dump(), policy_id=str(uuid.uuid4()),
            authorized_by=principal, authorized_at=now,
        )
        with self._connect() as db:
            db.execute("INSERT INTO policies VALUES (?, ?)", (policy.policy_id, policy.model_dump_json()))
        return policy

    def get(self, policy_id: str) -> StoredPolicy:
        with self._connect() as db:
            row = db.execute("SELECT document FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if row is None:
            raise PermissionError("Stored authorization policy not found")
        return StoredPolicy.model_validate_json(row["document"])

    def require(self, policy_id: str | None, mode: ScanMode, method: str, url: str,
                principal: str | None = None) -> StoredPolicy:
        if mode == ScanMode.PASSIVE or not policy_id:
            raise PermissionError("Outbound requests require a stored active authorization policy")
        policy = self.get(policy_id)
        if principal is not None and policy.authorized_by != principal:
            raise PermissionError("Authorization belongs to a different API credential")
        policy.require_request(mode, method, url)
        return policy

    def record_request(self, scan_id: str, policy: StoredPolicy, method: str, url: str) -> str:
        request_id = str(uuid.uuid4())
        # Deliberately exclude query strings, bodies, headers, cookies and tokens.
        with self._connect() as db:
            db.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                request_id, scan_id, policy.policy_id, policy.version, method, origin(url),
                urlsplit(url).path, datetime.now(UTC).isoformat(), "authorized", None,
            ))
        return request_id

    def finish_request(self, request_id: str, outcome: str, status_code: int | None = None):
        with self._connect() as db:
            db.execute("UPDATE requests SET outcome = ?, status_code = ? WHERE id = ?",
                       (outcome, status_code, request_id))

    def requests_for_scan(self, scan_id: str) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM requests WHERE scan_id = ? ORDER BY authorized_at", (scan_id,),
            )]
