"""Set test-only configuration before importing the application."""

import os

import httpcore
import pytest

os.environ["SENTINAL_API_KEY"] = "ci_test_key_abcdefghijklmnop12345678"


@pytest.fixture(autouse=True)
def offline_and_isolated_policies(monkeypatch, tmp_path):
    """No test may reach a real target; MockTransport fixtures remain available."""
    from app.core.config import settings
    from app.services.scanner.manager import scan_manager

    async def deny_network(*args, **kwargs):
        raise AssertionError("Real outbound HTTP is forbidden in the offline suite")

    monkeypatch.setattr(httpcore.AsyncConnectionPool, "handle_async_request", deny_network)
    monkeypatch.setattr(settings, "SCAN_POLICY_DB", str(tmp_path / "authorization.sqlite3"))
    monkeypatch.setattr(scan_manager.authorization_store, "path", tmp_path / "authorization.sqlite3")
