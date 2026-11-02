from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.models.policy import PolicyAuthorization
from app.models.scan import ScanRequest
from app.services.scanner.authorization import AuthorizationStore
from app.services.scanner.crawler import WebCrawler


@pytest.mark.asyncio
async def test_private_ip_target_is_blocked():
    crawler = WebCrawler(ScanRequest(target_url="http://127.0.0.1"))
    with pytest.raises(ValueError):
        await crawler.validate_target()


@pytest.mark.asyncio
async def test_rfc1918_target_requires_explicit_opt_in():
    crawler = WebCrawler(ScanRequest(target_url="http://192.168.1.99"))
    with pytest.raises(ValueError):
        await crawler.validate_target()

    allowed = WebCrawler(
        ScanRequest(target_url="http://192.168.1.99", allow_private_targets=True)
    )
    await allowed.validate_target()


@pytest.mark.asyncio
async def test_loopback_stays_blocked_even_with_private_opt_in():
    crawler = WebCrawler(
        ScanRequest(target_url="http://127.0.0.1", allow_private_targets=True)
    )
    with pytest.raises(ValueError):
        await crawler.validate_target()


@pytest.mark.asyncio
async def test_unresolvable_host_is_blocked():
    crawler = WebCrawler(ScanRequest(target_url="http://does-not-resolve.invalid"))
    with pytest.raises(ValueError):
        await crawler.validate_target()


@pytest.mark.asyncio
async def test_redirect_to_loopback_is_blocked(monkeypatch):
    crawler = active_crawler("http://example.com")
    monkeypatch.setattr(crawler, "_is_safe_ip", lambda hostname: _safe_ip(hostname))

    def handler(request):
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        await crawler.safe_get("http://example.com")
    await crawler.close()


@pytest.mark.asyncio
async def test_redirect_to_metadata_ip_is_blocked(monkeypatch):
    crawler = active_crawler("http://example.com")
    monkeypatch.setattr(crawler, "_is_safe_ip", lambda hostname: _safe_ip(hostname))

    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})

    crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        await crawler.safe_get("http://example.com")
    await crawler.close()


@pytest.mark.asyncio
async def test_url_canonicalization_fragment_static_same_origin_and_exclude(monkeypatch):
    crawler = active_crawler("https://Example.com:443/app/?b=2&a=1#frag", exclude_paths=["/admin"])
    monkeypatch.setattr(crawler, "_is_safe_ip", lambda hostname: _safe_ip(hostname))

    assert crawler.base_url == "https://example.com/app/?b=2&a=1"
    assert await crawler._is_valid_link(crawler.base_url, "/next#part") is True
    assert await crawler._is_valid_link(crawler.base_url, "https://evil.test/") is False
    assert await crawler._is_valid_link(crawler.base_url, "/assets/app.js") is False
    assert await crawler._is_valid_link(crawler.base_url, "/admin/panel") is False


def active_crawler(target, **kwargs):
    from app.models.policy import origin

    store = AuthorizationStore()
    policy = store.register(PolicyAuthorization(
        mode="safe-active", scope_origin=origin(target),
        allowed_endpoints=[{"path": path, "methods": ["GET"]} for path in ("/", "/app/", "/next")],
        expires_at=datetime.now(UTC) + timedelta(minutes=10), authorization_confirmed=True,
    ), "test")
    return WebCrawler(ScanRequest(target_url=target, mode="safe-active", policy_id=policy.policy_id, **kwargs), store=store)


async def _safe_ip(hostname):
    return hostname not in {"127.0.0.1", "169.254.169.254"}
