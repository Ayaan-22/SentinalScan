"""P0 regressions: real plugin wiring, mocked DNS and HTTP only."""

import asyncio
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.models.policy import PolicyAuthorization
from app.models.scan import ScanRequest
from app.services.scanner.authorization import AuthorizationStore
from app.services.scanner.engine import ScannerEngine
from app.services.scanner.transport import ActiveRequests


def grant(store, *, mode="custom-active", endpoints=None):
    return store.register(PolicyAuthorization(
        mode=mode, scope_origin="https://example.test",
        allowed_endpoints=endpoints or [
            {"path": "/", "methods": ["GET"]},
            {"path": "/search", "methods": ["GET", "POST"]},
        ], expires_at=datetime.now(UTC) + timedelta(hours=1), authorization_confirmed=True,
    ), "fixture-principal")


def engine_for(store, policy, **kwargs):
    return ScannerEngine(ScanRequest(
        target_url="https://example.test/", mode=policy.mode,
        policy_id=policy.policy_id, obey_robots=False, workers=1,
        auth_token="fixture-bearer", cookies={"session": "fixture-cookie"}, **kwargs,
    ), store=store)


def mocked_client(monkeypatch, handler):
    factory = httpx.AsyncClient

    def create(**kwargs):
        return factory(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", create)


def mock_dns(monkeypatch, addresses):
    async def resolve(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in addresses()]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)


@pytest.mark.asyncio
async def test_all_engine_plugins_share_boundary_and_credentials_stay_in_scope(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store, endpoints=[
        {"path": path, "methods": ["GET", "POST"]}
        for path in ("/", "/search", "/blocked", "/.env", "/.git/HEAD")
    ])
    actions = [
        "https://127.0.0.1/search", "https://169.254.169.254/search",
        "https://elsewhere.test/search", "http://example.test/search",
        "https://example.test:444/search", "/blocked", "/not-approved",
    ]
    html = "".join(
        f'<form method="{method}" action="{action}"><input name="q" value="original"></form>'
        for method in ("get", "post") for action in actions + ["/search"]
    )
    sends = []

    def handler(request):
        sends.append(request)
        if request.url.path == "/":
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        if request.url.path == "/.env":
            return httpx.Response(200, text="FIXTURE_KEY=not-a-secret", headers={"content-type": "text/plain"})
        # Neither GET nor POST plugin requests may follow this redirect.
        return httpx.Response(307, headers={"location": "https://elsewhere.test/search"})

    mocked_client(monkeypatch, handler)
    mock_dns(monkeypatch, lambda: ["93.184.216.34"])
    engine = engine_for(store, policy, exclude_paths=["/blocked", "/.git"])
    findings = await engine.run()

    assert all(isinstance(plugin.client, ActiveRequests) for plugin in engine.plugins)
    assert {request.url.path for request in sends} == {"/", "/search", "/.env"}
    assert {request.method for request in sends if request.url.path == "/search"} == {"GET", "POST"}
    assert all(str(request.url).startswith("https://example.test/") for request in sends)
    assert all(request.headers["authorization"] == "Bearer fixture-bearer" for request in sends)
    assert all("session=fixture-cookie" in request.headers["cookie"] for request in sends)
    assert any(finding.url == "https://example.test/.env" for finding in findings)
    assert len(store.requests_for_scan("standalone")) == len(sends)


@pytest.mark.asyncio
async def test_plugin_rechecks_dns_after_an_approved_request(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store, endpoints=[
        {"path": path, "methods": ["GET"]} for path in ("/", "/.env")
    ])
    addresses = ["93.184.216.34"]
    mock_dns(monkeypatch, lambda: addresses)
    sends = []

    def handler(request):
        sends.append(request)
        return httpx.Response(200, text="ok")

    mocked_client(monkeypatch, handler)
    engine = engine_for(store, policy)
    try:
        await engine._init_plugins()
        await engine.crawler.safe_get("https://example.test/")
        addresses[:] = ["127.0.0.1"]
        sensitive = next(plugin for plugin in engine.plugins if plugin.__class__.__name__ == "SensitiveFiles")
        assert await sensitive.check("https://example.test/", "", []) == []
        assert len(sends) == 1
    finally:
        await engine.crawler.close()


@pytest.mark.asyncio
async def test_safe_active_does_not_submit_post_or_unapproved_stateful_get(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store, mode="safe-active", endpoints=[{"path": "/", "methods": ["GET"]}])
    state = {"mutations": 0}
    html = """
    <a href='/mutate-by-get'>mutate</a>
    <form method='post' action='/'><input name='q' value='original'></form>
    <form action='/mutate-by-get'><input name='q'></form>
    <form action='/?action=delete'><input name='q'></form>
    """
    sends = []

    def handler(request):
        sends.append(request)
        if request.method != "GET" or request.url.path != "/" or request.url.query:
            state["mutations"] += 1
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    mocked_client(monkeypatch, handler)
    mock_dns(monkeypatch, lambda: ["93.184.216.34"])
    await engine_for(store, policy).run()
    assert sends
    assert state == {"mutations": 0}
    assert all(request.method == "GET" and str(request.url) == "https://example.test/" for request in sends)


@pytest.mark.asyncio
async def test_facade_alternate_methods_still_require_policy(tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    engine = engine_for(store, policy)
    await engine._init_plugins()
    for method in ("PUT", "PATCH", "DELETE", "OPTIONS"):
        with pytest.raises(PermissionError, match="not authorized"):
            await engine.plugins[0].client.request(method, "https://example.test/search")
    assert engine.crawler.client is None


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [{"follow_redirects": True}, {"auth": httpx.DigestAuth("fixture", "fixture")}])
async def test_plugins_cannot_enable_unvalidated_httpx_sends(monkeypatch, tmp_path, options):
    mock_dns(monkeypatch, lambda: ["93.184.216.34"])
    store = AuthorizationStore(tmp_path / "policy.db")
    engine = engine_for(store, grant(store))
    await engine._init_plugins()
    with pytest.raises(PermissionError):
        await engine.plugins[0].client.get("https://example.test/", **options)
    assert engine.crawler.client is None


@pytest.mark.asyncio
async def test_stopped_plugin_request_makes_no_send(tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    engine = engine_for(store, grant(store))
    await engine._init_plugins()
    engine.stop()
    with pytest.raises(asyncio.CancelledError):
        await engine.plugins[0].client.post("https://example.test/search", data={"q": "fixture"})
    assert engine.crawler.client is None
