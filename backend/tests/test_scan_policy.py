"""Offline acceptance fixtures for SS-02; assert actual transport sends and handler state."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models.policy import PolicyAuthorization, ScanMode
from app.models.scan import ScanRequest
from app.services.scanner.authorization import AuthorizationStore, principal_for_key
from app.services.scanner.crawler import WebCrawler
from app.services.scanner.engine import ScannerEngine

KEY = "ci_test_key_abcdefghijklmnop12345678"
HEADERS = {"X-API-Key": KEY}
HTML = """<a href='/logout'>logout</a><a href='/checkout'>checkout</a>
<a href='/mutate-by-get'>stateful GET</a>
<form method='post' action='/checkout'><input name='item' value='real-item'></form>
<form action='/mutate-by-get'><input name='value' value='real-value'></form>
<form method='post' action='/search?keep=a%2Fb&amp;keep=two'>
 <input name='q' value='existing-query'>
 <input type='hidden' name='_csrf' value='csrf-real+/='>
 <input name='requestVerificationToken' value='visible-token-real'>
 <input type='hidden' name='record_id' value='record-42'>
 <input name='tag' type='hidden' value='first'><input name='tag' type='hidden' value='second'>
 <input type='checkbox' name='enabled' checked value='yes'>
 <input type='checkbox' name='disabled_option' value='no'>
 <input name='ignored' disabled value='omit'>
 <select name='region'><option value='PK' selected>Pakistan</option></select>
 <textarea name='notes'>actual notes</textarea>
</form>
<form method='post' action='https://elsewhere.test/search'><input name='q' value='real'></form>
"""


def grant(store, *, mode="custom-active", endpoints=None, excluded_paths=()):
    return store.register(PolicyAuthorization(
        mode=mode, scope_origin="https://example.test",
        allowed_endpoints=endpoints or [
            {"path": "/", "methods": ["GET"]},
            {"path": "/search", "methods": ["GET", "POST"]},
        ], excluded_paths=excluded_paths,
        expires_at=datetime.now(UTC) + timedelta(hours=1), authorization_confirmed=True,
    ), principal_for_key(KEY))


async def yes(hostname):
    return True


@pytest.mark.asyncio
@pytest.mark.parametrize("explicit_mode", [False, True])
async def test_real_engine_passive_never_touches_state_changing_handlers(monkeypatch, explicit_mode):
    state = {"purchases": 0, "mutations": 0, "requests": 0}

    def handler(request):
        state["requests"] += 1
        if request.url.path == "/checkout":
            state["purchases"] += 1
        if request.url.path == "/mutate-by-get":
            state["mutations"] += 1
        return httpx.Response(200, text=HTML, headers={"content-type": "text/html"})

    config = ScanRequest(
        target_url="https://example.test/", **({"mode": "passive"} if explicit_mode else {}),
        captured_pages=[{"url": "https://example.test/", "content": HTML, "headers": {}}],
    )
    engine = ScannerEngine(config)
    engine.crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def no_dns(*args):
        pytest.fail("Passive analysis must not resolve target DNS")

    monkeypatch.setattr(engine.crawler, "_is_safe_ip", no_dns)
    results = await engine.run()
    assert engine.pages_scanned == 1
    assert results  # Captured headers/forms are actually analyzed.
    assert state == {"purchases": 0, "mutations": 0, "requests": 0}


@pytest.mark.asyncio
async def test_passive_transport_denies_even_direct_or_alternate_methods():
    crawler = WebCrawler(ScanRequest(target_url="https://example.test"))
    for method in ("GET", "HEAD", "POST", "DELETE", "PATCH"):
        with pytest.raises(PermissionError):
            await crawler.request(method, "https://example.test/search")
    assert crawler.client is None


@pytest.mark.asyncio
async def test_active_real_engine_uses_exact_policy_and_preserves_values(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    sends = []

    def handler(request):
        sends.append(request)
        return httpx.Response(200, text=HTML if request.url.path == "/" else "ok",
                              headers={"content-type": "text/html"})

    config = ScanRequest(target_url="https://example.test/", mode="custom-active",
                         policy_id=policy.policy_id, obey_robots=False, workers=1,
                         auth_token="fixture-secret", cookies={"session": "fixture-cookie"})
    engine = ScannerEngine(config, store=store, scan_id="fixture-scan")
    monkeypatch.setattr(engine.crawler, "_is_safe_ip", yes)
    client_factory = httpx.AsyncClient

    def fixture_client(**kwargs):
        return client_factory(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fixture_client)
    await engine.run()
    assert sends
    assert all(request.url.host == "example.test" and request.url.path in {"/", "/search"} for request in sends)
    assert all(request.headers["authorization"] == "Bearer fixture-secret" for request in sends)
    probes = [request for request in sends if request.method == "POST"]
    assert probes
    for request in probes:
        values = parse_qsl(request.content.decode(), keep_blank_values=True)
        assert ("_csrf", "csrf-real+/=") in values
        assert ("requestVerificationToken", "visible-token-real") in values
        assert ("record_id", "record-42") in values
        assert [(k, v) for k, v in values if k == "tag"] == [("tag", "first"), ("tag", "second")]
        assert ("enabled", "yes") in values
        assert ("region", "PK") in values
        assert not any(k in {"ignored", "disabled_option"} for k, _ in values)
        assert sum(pair not in [("q", "existing-query"), ("notes", "actual notes")]
                   for pair in values if pair[0] in {"q", "notes"}) == 1
        assert request.url.query == b"keep=a%2Fb&keep=two"
    audit = AuthorizationStore(store.path).requests_for_scan("fixture-scan")
    assert len(audit) == len(sends)
    assert all(row["policy_id"] == policy.policy_id and row["policy_version"] == 1
               and row["outcome"] == "responded" for row in audit)
    assert "csrf-real" not in str(audit)
    assert "keep=" not in str(audit)
    assert "fixture-secret" not in str(audit) and "fixture-cookie" not in str(audit)


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["Host", "X-HTTP-Method-Override"])
async def test_routing_and_method_overrides_are_denied_before_send(tmp_path, header):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id, headers={header: "override"}), store=store)
    with pytest.raises(PermissionError, match="overrides"):
        await crawler.request("GET", "https://example.test/")
    assert crawler.client is None


@pytest.mark.asyncio
async def test_audit_failure_prevents_send(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id), store=store)
    monkeypatch.setattr(crawler, "_is_safe_ip", yes)

    def no_send(request):
        pytest.fail("Request must not be sent if audit cannot be committed")

    def unavailable(*args):
        raise OSError("Fixture audit store unavailable")

    crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(no_send))
    monkeypatch.setattr(store, "record_request", unavailable)
    with pytest.raises(OSError, match="unavailable"):
        await crawler.request("GET", "https://example.test/")
    await crawler.close()


@pytest.mark.asyncio
async def test_expiry_during_audit_commit_blocks_send(monkeypatch, tmp_path):
    import app.models.policy as policy_module

    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id), store=store)
    monkeypatch.setattr(crawler, "_is_safe_ip", yes)
    after_commit = False

    class FixtureClock:
        @classmethod
        def now(cls, tz):
            return policy.expires_at + timedelta(seconds=1) if after_commit else datetime.now(tz)

    record_request = store.record_request

    def commit_then_expire(*args):
        nonlocal after_commit
        request_id = record_request(*args)
        after_commit = True
        return request_id

    def no_send(request):
        pytest.fail("Expired authorization must not be sent after audit commit")

    crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(no_send))
    monkeypatch.setattr(policy_module, "datetime", FixtureClock)
    monkeypatch.setattr(store, "record_request", commit_then_expire)
    with pytest.raises(PermissionError, match="expired"):
        await crawler.request("GET", "https://example.test/")
    assert store.requests_for_scan("standalone")[0]["outcome"] == "blocked"
    await crawler.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("method,url", [
    ("POST", "https://example.test/"),
    ("DELETE", "https://example.test/search"),
    ("GET", "https://example.test/not-approved"),
    ("GET", "https://elsewhere.test/search"),
    ("GET", "http://example.test/search"),
    ("GET", "https://example.test:444/search"),
    ("GET", "https://example.test/search?action=delete"),
    ("GET", "https://example.test/%73earch"),
    ("GET", "https://example.test/search/"),
])
async def test_active_mismatches_produce_zero_sends(monkeypatch, tmp_path, method, url):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id), store=store)
    monkeypatch.setattr(crawler, "_is_safe_ip", yes)
    with pytest.raises(PermissionError):
        await crawler.request(method, url)
    assert crawler.client is None
    assert store.requests_for_scan("standalone") == []


@pytest.mark.asyncio
async def test_policy_expiry_rechecked_after_dns_and_exclusion_denied(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store, excluded_paths=("/search",))
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id), store=store)
    with pytest.raises(PermissionError, match="excluded"):
        await crawler.request("POST", "https://example.test/search")

    expired = policy.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})

    async def expire_during_dns(hostname):
        with store._connect() as db:
            db.execute("UPDATE policies SET document = ? WHERE id = ?", (expired.model_dump_json(), policy.policy_id))
        return True

    monkeypatch.setattr(crawler, "_is_safe_ip", expire_during_dns)
    with pytest.raises(PermissionError, match="expired"):
        await crawler.request("GET", "https://example.test/")
    assert store.requests_for_scan("standalone") == []
    await crawler.close()


@pytest.mark.asyncio
async def test_redirect_is_checked_again_before_send(monkeypatch, tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    policy = grant(store)
    crawler = WebCrawler(ScanRequest(target_url="https://example.test/", mode="custom-active",
                                     policy_id=policy.policy_id), store=store)
    monkeypatch.setattr(crawler, "_is_safe_ip", yes)
    sent = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(302, headers={"location": "/checkout"})

    crawler.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(PermissionError):
        await crawler.safe_get("https://example.test/")
    assert sent == ["https://example.test/"]
    await crawler.close()


def test_api_default_policy_and_authorization_contract():
    with TestClient(app) as client:
        response = client.post("/api/v1/scan/", headers=HEADERS, json={"target_url": "https://example.test/"})
        assert response.status_code == 200
        assert response.json()["mode"] == "passive"
        assert response.json()["policy"] is None
        assert "0 supplied captures" in response.json()["policy_description"]
        for mode in ("safe-active", "custom-active"):
            missing = client.post("/api/v1/scan/", headers=HEADERS, json={
                "target_url": "https://example.test/", "mode": mode,
            })
            assert missing.status_code == 422
            unknown = client.post("/api/v1/scan/", headers=HEADERS, json={
                "target_url": "https://example.test/", "mode": mode, "policy_id": "invented",
            })
            assert unknown.status_code == 403


def test_api_stores_identity_scope_version_and_rejects_mismatching_authorization(monkeypatch):
    import app.api.v1.endpoints.scan as routes

    # Prevent active background tasks here; real-engine behavior is exercised above.
    async def no_run(*args):
        return None

    monkeypatch.setattr(routes.scan_manager, "_run_scan", no_run)
    with TestClient(app) as client:
        document = {
            "mode": "safe-active", "scope_origin": "https://example.test",
            "allowed_endpoints": [{"path": "/", "methods": ["GET"]}],
            "excluded_paths": ["/internal"],
            "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            "authorization_confirmed": True,
        }
        assert client.post("/api/v1/scan/policies", json=document).status_code == 401
        stored = client.post("/api/v1/scan/policies", headers=HEADERS, json=document)
        assert stored.status_code == 200
        policy = stored.json()
        assert policy["authorized_by"] == principal_for_key(KEY)
        assert policy["version"] == 1 and policy["authorized_at"]
        assert client.get(f"/api/v1/scan/policies/{policy['policy_id']}", headers=HEADERS).json() == policy
        for target, mode in [("https://other.test/", "safe-active"),
                             ("https://example.test/", "custom-active")]:
            response = client.post("/api/v1/scan/", headers=HEADERS, json={
                "target_url": target, "mode": mode, "policy_id": policy["policy_id"],
            })
            assert response.status_code == 403
        response = client.post("/api/v1/scan/", headers=HEADERS, json={
            "target_url": "https://example.test/", "mode": "safe-active", "policy_id": policy["policy_id"],
        })
        assert response.status_code == 200
        assert response.json()["policy"] == policy


@pytest.mark.parametrize("path", ["/checkout", "/logout", "/payment", "/delete", "/account/recovery"])
def test_sensitive_workflows_cannot_be_authorized(tmp_path, path):
    with pytest.raises(ValidationError, match="Sensitive"):
        grant(AuthorizationStore(tmp_path / "policy.db"), endpoints=[{"path": path, "methods": ["GET", "POST"]}])


def test_safe_active_post_expired_unconfirmed_and_wrong_principal_rejected(tmp_path):
    store = AuthorizationStore(tmp_path / "policy.db")
    with pytest.raises(ValidationError, match="GET and HEAD"):
        grant(store, mode="safe-active")
    policy = grant(store)
    with pytest.raises(PermissionError, match="different API credential"):
        store.require(policy.policy_id, ScanMode.CUSTOM_ACTIVE, "GET", "https://example.test/", "someone-else")
    for changes in ({"expires_at": datetime.now(UTC) - timedelta(seconds=1)},
                    {"expires_at": datetime.now(UTC) + timedelta(days=8)}):
        with pytest.raises(ValueError):
            store.register(PolicyAuthorization(**{**policy.model_dump(include=PolicyAuthorization.model_fields.keys()), **changes}), principal_for_key(KEY))
    with pytest.raises(ValidationError):
        PolicyAuthorization(**{**policy.model_dump(include=PolicyAuthorization.model_fields.keys()), "authorization_confirmed": False})
