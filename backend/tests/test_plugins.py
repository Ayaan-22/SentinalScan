import httpx
import pytest

from app.services.scanner.plugins.headers import SecurityHeaders
from app.services.scanner.plugins.sensitive_files import SensitiveFiles


@pytest.mark.asyncio
async def test_sensitive_file_true_positive_root_origin_only():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        if str(request.url) == "https://example.com/.env":
            return httpx.Response(200, text="API_KEY=abc\nSECRET=value", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    plugin = SensitiveFiles(client)

    findings = await plugin.check("https://example.com/about", "", [])
    second = await plugin.check("https://example.com/contact", "", [])

    assert any(f.url == "https://example.com/.env" for f in findings)
    assert second == []
    assert "https://example.com/about/.env" not in requested
    await client.aclose()


@pytest.mark.asyncio
async def test_sensitive_file_false_positive_custom_404_and_spa():
    def handler(request):
        if str(request.url).endswith("/.env"):
            return httpx.Response(200, text="<html><div id=\"root\"></div></html>", headers={"content-type": "text/html"})
        return httpx.Response(200, text='{"error":"not found"}', headers={"content-type": "application/json"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    plugin = SensitiveFiles(client)

    findings = await plugin.check("https://example.com/page", "", [])
    assert findings == []
    await client.aclose()


@pytest.mark.asyncio
async def test_security_headers_validate_weak_values_and_skip_hsts_on_http():
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "X-Content-Type-Options": "sniff",
                "X-Frame-Options": "ALLOWALL",
                "Content-Security-Policy": "default-src * 'unsafe-inline'",
                "Referrer-Policy": "unsafe-url",
                "Permissions-Policy": "camera=()",
            },
            text="<html></html>",
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    plugin = SecurityHeaders(client)

    findings = await plugin.check("http://example.com", "", [])
    descriptions = {finding.description for finding in findings}

    assert "Misconfigured security header: X-Content-Type-Options" in descriptions
    assert "Misconfigured security header: X-Frame-Options" in descriptions
    assert "Weak Content-Security-Policy header" in descriptions
    assert "Weak Referrer-Policy header" in descriptions
    assert not any("Strict-Transport-Security" in item for item in descriptions)
    await client.aclose()
