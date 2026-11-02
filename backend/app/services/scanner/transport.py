"""Plugin capabilities: cached responses for passive checks, guarded sends for active checks."""

from typing import Protocol

import httpx


class ScanHttpClient(Protocol):
    """The request capabilities used by checks; no raw HTTPX session access."""

    async def get(self, url: str, **kwargs) -> httpx.Response: ...

    async def post(self, url: str, **kwargs) -> httpx.Response: ...


class CapturedResponses:
    def __init__(self, pages):
        self.responses = {
            page.url: httpx.Response(200, text=page.content, headers=page.headers or {},
                                     request=httpx.Request("GET", page.url))
            for page in pages if page.headers is not None
        }

    async def get(self, url: str, **kwargs):
        if url not in self.responses:
            raise PermissionError("No response headers captured; no passive fetch permitted")
        return self.responses[url]

    async def post(self, url: str, **kwargs):
        raise PermissionError("Passive analysis cannot submit requests")


class ActiveRequests:
    """Plugins receive this facade, never the underlying HTTPX client."""

    def __init__(self, crawler):
        self._crawler = crawler

    async def request(self, method: str, url: str, **kwargs):
        return await self._crawler.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)
