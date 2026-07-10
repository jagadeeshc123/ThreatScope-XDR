import httpx
import asyncio
import os
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

class SafeHTTPClient:
    def __init__(self, timeout: int = 10, rate_limit_delay: float = 0.5):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.headers = {
            "User-Agent": "VulnScope-SafeScanner/1.0"
        }
        self.client = httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False)

    def _request_details(self, url: str) -> tuple[str, dict[str, str]]:
        parsed = urlsplit(url)
        replacement_host = os.getenv("LOCALHOST_SCAN_HOST")
        headers = dict(self.headers)
        if replacement_host and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            netloc = replacement_host
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            headers["Host"] = parsed.netloc
            return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)), headers
        return url, headers

    async def get(self, url: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
        try:
            await asyncio.sleep(self.rate_limit_delay)
            request_url, headers = self._request_details(url)
            response = await self.client.get(request_url, headers=headers)
            return response, None
        except httpx.RequestError as exc:
            return None, f"Request to {url} failed: {exc}"

    async def head(self, url: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
        try:
            await asyncio.sleep(self.rate_limit_delay)
            request_url, headers = self._request_details(url)
            response = await self.client.head(request_url, headers=headers)
            return response, None
        except httpx.RequestError as exc:
            return None, f"Request to {url} failed: {exc}"

    async def close(self):
        await self.client.aclose()
