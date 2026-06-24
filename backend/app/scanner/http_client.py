import httpx
import time
import asyncio
from typing import Optional, Tuple

class SafeHTTPClient:
    def __init__(self, timeout: int = 10, rate_limit_delay: float = 0.5):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.headers = {
            "User-Agent": "VulnScope-SafeScanner/1.0"
        }
        self.client = httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False)

    async def get(self, url: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
        try:
            await asyncio.sleep(self.rate_limit_delay)
            response = await self.client.get(url, headers=self.headers)
            return response, None
        except httpx.RequestError as exc:
            return None, f"Request error: {exc}"

    async def head(self, url: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
        try:
            await asyncio.sleep(self.rate_limit_delay)
            response = await self.client.head(url, headers=self.headers)
            return response, None
        except httpx.RequestError as exc:
            return None, f"Request error: {exc}"

    async def close(self):
        await self.client.aclose()
