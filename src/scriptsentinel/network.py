"""Explicit destination scope for active HTTP and browser observation."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx


def origin(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Scope requires HTTP(S) URLs without credentials")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{host}:{port}"


@dataclass(frozen=True)
class NetworkPolicy:
    origins: frozenset[str]
    allow_private: bool = False
    max_bytes: int = 5_000_000

    @classmethod
    def create(cls, urls: list[str], allow_private: bool = False) -> NetworkPolicy:
        return cls(frozenset(origin(url) for url in urls), allow_private)

    def check(self, url: str, resolve: bool = True) -> None:
        if origin(url) not in self.origins:
            raise ValueError("Destination outside authorized origin scope")
        host = urlsplit(url).hostname or ""
        if not resolve:
            return
        addresses = {row[4][0] for row in socket.getaddrinfo(host, None)}
        if not addresses:
            raise ValueError("Destination did not resolve")
        if not self.allow_private and any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise ValueError("Private/local destinations require --allow-private")


class ScopedClient:
    """Small async HTTP adapter; every redirect is reauthorized before fetching."""

    def __init__(self, client: httpx.AsyncClient, policy: NetworkPolicy):
        self.client, self.policy = client, policy

    async def get(self, url: str) -> httpx.Response:
        for _ in range(6):
            self.policy.check(url)
            async with self.client.stream("GET", url, follow_redirects=False) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("Redirect missing destination")
                    url = str(response.url.join(location))
                    continue
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.policy.max_bytes:
                        raise ValueError("Response exceeds configured resource limit")
                headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower()
                    not in ("content-encoding", "content-length", "transfer-encoding")
                }
                return httpx.Response(
                    response.status_code,
                    headers=headers,
                    content=bytes(body),
                    request=response.request,
                )
        raise ValueError("Redirect limit exceeded")
