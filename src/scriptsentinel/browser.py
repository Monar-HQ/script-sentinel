"""Bounded anonymous browser observation for explicitly authorized staging pages."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .network import NetworkPolicy


def public_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def observe(
    url: str,
    policy: NetworkPolicy,
    authorized: bool,
    wait_ms: int = 1000,
    executable: str | None = None,
) -> dict[str, Any]:
    if not authorized:
        raise ValueError("Browser observation requires --authorized for a page you own or may test")
    if not 0 <= wait_ms <= 10000:
        raise ValueError("Observation wait must be 0-10000 ms")
    policy.check(url)
    from playwright.sync_api import Route, sync_playwright

    events: list[dict[str, Any]] = []
    with (
        sync_playwright() as playwright,
        httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client,
    ):
        browser = playwright.chromium.launch(headless=True, executable_path=executable)
        try:
            context = browser.new_context(service_workers="block", accept_downloads=False)
            context.route_web_socket("**/*", lambda ws: ws.close())

            def intercept(route: Route) -> None:
                request = route.request
                event: dict[str, Any] = {
                    "url": public_url(request.url),
                    "type": request.resource_type,
                    "method": request.method,
                    "blocked": True,
                }
                if len(events) >= 200:
                    route.abort()
                    return
                events.append(event)
                try:
                    if request.method not in ("GET", "HEAD"):
                        raise ValueError("Observation blocks state-changing requests")
                    policy.check(request.url)
                    with client.stream(request.method, request.url) as response:
                        if response.is_redirect:
                            raise ValueError("Use a canonical URL; observation blocks redirects")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            body.extend(chunk)
                            if len(body) > policy.max_bytes:
                                raise ValueError("Response size exceeded")
                        headers = {
                            key: value
                            for key, value in response.headers.items()
                            if key.lower()
                            not in (
                                "content-encoding",
                                "content-length",
                                "transfer-encoding",
                                "set-cookie",
                                "connection",
                            )
                        }
                        route.fulfill(
                            status=response.status_code, headers=headers, body=bytes(body)
                        )
                        event.update(blocked=False, status=response.status_code, bytes=len(body))
                except (ValueError, OSError, httpx.HTTPError) as exc:
                    event["reason"] = type(exc).__name__
                    route.abort()

            context.route("**/*", intercept)
            page = context.new_page()
            page.set_default_timeout(10000)
            page.add_init_script(
                "window.__ssViolations=[]; addEventListener('securitypolicyviolation',e=>window.__ssViolations.push({directive:e.effectiveDirective,disposition:e.disposition}));"
            )
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(wait_ms)
            scripts = page.locator("script").evaluate_all(
                "nodes=>nodes.map(n=>({url:n.src||null,integrity:n.integrity||null,inline:!n.src,characters:n.src?0:n.textContent.length}))"
            )
            for script in scripts:
                if script["url"]:
                    script["url"] = public_url(script["url"])
            violations = page.evaluate("window.__ssViolations || []")
            return {
                "schema": 1,
                "target": public_url(url),
                "scripts": scripts,
                "requests": events,
                "csp_violations": violations,
                "scope": sorted(policy.origins),
                "mode": "anonymous read-only requests; no login, forms, redirects or service workers",
                "limitations": "A browser context is not a network sandbox. Use an isolated VM/container with egress controls for untrusted pages.",
            }
        finally:
            browser.close()
