"""Offline inventory from an authorized browser HAR; no active browser control."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def inventory_har(path: Path, page_origin: str) -> dict[str, object]:
    """Extract script request evidence without retaining cookies, bodies or queries.

    HAR is an untrusted observation, not proof of execution or integrity.
    A single-page export is required to prevent mixing unrelated tabs.
    """
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("HAR exceeds 25 MiB limit")
    origin = urlsplit(page_origin)
    if origin.scheme not in ("http", "https") or not origin.hostname or origin.username:
        raise ValueError("Expected an HTTP(S) page origin without credentials")
    canonical = f"{origin.scheme}://{origin.netloc}"
    raw = json.loads(path.read_text(encoding="utf-8"))
    log = raw["log"]
    pages = log.get("pages", [])
    if len(pages) != 1 or not isinstance(pages[0].get("id"), str):
        raise ValueError("Export exactly one authorized browser page")
    page_id = pages[0]["id"]
    records: list[dict[str, object]] = []
    for entry in log["entries"]:
        if entry.get("pageref") != page_id:
            raise ValueError("HAR includes unrelated or unattributed requests")
        response = entry.get("response", {})
        mime = response.get("content", {}).get("mimeType", "").split(";")[0].lower()
        if (
            mime
            not in (
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/ecmascript",
            )
            and entry.get("_resourceType") != "script"
        ):
            continue
        parsed = urlsplit(entry["request"]["url"])
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
            raise ValueError("Invalid script URL")
        records.append(
            {
                "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
                "status": response.get("status"),
                "third_party": f"{parsed.scheme}://{parsed.netloc}" != canonical,
            }
        )
    return {
        "schema": 1,
        "page_origin": canonical,
        "scripts": records,
        "evidence_kind": "user-supplied HAR; execution and integrity unverified",
        "privacy": "headers, cookies, queries and bodies excluded",
    }
