"""Optional real Chromium tests. No third-party sites or offensive fixtures."""

import os
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scriptsentinel.browser import observe
from scriptsentinel.dashboard import make_server
from scriptsentinel.network import NetworkPolicy

pytestmark = pytest.mark.skipif(
    not os.environ.get("SCRIPTSENTINEL_BROWSER_EXECUTABLE"),
    reason="Set SCRIPTSENTINEL_BROWSER_EXECUTABLE to run real Chromium checks",
)


def test_console_desktop_mobile_and_navigation(tmp_path):
    from playwright.sync_api import sync_playwright

    (tmp_path / "index.html").write_text('<script src="app.js"></script>', encoding="utf-8")
    (tmp_path / "app.js").write_text('console.log("synthetic");', encoding="utf-8")
    server, token = make_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ["SCRIPTSENTINEL_BROWSER_EXECUTABLE"]
            )
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/#token={token}")
            page.get_by_role("button", name="Try the synthetic demo").click()
            page.locator("#report").wait_for(state="visible")
            assert page.locator("#script-count").inner_text() == "1"
            page.get_by_role("button", name="Script inventory", exact=True).click()
            assert page.locator("#scripts tr").count() == 1
            assert "MISSING_SRI" in page.locator("#scripts").inner_text()
            assert "external" in page.locator("#scripts").inner_text()
            page.get_by_role("button", name="Research library", exact=True).click()
            page.get_by_text("OPTIMJACK", exact=True).wait_for()
            page.get_by_role("button", name="Activity ledger", exact=True).click()
            page.get_by_text("demo-audit", exact=True).wait_for()
            page.get_by_role("button", name="Overview", exact=False).click()
            if os.environ.get("SCRIPTSENTINEL_CAPTURE"):
                path = Path(os.environ["SCRIPTSENTINEL_CAPTURE"])
                path.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(path), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.emulate_media(reduced_motion="reduce")
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


def test_authorized_observation_captures_dynamic_script_and_blocks_posts(tmp_path):
    (tmp_path / "index.html").write_text('<script src="app.js"></script>', encoding="utf-8")
    (tmp_path / "app.js").write_text(
        "const s=document.createElement('script'); s.src='dynamic.js'; document.head.appendChild(s); fetch('/should-not-send',{method:'POST',body:'synthetic'}).catch(()=>{});",
        encoding="utf-8",
    )
    (tmp_path / "dynamic.js").write_text("window.syntheticLoaded=true;", encoding="utf-8")

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(tmp_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/index.html"
    try:
        result = observe(
            url,
            NetworkPolicy.create([url], allow_private=True),
            True,
            500,
            os.environ["SCRIPTSENTINEL_BROWSER_EXECUTABLE"],
        )
        assert any(item["url"].endswith("dynamic.js") for item in result["scripts"])
        assert any(item["method"] == "POST" and item["blocked"] for item in result["requests"])
        assert all(not item.get("url", "").startswith("https://") for item in result["requests"])
    finally:
        server.shutdown()
        server.server_close()
