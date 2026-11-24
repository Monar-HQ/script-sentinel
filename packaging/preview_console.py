"""Capture the actual local demo console for repository presentation."""

import os
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

from scriptsentinel.dashboard import make_server

root = Path(__file__).resolve().parents[1]
server, token = make_server(root / "examples" / "synthetic", 0)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=os.environ.get("SCRIPTSENTINEL_BROWSER_EXECUTABLE")
        )
        page = browser.new_page(viewport={"width": 1440, "height": 1040}, device_scale_factor=1)
        page.goto(f"http://127.0.0.1:{server.server_port}/#token={token}")
        page.locator("#workspace").get_by_text(str(root / "examples" / "synthetic")).wait_for()
        page.screenshot(path=str(root / "assets" / "console-v1.png"), full_page=True)
        page.get_by_role("button", name="Try the synthetic demo").click()
        page.locator("#report").wait_for(state="visible")
        page.screenshot(path=str(root / "assets" / "evidence-v1.png"), full_page=True)
        page.set_viewport_size({"width": 1600, "height": 640})
        page.set_content((root / "assets" / "hero-v1.svg").read_text(encoding="utf-8"),wait_until="domcontentloaded")
        page.locator("svg").screenshot(path=str(root / "assets" / "social-v1.png"))
        browser.close()
finally:
    server.shutdown()
    server.server_close()
