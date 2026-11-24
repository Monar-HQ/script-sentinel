"""Capture focused README evidence from the real, harmless demo."""

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
        page.get_by_role("button", name="Try the synthetic demo").click()
        page.locator("#report").wait_for(state="visible")
        page.locator("#report").screenshot(path=str(root / "assets" / "review-console.png"))
        page.get_by_role("button", name="Script inventory", exact=True).click()
        page.locator("#inventory").screenshot(path=str(root / "assets" / "inventory-console.png"))
        browser.close()
finally:
    server.shutdown()
    server.server_close()
