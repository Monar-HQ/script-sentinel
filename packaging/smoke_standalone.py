"""Windows native-console smoke test; only an owned disposable process tree."""

import queue
import re
import subprocess
import tempfile
import threading
from pathlib import Path

import httpx

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="scriptsentinel-native-smoke-") as folder:
    process = subprocess.Popen(
        [str(root / "dist" / "v1" / "scriptsentinel.exe"), "ui", folder, "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = queue.Queue()

    def read_line():
        lines.put(process.stdout.readline())

    threading.Thread(target=read_line, daemon=True).start()
    try:
        line = lines.get(timeout=45)
        match = re.search(r"(http://127\.0\.0\.1:\d+)/#token=([A-Za-z0-9_-]+)", line)
        assert match, "Native console did not return a private local link"
        url, token = match.groups()
        with httpx.Client(trust_env=False, timeout=20) as client:
            assert client.get(url).status_code == 200
            result = client.post(
                url + "/api/demo",
                headers={"Authorization": "Bearer " + token, "Origin": url},
                json={},
            )
            assert result.status_code == 200 and len(result.json()["report"]["scripts"]) == 1
        print("Native Windows console and bundled demo smoke passed.")
    finally:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False
        )
        process.wait(timeout=15)
        if process.stdout:
            process.stdout.close()
