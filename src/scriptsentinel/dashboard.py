"""Loopback-only local application; scoped workspace, bearer auth and origin checks."""

from __future__ import annotations

import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import monitoring, proposals, validation
from .auto import run_auto_pipeline
from .runtime import Workspace


def make_server(root: Path, port: int = 8765) -> tuple[ThreadingHTTPServer, str]:
    workspace = Workspace(root)
    token = secrets.token_urlsafe(32)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # never log paths, query strings, bearer tokens or request bodies

        def send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def allowed(self) -> bool:
            expected = f"127.0.0.1:{server.server_port}"
            if self.headers.get("Host") != expected:
                self.send(403, b'{"error":"Invalid host"}')
                return False
            if self.path.startswith("/api/"):
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
                    self.send(
                        401, b'{"error":"Open the private dashboard link printed in your terminal"}'
                    )
                    return False
            if self.command == "POST" and self.headers.get("Origin") != f"http://{expected}":
                self.send(403, b'{"error":"Invalid request origin"}')
                return False
            return True

        def do_GET(self) -> None:
            if not self.allowed():
                return
            if self.path in ("/", "/app.js", "/style.css", "/mark.svg"):
                filename = "index.html" if self.path == "/" else self.path[1:]
                content_type = {
                    "index.html": "text/html; charset=utf-8",
                    "app.js": "text/javascript; charset=utf-8",
                    "style.css": "text/css; charset=utf-8",
                    "mark.svg": "image/svg+xml",
                }[filename]
                self.send(
                    200,
                    files("scriptsentinel").joinpath("web", filename).read_bytes(),
                    content_type,
                )
            elif self.path == "/api/status":
                self.send(
                    200,
                    json.dumps(
                        {
                            "workspace": str(workspace.root),
                            "baseline": (workspace.state / "baseline.json").exists(),
                            "version": "1.0.0rc1",
                            "mode": "Core · local only",
                        }
                    ).encode(),
                )
            elif self.path == "/api/events":
                self.send(200, json.dumps(workspace.events()).encode())
            elif self.path == "/api/research":
                self.send(
                    200,
                    files("scriptsentinel").joinpath("knowledge", "optimjack.json").read_bytes(),
                )
            else:
                self.send(404, b'{"error":"Not found"}')

        def do_POST(self) -> None:
            if not self.allowed():
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("Request size invalid")
                if self.headers.get("Content-Type") != "application/json":
                    raise ValueError("Expected JSON request")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Expected request object")
                if not lock.acquire(blocking=False):
                    self.send(409, b'{"error":"Another operation is running; try again shortly"}')
                    return
                try:
                    result: Any
                    if self.path in ("/api/audit", "/api/demo"):
                        target = (
                            workspace.root
                            if self.path == "/api/audit"
                            else Path(str(files("scriptsentinel").joinpath("demo")))
                        )
                        result = run_auto_pipeline(str(target)).audit_report.to_dict()
                        identifier = workspace.record(
                            "demo-audit" if self.path == "/api/demo" else "audit", result
                        )
                        result = {"id": identifier, "report": result}
                    elif self.path == "/api/baseline":
                        if payload.get("approve") is not True:
                            raise ValueError("Review the source before approving its baseline")
                        result = monitoring.pin(
                            workspace,
                            str(payload.get("reviewer", "")),
                            str(payload.get("provenance", "")),
                        )
                    elif self.path == "/api/monitor":
                        result = monitoring.compare(workspace)
                    elif self.path == "/api/propose":
                        result = proposals.propose(
                            workspace.root,
                            str(payload["file"]),
                            proposals.confined(workspace.root, str(payload["baseline"])),
                        )
                        identifier = workspace.record("proposal", result)
                        result = {"id": identifier, "proposal": result}
                    elif self.path == "/api/validate":
                        event = workspace.event(int(payload["id"]))
                        if event["kind"] != "proposal":
                            raise ValueError("Expected a proposal record")
                        result = validation.isolated(
                            workspace.root,
                            event["data"],
                            proposals.confined(workspace.root, str(payload["baseline"])),
                        )
                        workspace.record("proposal-validation", result)
                    else:
                        self.send(404, b'{"error":"Not found"}')
                        return
                    self.send(200, json.dumps(result).encode())
                finally:
                    lock.release()
            except (ValueError, OSError, KeyError, TypeError) as exc:
                self.send(400, json.dumps({"error": str(exc)}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server, token


def serve(root: Path, port: int = 8765) -> None:
    server, token = make_server(root, port)
    print(
        f"ScriptSentinel local console: http://127.0.0.1:{server.server_port}/#token={token}",
        flush=True,
    )
    print("Private link. Keep this terminal open; Ctrl+C stops the console.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
