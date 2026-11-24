"""Trust-boundary and end-to-end tests using temporary, harmless fixtures."""

import asyncio
import threading
from pathlib import Path

import httpx
import pytest

from scriptsentinel import monitoring, proposals, validation
from scriptsentinel.ast_analysis import ast_findings
from scriptsentinel.benchmark import measure
from scriptsentinel.dashboard import make_server
from scriptsentinel.host import dispatch
from scriptsentinel.network import NetworkPolicy, origin
from scriptsentinel.research import load_pack
from scriptsentinel.runtime import Workspace


def seed(root: Path):
    (root / "index.html").write_text(
        '<html><head></head><body><script src="app.js"></script></body></html>', encoding="utf-8"
    )
    (root / "app.js").write_text('console.log("synthetic");', encoding="utf-8")
    workspace = Workspace(root)
    monitoring.pin(workspace, "test reviewer", "reviewed synthetic artifact")
    return workspace, workspace.state / "baseline.json"


def test_ast_ignores_comments_and_strings():
    assert not ast_findings("// eval(source)\nconst value='navigator.clipboard.readText()'")
    assert ast_findings("const x = eval(source)")[0].rule_id == "JS-DYNAMIC-CODE"
    assert ast_findings("const x = {")[0].rule_id == "JS-PARSE-ERROR"


def test_data_scripts_are_inventoried_without_false_code_findings(tmp_path):
    from scriptsentinel.auto import run_auto_pipeline

    (tmp_path / "index.html").write_text(
        '<script type="application/ld+json">{"password":"eval(source)"}</script>', encoding="utf-8"
    )
    script = run_auto_pipeline(str(tmp_path)).audit_report.scripts[0]
    assert script.analysis_note
    assert script.scan is None and script.error is None


@pytest.mark.parametrize(
    "mime",
    ["application/x-javascript", "text/jscript", "text/javascript1.5", "application/x-ecmascript"],
)
def test_legacy_javascript_mime_types_are_analyzed(tmp_path, mime):
    from scriptsentinel.auto import run_auto_pipeline

    (tmp_path / "index.html").write_text(
        f'<script type="{mime}" src="app.js"></script>', encoding="utf-8"
    )
    (tmp_path / "app.js").write_text('console.log("harmless legacy type")', encoding="utf-8")
    script = run_auto_pipeline(str(tmp_path)).audit_report.scripts[0]
    assert script.integrity is not None and script.scan is not None
    assert script.analysis_note is None


def test_receipt_not_created_without_approval(tmp_path):
    _, baseline = seed(tmp_path)
    plan = proposals.propose(tmp_path, "index.html", baseline)
    receipt = tmp_path / "receipt.json"
    with pytest.raises(ValueError, match="approval"):
        validation.apply_reviewed(tmp_path, plan, baseline, receipt, False)
    assert not receipt.exists()


def test_noncanonical_leave_and_reenter_path_is_rejected(tmp_path):
    _, baseline = seed(tmp_path)
    original = (tmp_path / "index.html").read_bytes()
    with pytest.raises(ValueError, match="workspace-relative"):
        proposals.propose(tmp_path, f"../{tmp_path.name}/index.html", baseline)
    assert (tmp_path / "index.html").read_bytes() == original


def test_local_base_href_never_pins_or_patches_wrong_resource(tmp_path):
    from scriptsentinel.auto import run_auto_pipeline

    _workspace, baseline = seed(tmp_path)
    (tmp_path / "index.html").write_text(
        '<base href="/different/"><script src="app.js"></script>', encoding="utf-8"
    )
    original = (tmp_path / "index.html").read_bytes()
    with pytest.raises(ValueError, match="base href"):
        proposals.propose(tmp_path, "index.html", baseline)
    with pytest.raises(ValueError, match="incomplete"):
        monitoring.snapshot(tmp_path)
    report = run_auto_pipeline(str(tmp_path)).audit_report
    assert report.scripts[0].error and report.scripts[0].integrity is None
    assert (tmp_path / "index.html").read_bytes() == original


def test_receipt_failure_restores_applied_bytes(tmp_path, monkeypatch):
    _, baseline = seed(tmp_path)
    original = (tmp_path / "index.html").read_bytes()
    plan = proposals.propose(tmp_path, "index.html", baseline)
    monkeypatch.setattr(
        "scriptsentinel.validation.os.fsync",
        lambda _: (_ for _ in ()).throw(OSError("injected disk failure")),
    )
    with pytest.raises(OSError, match="disk failure"):
        validation.apply_reviewed(tmp_path, plan, baseline, tmp_path / "receipt.json", True)
    assert (tmp_path / "index.html").read_bytes() == original


def test_monitoring_restarts_from_persistent_state(tmp_path):
    first, _ = seed(tmp_path)
    for _ in range(25):
        assert not monitoring.compare(first)["changed"]
    restarted = Workspace(tmp_path)
    assert len(restarted.events(100)) == 26
    (tmp_path / "app.js").unlink()
    assert monitoring.compare(restarted)["changed"]


def test_runtime_rejects_preexisting_linked_database(tmp_path):
    import os
    import sqlite3
    from contextlib import closing

    root = tmp_path / "root"
    state = root / ".scriptsentinel"
    state.mkdir(parents=True)
    outside = tmp_path / "outside.sqlite3"
    with closing(sqlite3.connect(outside)) as db:
        db.execute("CREATE TABLE original(value TEXT)")
        db.commit()
    before = outside.read_bytes()
    os.link(outside, state / "state.sqlite3")
    with pytest.raises(ValueError, match="hard-linked"):
        Workspace(root)
    assert outside.read_bytes() == before


def test_scoped_client_decodes_compressed_resources_once(monkeypatch):
    import gzip

    from scriptsentinel.network import ScopedClient

    policy = NetworkPolicy.create(["https://owned.example"])
    monkeypatch.setattr(NetworkPolicy, "check", lambda *args, **kwargs: None)

    async def run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-encoding": "gzip"}, content=gzip.compress(b"synthetic")
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            result = await ScopedClient(client, policy).get("https://owned.example/app.js")
            assert result.content == b"synthetic"

    asyncio.run(run())


def test_persistent_change_detection(tmp_path):
    workspace, _ = seed(tmp_path)
    assert not monitoring.compare(workspace)["changed"]
    (tmp_path / "app.js").write_text("console.log('changed')", encoding="utf-8")
    assert monitoring.compare(workspace)["changed"]
    assert workspace.events()[0]["kind"] == "monitor-drift"
    with pytest.raises(FileExistsError):
        monitoring.pin(workspace, "reviewer", "do not overwrite")


def test_isolated_validation_apply_and_rollback(tmp_path):
    _, baseline = seed(tmp_path)
    original = (tmp_path / "index.html").read_bytes()
    plan = proposals.propose(tmp_path, "index.html", baseline)
    assert validation.isolated(tmp_path, plan, baseline)["passed"]
    backup = proposals.apply(tmp_path, plan, baseline, approved=True)
    receipt = {
        "file": "index.html",
        "backup": backup.name,
        "before_sha256": plan["before_sha256"],
        "after_sha256": plan["after_sha256"],
    }
    validation.rollback(tmp_path, receipt, True)
    assert (tmp_path / "index.html").read_bytes() == original
    assert backup.exists()


def test_rollback_refuses_later_user_edits(tmp_path):
    _, baseline = seed(tmp_path)
    plan = proposals.propose(tmp_path, "index.html", baseline)
    backup = proposals.apply(tmp_path, plan, baseline, approved=True)
    (tmp_path / "index.html").write_text("new user edits", encoding="utf-8")
    receipt = {
        "file": "index.html",
        "backup": backup.name,
        "before_sha256": plan["before_sha256"],
        "after_sha256": plan["after_sha256"],
    }
    with pytest.raises(ValueError, match="later work"):
        validation.rollback(tmp_path, receipt, True)


def test_scope_requires_explicit_origin_and_private_opt_in():
    policy = NetworkPolicy.create(["http://127.0.0.1:8000"])
    with pytest.raises(ValueError, match="Private/local"):
        policy.check("http://127.0.0.1:8000/page")
    with pytest.raises(ValueError, match="outside"):
        policy.check("https://example.invalid")
    assert origin("https://EXAMPLE.com/path") == "https://example.com:443"
    with pytest.raises(ValueError):
        origin("https://secret@example.com")


def test_dashboard_auth_csrf_and_end_to_end(tmp_path):
    seed(tmp_path)
    server, token = make_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            assert client.get("/").status_code == 200
            assert client.get("/api/status").status_code == 401
            headers = {"Authorization": f"Bearer {token}", "Origin": base}
            assert (
                client.post(
                    "/api/audit", headers={"Authorization": f"Bearer {token}"}, json={}
                ).status_code
                == 403
            )
            result = client.post("/api/audit", headers=headers, json={})
            assert result.status_code == 200
            assert len(result.json()["report"]["scripts"]) == 1
            plan = client.post(
                "/api/propose",
                headers=headers,
                json={"file": "index.html", "baseline": ".scriptsentinel/baseline.json"},
            ).json()
            result = client.post(
                "/api/validate",
                headers=headers,
                json={"id": plan["id"], "baseline": ".scriptsentinel/baseline.json"},
            )
            assert result.json()["passed"]
            assert client.get("/api/events", headers=headers).json()
            assert client.post("/api/apply", headers=headers, json={}).status_code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_host_tools_are_scoped_read_only(tmp_path):
    workspace, _ = seed(tmp_path)
    tools = dispatch(workspace, "tools/list", {})["tools"]
    assert {item["name"] for item in tools} == {"audit_workspace", "advisory_roles"}
    with pytest.raises(ValueError):
        dispatch(
            workspace,
            "tools/call",
            {"name": "audit_workspace", "arguments": {"path": "../outside"}},
        )
    assert dispatch(workspace, "tools/call", {"name": "audit_workspace"})["content"]


def test_benchmark_and_pack_are_reproducible():
    result = measure()
    assert result["false_negative"] == result["false_positive"] == 0
    assert len(result["fixtures"]) == 10
    assert load_pack()["cve"]["cna_base_score"] == 7.1


def test_http_inventory_honors_document_base_url():
    from scriptsentinel.auditor import audit_url

    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/index.html":
            return httpx.Response(200, text='<base href="/assets/"><script src="app.js"></script>')
        return httpx.Response(200, text='console.log("harmless")')

    report = asyncio.run(
        audit_url("https://owned.example/index.html", transport=httpx.MockTransport(handler))
    )
    assert report.scripts[0].url == "https://owned.example/assets/app.js"
    assert seen == ["https://owned.example/index.html", "https://owned.example/assets/app.js"]


def test_discovery_enforces_size_before_html_parse(tmp_path, monkeypatch):
    from scriptsentinel import env_detector

    (tmp_path / "large.html").write_bytes(b" " * 5_000_001)
    monkeypatch.setattr(
        env_detector,
        "BeautifulSoup",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("parser must not run")),
    )
    profile = env_detector.detect_environment(str(tmp_path))
    assert any(key.startswith("size_limit_") for key in profile.metadata)


def test_scoped_http_redirect_does_not_escape(monkeypatch):
    from scriptsentinel.network import ScopedClient

    policy = NetworkPolicy.create(["https://owned.example"])
    monkeypatch.setattr(
        NetworkPolicy,
        "check",
        lambda self, url, resolve=True: (
            None
            if origin(url) in self.origins
            else (_ for _ in ()).throw(ValueError("outside scope"))
        ),
    )
    requests = []

    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.example/private"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError, match="outside"):
                await ScopedClient(client, policy).get("https://owned.example")

    asyncio.run(run())
    assert len(requests) == 1
