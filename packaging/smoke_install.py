"""Exercise installed CLI proposals and recovery using only disposable fixtures."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(*arguments):
    result = subprocess.run(
        [sys.executable, "-m", "scriptsentinel.cli", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(f"CLI smoke failed: {arguments[0]}: {result.stdout} {result.stderr}")
    return result.stdout


with tempfile.TemporaryDirectory(prefix="scriptsentinel-install-smoke-") as folder:
    root = Path(folder)
    html = root / "index.html"
    html.write_text(
        '<html><head></head><body><script src="app.js"></script></body></html>', encoding="utf-8"
    )
    (root / "app.js").write_text('console.log("synthetic")', encoding="utf-8")
    original = html.read_bytes()
    run(
        "baseline",
        root,
        "--reviewer",
        "smoke test",
        "--provenance",
        "independently authored harmless fixture",
        "--approve",
    )
    baseline = root / ".scriptsentinel" / "baseline.json"
    proposal = root / "proposal.json"
    run(
        "propose",
        root,
        "--file",
        "index.html",
        "--trusted-baseline",
        baseline,
        "--proposal",
        proposal,
    )
    validation = run(
        "validate-proposal", root, "--trusted-baseline", baseline, "--proposal", proposal
    )
    assert json.loads(validation)["passed"]
    run("apply-proposal", root, "--trusted-baseline", baseline, "--proposal", proposal, "--approve")
    assert b"integrity=" in html.read_bytes()
    run("rollback", root, "--receipt", str(proposal) + ".receipt.json", "--approve")
    assert html.read_bytes() == original
    run("watch", root, "--count", "1")
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    rpc = subprocess.run(
        [sys.executable, "-m", "scriptsentinel.cli", "mcp", str(root)],
        input="".join(json.dumps(message) + "\n" for message in messages),
        capture_output=True,
        text=True,
        timeout=30,
    )
    responses = [json.loads(line) for line in rpc.stdout.splitlines()]
    assert len(responses) == 2 and len(responses[1]["result"]["tools"]) == 2
print(
    "Installed CLI smoke passed: baseline -> propose -> staged validation -> apply -> rollback -> watch; MCP initialization and tools list."
)
