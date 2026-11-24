"""Complete local workflows shared by CLI, dashboard and host-agent tools."""

from __future__ import annotations

import json
import time
from importlib.resources import files
from pathlib import Path
from typing import Any


def register(subparsers: Any) -> None:
    for name, help_text in (
        ("ui", "Private local security console"),
        ("baseline", "Pin independently reviewed local artifacts"),
        ("watch", "Persist local changes against a reviewed baseline"),
        ("mcp", "Read-only host-agent tools over stdio"),
    ):
        p = subparsers.add_parser(name, help=help_text)
        p.add_argument("root", nargs="?", default=".")
        if name == "ui":
            p.add_argument("--port", type=int, default=8765)
        if name == "baseline":
            p.add_argument("--reviewer", required=True)
            p.add_argument("--provenance", required=True)
            p.add_argument("--approve", action="store_true")
        if name == "watch":
            p.add_argument("--interval", type=float, default=60)
            p.add_argument("--count", type=int, default=0, help="0 watches until Ctrl+C")
    p = subparsers.add_parser(
        "observe-browser", help="Observe one authorized anonymous staging page"
    )
    p.add_argument("url")
    p.add_argument("--allow-origin", action="append", default=[])
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--wait-ms", type=int, default=1000)
    p.add_argument("--executable")
    p.add_argument("--output", required=True)
    p = subparsers.add_parser("demo", help="Audit a harmless bundled checkout")
    p.add_argument("--format", choices=("json", "html"), default="json")
    p.add_argument("--output")
    p = subparsers.add_parser("research", help="Read a validated, sourced research pack")
    p.add_argument("--pack", help="Optional local data-only research pack")
    subparsers.add_parser("benchmark", help="Measure the synthetic AST corpus")
    p = subparsers.add_parser("rollback", help="Restore a proposal without overwriting later edits")
    p.add_argument("root")
    p.add_argument("--receipt", required=True)
    p.add_argument("--approve", action="store_true")
    p = subparsers.add_parser("credential-set", help="Store a provider key in the OS keychain")
    p.add_argument("provider", choices=("openai", "anthropic", "openrouter", "gemini", "custom"))


def execute(args: Any) -> int | None:
    if args.command not in {
        "ui",
        "baseline",
        "watch",
        "observe-browser",
        "mcp",
        "demo",
        "research",
        "benchmark",
        "rollback",
        "credential-set",
    }:
        return None
    try:
        if args.command == "ui":
            from .dashboard import serve

            serve(Path(args.root), args.port)
        elif args.command == "baseline":
            from .monitoring import pin
            from .runtime import Workspace

            if not args.approve:
                raise ValueError("Review artifacts independently before using --approve")
            print(
                json.dumps(
                    pin(Workspace(Path(args.root)), args.reviewer, args.provenance), indent=2
                )
            )
        elif args.command == "watch":
            from .monitoring import compare
            from .runtime import Workspace

            if args.interval < 1 or args.count < 0:
                raise ValueError("Interval must be >=1 second and count >=0")
            workspace = Workspace(Path(args.root))
            count, changed = 0, False
            while args.count == 0 or count < args.count:
                result = compare(workspace)
                changed = changed or result["changed"]
                print(json.dumps(result), flush=True)
                count += 1
                if args.count == 0 or count < args.count:
                    time.sleep(args.interval)
            return int(changed)
        elif args.command == "observe-browser":
            from .browser import observe
            from .network import NetworkPolicy

            result = observe(
                args.url,
                NetworkPolicy.create([args.url, *args.allow_origin], args.allow_private),
                args.authorized,
                args.wait_ms,
                args.executable,
            )
            with Path(args.output).open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
        elif args.command == "mcp":
            from .host import serve as serve_host

            serve_host(Path(args.root))
        elif args.command == "demo":
            from .auto import run_auto_pipeline

            report = run_auto_pipeline(str(files("scriptsentinel").joinpath("demo"))).audit_report
            if args.format == "html":
                from .report.html_reporter import render_html

                content = render_html(report)
            else:
                content = json.dumps(report.to_dict(), indent=2)
            if args.output:
                with Path(args.output).open("x", encoding="utf-8") as stream:
                    stream.write(content)
            else:
                print(content)
        elif args.command == "research":
            from .research import load_pack

            print(json.dumps(load_pack(Path(args.pack) if args.pack else None), indent=2))
        elif args.command == "benchmark":
            from .benchmark import measure

            print(json.dumps(measure(), indent=2))
        elif args.command == "rollback":
            from .validation import rollback

            rollback(
                Path(args.root),
                json.loads(Path(args.receipt).read_text(encoding="utf-8")),
                args.approve,
            )
            print("Restored original bytes. Recovery copy retained.")
        elif args.command == "credential-set":
            import getpass

            import keyring

            if keyring.get_keyring().priority <= 0:
                raise ValueError("No secure OS keychain is available")
            secret = getpass.getpass("Provider API key (hidden): ")
            if not secret.strip():
                raise ValueError("Empty credential")
            keyring.set_password("scriptsentinel", args.provider, secret)
            print("Credential stored in the OS keychain.")
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        print(f"Unable to complete: {exc}")
        return 2
