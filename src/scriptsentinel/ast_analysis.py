"""Syntax-aware defensive signals. Parsing never evaluates project code."""

from __future__ import annotations

from typing import Any, cast

from .models import ScanFinding, Severity


def ast_findings(source: str) -> tuple[ScanFinding, ...]:
    import tree_sitter_javascript
    from tree_sitter import Language, Parser

    raw = source.encode("utf-8")
    if len(raw) > 5_000_000:
        return (
            ScanFinding(
                "JS-SIZE-LIMIT",
                "Analysis size limit",
                "MEDIUM",
                1,
                "AST analysis limited to 5 MB; resource not fully analyzed.",
            ),
        )
    tree = Parser(Language(tree_sitter_javascript.language())).parse(raw)
    results: list[ScanFinding] = []
    if tree.root_node.has_error:
        results.append(
            ScanFinding(
                "JS-PARSE-ERROR",
                "JavaScript syntax incomplete",
                "MEDIUM",
                1,
                "Parser found syntax errors; coverage may be incomplete.",
            )
        )
    stack: list[Any] = [tree.root_node]
    seen: set[str] = set()
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.named_children))
        if node.type not in ("call_expression", "new_expression"):
            continue
        callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if callee is None:
            continue
        name = raw[callee.start_byte : callee.end_byte].decode("utf-8")
        rule = None
        if name in ("eval", "window.eval", "Function"):
            rule = ("JS-DYNAMIC-CODE", "Dynamic code execution", "HIGH")
        elif name in ("navigator.sendBeacon",):
            rule = ("JS-BEACON", "Browser beacon", "LOW")
        elif name.startswith("navigator.clipboard."):
            rule = ("JS-CLIPBOARD", "Clipboard capability", "MEDIUM")
        elif name in ("document.createElement",):
            args = node.child_by_field_name("arguments")
            if args and raw[args.start_byte : args.end_byte].strip() in (
                b"('script')",
                b'("script")',
            ):
                rule = ("JS-DYNAMIC-SCRIPT", "Dynamic script creation", "MEDIUM")
        if rule and rule[0] not in seen:
            seen.add(rule[0])
            results.append(
                ScanFinding(
                    rule[0],
                    rule[1],
                    cast(Severity, rule[2]),
                    1,
                    f"AST call at line {node.start_point.row + 1}, column {node.start_point.column + 1}. "
                    "Capability evidence only; legitimate software may use this API. Review context.",
                )
            )
    return tuple(results)
