"""Small, disclosed AST capability corpus; no claim of malware detection accuracy."""
from __future__ import annotations

import time
from typing import Any

from .ast_analysis import ast_findings

CORPUS = (
    ("dynamic-eval", "eval(source)", "JS-DYNAMIC-CODE"),
    ("function-constructor", "new Function(source)", "JS-DYNAMIC-CODE"),
    ("script-element", "document.createElement('script')", "JS-DYNAMIC-SCRIPT"),
    ("clipboard", "navigator.clipboard.readText()", "JS-CLIPBOARD"),
    ("beacon", "navigator.sendBeacon('/metrics', data)", "JS-BEACON"),
    ("benign-reduce", "const total = items.reduce((a,b)=>a+b,0)", None),
    ("comment", "// eval(source)\nconst ok = true", None),
    ("string", "const text = 'eval(source)'", None),
    ("modern-syntax", "const value = account?.preferences ?? {}", None),
    ("ordinary-dom", "document.querySelector('main')", None),
)


def measure() -> dict[str, Any]:
    start = time.perf_counter()
    rows, tp, fp, fn, tn = [], 0, 0, 0, 0
    for name, source, expected in CORPUS:
        observed = {finding.rule_id for finding in ast_findings(source)}
        positive = expected is not None
        matched = expected in observed if positive else bool(observed)
        tp += int(positive and matched)
        fn += int(positive and not matched)
        fp += int(not positive and matched)
        tn += int(not positive and not matched)
        rows.append({"fixture": name, "expected": expected, "observed": sorted(observed), "passed": matched if positive else not matched})
    return {"scope": "10 synthetic AST capability fixtures; not malware or incident coverage",
            "true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn,
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 3), "fixtures": rows}
