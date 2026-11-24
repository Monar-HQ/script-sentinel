# Detection rules in v1

Signals are evidence for review, not assertions of malicious intent. Rule IDs
from earlier versions are retained for compatibility; names and severity were
corrected where a common API had been mislabeled as proven theft.

| Family | Rules | Interpretation |
| --- | --- | --- |
| AST | JS-DYNAMIC-CODE, JS-DYNAMIC-SCRIPT, JS-CLIPBOARD, JS-BEACON | Parsed call expressions with source positions; capability evidence |
| AST coverage | JS-PARSE-ERROR, JS-SIZE-LIMIT | Incomplete syntax or analysis coverage; never silently clean |
| Heuristic | SKIM-INPUT-HARVEST | Sensitive-field access pattern, High; legitimate forms also match |
| Heuristic | SKIM-DOM-LISTENER, SKIM-CLIPBOARD-TAMPER | Listener/clipboard patterns, Medium; no inference of global interception |
| Heuristic | SKIM-EVAL-EXEC | Dynamic evaluation pattern, High |
| Heuristic | SKIM-BASE64-UNPACK | Encoding/decoding pattern, Medium |
| Heuristic | SKIM-EXFIL-BEACON | Beacon API pattern, Low; ordinary analytics also use it |
| Hunting | IOC-MATCH-C2-DOMAIN, IOC-MATCH-C2-HASH | Packaged indicators, High; verify lab/incident provenance |
| Integrity | MISSING_SRI, INTEGRITY_MISMATCH, SCRIPT_DRIFT | Missing declaration, unsupported/mismatched declaration or changed approved bytes |
| CSP | CSP-MISSING, CSP-UNSAFE-EVAL, CSP-UNSAFE-INLINE, CSP-UNSAFE-ATTR | Missing policy or supported unsafe execution surfaces |
| CSP | CSP-SCRIPT-UNRESTRICTED, CSP-CONNECT-WILDCARD, CSP-STRICT-DYNAMIC-RISK | Supported posture weaknesses requiring context |
| CSP | CSP-REPORTING-ABSENT, CSP-MULTIPLE-POLICIES | Reporting posture and independent-policy handling |

AST parsing never evaluates the source. Comments and strings are not executable
AST calls, but the separate regex layer can still match them; this limitation
is explicit. No interprocedural taint or whole-program maliciousness proof is
claimed. Dynamic JavaScript, aliasing and runtime-generated content may be missed.

The HTML inventory recognizes the WHATWG JavaScript MIME essences, including
legacy types. Non-executable data scripts are retained with an analysis note,
without generating false JavaScript syntax findings.

SRI uses the strongest supported declared algorithm and any matching digest at
that level. A digest validates content consistency, not the trustworthiness of
the original artifact. Local proposals require an independently reviewed
baseline. Missing resources, unsupported base URLs and discovery limits are
reported explicitly.

CSP rules model selected policy semantics, not every browser's policy engine.
Multiple policies are processed independently; shared posture signals contribute
to the aggregate grade. Hash-source syntax/length must be valid before it can
suppress an unsafe-inline warning. Header grades do not prove that deployment
works, that all exfiltration channels are blocked, or that a breach occurred.

The benchmark discloses ten harmless AST capability fixtures. It is not a
malware-detection false-positive/false-negative estimate for real applications.
