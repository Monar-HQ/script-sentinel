# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a Vulnerability

GitHub private vulnerability reporting is the preferred channel:

1. Open the repository's [Security Advisories](https://github.com/Ally-Released/scriptsentinel/security/advisories) tab.
2. Select **Report a vulnerability**.
3. Include the affected component or file, the issue class, a minimal reproduction, and the impact assessment.

If private reporting is unavailable, send an email to `iamnotlol30@gmail.com` with the subject `[SECURITY] ScriptSentinel Vulnerability Report`.

Do not open a public issue for an unpatched vulnerability, and do not disclose details before a coordinated release.

## Disclosure Timeline

| Stage | Target |
| --- | --- |
| Triage | Within 48 hours of receipt |
| Assessment and remediation plan | Within 5 business days |
| Fix and advisory | Within 14 days of confirmation |

## Scope

Security reports should cover the Python package, CLI, reporters, IOC loader, detection rules, and CI action. The OPTIJACK simulation lab is a separate local harness; report lab-specific defects against the harness files listed in `docs/ARCHITECTURE.md`.
