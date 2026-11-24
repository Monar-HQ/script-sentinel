# Harmless offline demonstration

This fixture contains no payment data, attack code or outbound requests.
It illustrates missing integrity metadata and a reviewed SRI proposal.
The baseline applies only to these synthetic bytes, never to a real application.

From the repository root:

```text
scriptsentinel auto examples/synthetic --json
scriptsentinel propose examples/synthetic --file index.html --trusted-baseline examples/synthetic/trusted.json --proposal demo-proposal.json
scriptsentinel validate-proposal examples/synthetic --trusted-baseline examples/synthetic/trusted.json --proposal demo-proposal.json
```

Review the diff, then test a copy before using `apply-proposal --approve`.
To demonstrate drift, edit a copy of app.js and observe validation fail.
Do not use this tiny fixture as a detection accuracy benchmark.
