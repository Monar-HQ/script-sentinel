# Distribution

Build the Python wheel and source archive with `python -m build`.
Install the wheel into a fresh virtual environment before release.

Windows standalone build (requires PyInstaller in the build environment):

```text
pyinstaller --noconfirm --onefile --noupx --name scriptsentinel --paths src --collect-all tree_sitter_javascript --collect-data scriptsentinel packaging/standalone.py
```

Use `python packaging/build_standalone.py` from the locked release environment
to include all package data. CI builds the wheel and source archive. Build
executables natively on each OS; a Windows
binary is not a macOS/Linux binary. Artifacts are unsigned until a release
operator supplies the platform signing identity. Do not imply provenance that
has not actually been produced.

Docker: `docker build -f packaging/Dockerfile -t scriptsentinel:1.0.0rc1 .`.
Run the offline demo with `docker run --rm --network none scriptsentinel:1.0.0rc1`.
Audit a read-only mounted web root with `auto /workspace --json`. The local UI
binds to loopback only and is intended for native use, not remote container hosting.

The Kubernetes CronJob is an offline audit example. Select a reviewed image,
volume and service-account policy in your own cluster. It is not auto-deployed.
The supplied local-audit workload needs no network egress; enforce that with
your cluster's CNI NetworkPolicy. Docker and Kubernetes require local tooling
and operator validation, not just a valid YAML document.
