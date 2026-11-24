"""Fixed entry point for PyInstaller; no import-time project execution."""
from scriptsentinel.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
