"""Versioned local state and bounded workspace access."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class Workspace:
    def __init__(self, root: Path, state: Path | None = None):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Workspace must be a directory")
        self.state = (state or self.root / ".scriptsentinel").resolve()
        if state is None and not self.state.is_relative_to(self.root):
            raise ValueError("Runtime state symlink escapes workspace")
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state_file("state.sqlite3")
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        for name in (
            "state.sqlite3",
            "state.sqlite3-journal",
            "state.sqlite3-wal",
            "state.sqlite3-shm",
        ):
            self.state_file(name)
        db = sqlite3.connect(self.database, timeout=10)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("PRAGMA trusted_schema=OFF")
            with db:
                yield db
        finally:
            db.close()

    def state_file(self, name: str) -> Path:
        candidate = self.state / name
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(self.state):
            raise ValueError("Runtime state file escapes approved state directory")
        if candidate.exists() and candidate.stat().st_nlink > 1:
            raise ValueError("Runtime state files must not be hard-linked")
        return candidate

    def record(self, kind: str, data: dict[str, Any]) -> int:
        if self.database.stat().st_size > 100_000_000:
            raise ValueError("Local evidence store reached 100 MB; archive it before continuing")
        encoded = json.dumps(data)
        if len(encoded) > 5_000_000:
            raise ValueError("Evidence record exceeds 5 MB")
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO events(time, kind, data) VALUES (?, ?, ?)",
                (datetime.now(UTC).isoformat(), kind, encoded),
            )
            return int(cursor.lastrowid or 0)

    def events(self, limit: int = 25) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,time,kind,data FROM events ORDER BY id DESC LIMIT ?",
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [
            {"id": row[0], "time": row[1], "kind": row[2], "data": json.loads(row[3])}
            for row in rows
        ]

    def event(self, identifier: int) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT kind,data FROM events WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise ValueError("Evidence record not found")
        return {"kind": row[0], "data": json.loads(row[1])}
