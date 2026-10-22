# Treska core — read-only SQLite schema extraction.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import sqlite3
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00"


def is_sqlite(file_path: Path) -> bool:
    """True when the file starts with the SQLite 3 magic header."""
    try:
        with open(file_path, "rb") as fh:
            return fh.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def probe_sqlite(file_path: Path) -> dict | None:
    """Return {"tables": [{"name", "columns": [{"name", "type"}]}]} or None.

    Opened with mode=ro&immutable=1 so SQLite never writes, locks, or creates
    journal/-shm files. Uncommitted WAL content is therefore not visible.
    Returns None for non-SQLite, locked, or corrupt files.
    """
    if not is_sqlite(file_path):
        return None
    uri = Path(file_path).resolve().as_uri() + "?mode=ro&immutable=1"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        names = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )]
        tables = []
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            try:
                columns = [
                    {"name": row[1], "type": row[2]}
                    for row in conn.execute(f"PRAGMA table_info({quoted})")
                ]
            except sqlite3.Error:
                # e.g. virtual tables whose module is unavailable
                columns = []
            tables.append({"name": name, "columns": columns})
        return {"tables": tables}
    except (sqlite3.Error, OSError):
        return None
    finally:
        if conn is not None:
            conn.close()
