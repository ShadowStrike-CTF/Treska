# Treska parsers — shared read-only SQLite triage helpers (iOS Phase 9, Android Phase 10).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

SAMPLE_CAP = 3   # max sample rows per artifact — triage, not dump
TEXT_CAP = 200   # max characters of any sampled text value
TOP_N = 10       # max entries in any ranked list

# WAL copies live here, under the parse temp dir, so the normal cleanup removes them.
WAL_DIR = ".treska_wal"


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open evidence read-only via URI (mode=ro&immutable=1).

    immutable=1 means SQLite never writes, locks, or creates -journal/-wal/-shm
    files beside the evidence — and also never reads a -wal sidecar.
    """
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def open_wal_copy(path: Path) -> sqlite3.Connection:
    """Open a scratch COPY normally so SQLite replays its -wal.

    Only ever called on a file stage_wal() copied under WAL_DIR — never on evidence.
    """
    return sqlite3.connect(str(path))


def stage_wal(db_path: Path, work_dir: Path) -> Path | None:
    """If <db>-wal sits beside db_path, copy db + -wal (+ -shm if present) into
    work_dir/WAL_DIR/<uuid8>/ and return the copied db path; else None.

    The originals are only read (shutil.copy2), never opened by SQLite.
    """
    db_path = Path(db_path)
    wal = db_path.with_name(db_path.name + "-wal")
    if not wal.is_file():
        return None
    dest = Path(work_dir) / WAL_DIR / uuid.uuid4().hex[:8]
    dest.mkdir(parents=True)
    for suffix in ("", "-wal", "-shm"):
        src = db_path.with_name(db_path.name + suffix)
        if src.is_file():
            shutil.copy2(src, dest / src.name)
    return dest / db_path.name


def wal_sidecar_exists(db_path: Path) -> bool:
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + "-wal").is_file()


def table_columns(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Return {table_name: [column_name, ...]} for all tables.

    Raises sqlite3.DatabaseError when the file is not a readable database.
    """
    names = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    )]
    tables: dict[str, list[str]] = {}
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        try:
            tables[name] = [row[1] for row in conn.execute(f"PRAGMA table_info({quoted})")]
        except sqlite3.Error:
            # e.g. a virtual table whose module is unavailable
            tables[name] = []
    return tables


def folded_schema(conn: sqlite3.Connection) -> dict[str, set[str]]:
    """table_columns() with table and column names casefolded — SQLite
    identifiers are case-insensitive, and extraction tools vary the case."""
    return {
        table.casefold(): {col.casefold() for col in cols}
        for table, cols in table_columns(conn).items()
    }


def safe_count(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int | None:
    """Run a COUNT query, return None on sqlite3.Error."""
    value = safe_scalar(conn, sql, params)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_scalar(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Any:
    """First column of the first row, or None on no row / sqlite3.Error."""
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def result_skeleton(filename: str, fmt: str) -> dict[str, Any]:
    """Base triage dict. Every SQLite artifact result has exactly these keys,
    so the JSON contract can pin one key set per format."""
    return {
        "filename": filename,
        "format": fmt,
        "status": None,
        "error": None,
        "warnings": [],
        "wal_present": False,
        "wal_applied": False,
        "summary": None,
        "samples": [],
    }


def truncate(text: Any) -> str | None:
    """Truncate to TEXT_CAP characters. None stays None; blobs (bytes) are
    never dumped and become None; other scalars are stringified."""
    if text is None or isinstance(text, (bytes, bytearray, memoryview)):
        return None
    return str(text)[:TEXT_CAP]


def warn(triage: dict[str, Any], message: str) -> None:
    if message not in triage["warnings"]:
        triage["warnings"].append(message)


@contextmanager
def open_evidence(
    db_path: Path, work_dir: Path | None, triage: dict[str, Any]
) -> Iterator[sqlite3.Connection]:
    """Yield a connection for db_path and record WAL handling on triage.

    No -wal sidecar: the original is opened mode=ro&immutable=1.
    -wal present: db/-wal/-shm are copied under work_dir/WAL_DIR and the copy is
    opened normally so SQLite replays the WAL (wal_applied True). work_dir None
    (a direct parser call) stages into a private temp dir removed on exit. If the
    copy cannot be made or read, fall back to the immutable original with
    wal_applied False and a warning. The originals are never opened read-write.
    """
    db_path = Path(db_path)
    with ExitStack() as stack:
        conn: sqlite3.Connection | None = None
        if wal_sidecar_exists(db_path):
            triage["wal_present"] = True
            try:
                root = Path(work_dir) if work_dir is not None else Path(
                    stack.enter_context(tempfile.TemporaryDirectory(prefix="treska_wal_"))
                )
                copy = stage_wal(db_path, root)
                if copy is None:  # sidecar vanished between checks
                    raise OSError("WAL sidecar not found")
                conn = open_wal_copy(copy)
                # Touching the schema forces the WAL replay now, so a bad copy
                # falls back here rather than failing a later query.
                conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                triage["wal_applied"] = True
            except (OSError, sqlite3.Error) as exc:
                if conn is not None:
                    conn.close()
                    conn = None
                warn(triage, f"WAL present but not applied ({type(exc).__name__}: {exc}); "
                             "read the database without it")
        if conn is None:
            conn = open_readonly(db_path)
        try:
            yield conn
        finally:
            # Close before the ExitStack removes any private temp dir (Windows).
            conn.close()
