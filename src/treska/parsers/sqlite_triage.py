# Treska parsers — shared read-only SQLite triage helpers (iOS Phase 9, Android Phase 10).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import math
import shutil
import sqlite3
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SAMPLE_CAP = 3   # max sample rows per artifact — triage, not dump
TEXT_CAP = 200   # max characters of any sampled text value
TOP_N = 10       # max entries in any ranked list

# WAL copies live here, under the parse temp dir, so the normal cleanup removes them.
WAL_DIR = ".treska_wal"

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Casefolded {table: {column, ...}} from folded_schema().
Schema = dict[str, set[str]]
# A per-artifact body: (conn, schema, triage) -> (summary, samples, total_rows).
Body = Callable[[sqlite3.Connection, Schema, dict[str, Any]], tuple[dict[str, Any], list[dict], int]]


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


def epoch_to_iso(epoch: datetime, seconds: Any) -> str | None:
    """epoch + seconds -> ISO 8601 UTC ("YYYY-MM-DDTHH:MM:SSZ").

    The caller fixes the unit (it converts to seconds before calling); this never
    guesses. None, blobs, non-numbers, 0, NaN/inf and out-of-range values -> None.
    """
    if seconds is None or isinstance(seconds, (bytes, bytearray, memoryview)):
        return None
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return None
    if seconds == 0 or not math.isfinite(seconds):
        return None
    try:
        return (epoch + timedelta(seconds=seconds)).strftime(ISO_FORMAT)
    except (OverflowError, ValueError):
        return None


def has(schema: Schema, table: str, column: str | None = None) -> bool:
    """True if table (and column, if given) exists — case-insensitively."""
    cols = schema.get(table.casefold())
    if cols is None:
        return False
    return column is None or column.casefold() in cols


def need_column(schema: Schema, triage: dict[str, Any], table: str, column: str) -> bool:
    """True if table.column exists; else record a warning (table assumed present)."""
    if has(schema, table, column):
        return True
    warn(triage, f"missing column {table}.{column}")
    return False


def count_table(conn: sqlite3.Connection, schema: Schema, table: str) -> int | None:
    """COUNT(*) of table, or None when the table is absent or unreadable."""
    if not has(schema, table):
        return None
    return safe_count(conn, f'SELECT COUNT(*) FROM "{table}"')


def fetch_rows(conn: sqlite3.Connection, triage: dict[str, Any], sql: str,
               params: tuple = ()) -> list[tuple]:
    """All rows of sql, or [] plus a warning on sqlite3.Error."""
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error as exc:
        warn(triage, f"query failed ({type(exc).__name__}: {exc})")
        return []


UNKNOWN_LABEL = "unknown"  # count_map label for NULL / blob group keys


def count_map(
    conn: sqlite3.Connection,
    triage: dict[str, Any],
    sql: str,
    params: tuple = (),
    key: Callable[[str], str | None] | None = None,
) -> dict[str, int] | None:
    """Run a `label, count` GROUP BY query -> {label: count}.

    NULL / blob labels become "unknown"; labels are TEXT_CAP-truncated. key, if
    given, re-buckets each label in Python (e.g. URL -> host) and counts merge;
    a key returning None/"" also lands in "unknown". On sqlite3.Error: warning + None.
    """
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.Error as exc:
        warn(triage, f"query failed ({type(exc).__name__}: {exc})")
        return None
    counts: dict[str, int] = {}
    for label, n in rows:
        text = truncate(label)
        if text is not None and key is not None:
            text = truncate(key(text))
        if not text:
            text = UNKNOWN_LABEL
        counts[text] = counts.get(text, 0) + int(n or 0)
    return counts


def ranked(counts: dict[str, int] | None, label_key: str, n: int = TOP_N) -> list[dict] | None:
    """{label: count} -> [{label_key: label, "count": count}], count DESC then
    label ASC, at most n entries. None stays None."""
    if counts is None:
        return None
    order = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{label_key: label, "count": count} for label, count in order[:n]]


def has_all_tables(path: Path, required: tuple[str, ...]) -> bool:
    """True when the ORIGINAL db (immutable read-only, no WAL replay) has every
    required table. The generic-name pre-check (History / History.db). Never raises."""
    try:
        conn = open_readonly(Path(path))
    except (sqlite3.Error, OSError):
        return False
    try:
        schema = folded_schema(conn)
        return all(has(schema, table) for table in required)
    except (sqlite3.Error, OSError):
        return False
    finally:
        conn.close()


def triage_sqlite(
    path: Path,
    filename: str,
    fmt: str,
    required: tuple[str, ...],
    body: Body,
    work_dir: Path | None,
    sample_cap: int = SAMPLE_CAP,
) -> dict[str, Any]:
    """Shared frame for every SQLite artifact (iOS and Android): open (WAL-aware,
    read-only), check required tables, run body.

    status: corrupt = can't open / none of the required tables exist;
    empty = body reports zero rows; parsed otherwise. Never raises.
    sample_cap bounds samples (default SAMPLE_CAP; Chrome mixes visits + searches).
    """
    triage = result_skeleton(filename, fmt)
    try:
        with open_evidence(Path(path), work_dir, triage) as conn:
            schema = folded_schema(conn)
            present = [t for t in required if has(schema, t)]
            if not present:
                triage["status"] = "corrupt"
                triage["error"] = "none of the required tables exist: " + ", ".join(required)
                return triage
            for table in required:
                if table not in present:
                    warn(triage, f"missing table {table}")
            summary, samples, total_rows = body(conn, schema, triage)
    except Exception as exc:  # noqa: BLE001 — never let a parser exception escape
        triage.update(status="corrupt", summary=None, samples=[],
                      error=f"{type(exc).__name__}: {exc}")
        return triage
    triage["summary"] = summary
    triage["samples"] = samples[:sample_cap]
    triage["status"] = "empty" if total_rows == 0 else "parsed"
    return triage
