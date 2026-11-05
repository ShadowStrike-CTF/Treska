# Treska parsers — iOS FFS artifact triage: sms.db, KnowledgeC.db, AddressBook.sqlitedb.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import math
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from treska.parsers.sqlite_triage import (
    SAMPLE_CAP,
    TOP_N,
    folded_schema,
    open_evidence,
    result_skeleton,
    safe_count,
    safe_scalar,
    truncate,
    warn,
)

COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
# Cocoa timestamps above this are nanoseconds (iOS 11+ sms.db), not seconds.
NANOSECOND_THRESHOLD = 1e11

APP_USAGE_STREAM = "/app/usage"
# AddressBook ABMultiValue.property values.
AB_PHONE = 3
AB_EMAIL = 4

Schema = dict[str, set[str]]
Body = Callable[[sqlite3.Connection, Schema, dict[str, Any]], tuple[dict[str, Any], list[dict], int]]


def apple_to_iso(value: Any) -> str | None:
    """Convert Apple Cocoa epoch to ISO 8601 UTC.
    Cocoa epoch: seconds since 2001-01-01.
    Values > 1e11 treated as nanoseconds (iOS 11+).
    0 or None → None."""
    if value is None or isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds == 0 or not math.isfinite(seconds):
        return None
    if abs(seconds) > NANOSECOND_THRESHOLD:
        seconds /= 1e9
    try:
        return (COCOA_EPOCH + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def _has(schema: Schema, table: str, column: str | None = None) -> bool:
    cols = schema.get(table.casefold())
    if cols is None:
        return False
    return column is None or column.casefold() in cols


def _need_column(schema: Schema, triage: dict[str, Any], table: str, column: str) -> bool:
    """True if table.column exists; else record a warning (table assumed present)."""
    if _has(schema, table, column):
        return True
    warn(triage, f"missing column {table}.{column}")
    return False


def _count(conn: sqlite3.Connection, schema: Schema, table: str) -> int | None:
    if not _has(schema, table):
        return None
    return safe_count(conn, f"SELECT COUNT(*) FROM {table}")


def _rows(conn: sqlite3.Connection, triage: dict[str, Any], sql: str, params: tuple = ()) -> list[tuple]:
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error as exc:
        warn(triage, f"query failed ({type(exc).__name__}: {exc})")
        return []


def _triage_sqlite(
    path: Path,
    filename: str,
    fmt: str,
    required: tuple[str, ...],
    body: Body,
    work_dir: Path | None,
) -> dict[str, Any]:
    """Shared frame: open (WAL-aware, read-only), check required tables, run body.

    status: corrupt = can't open / none of the required tables exist;
    empty = body reports zero rows; parsed otherwise. Never raises.
    """
    triage = result_skeleton(filename, fmt)
    try:
        with open_evidence(Path(path), work_dir, triage) as conn:
            schema = folded_schema(conn)
            present = [t for t in required if _has(schema, t)]
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
    triage["samples"] = samples[:SAMPLE_CAP]
    triage["status"] = "empty" if total_rows == 0 else "parsed"
    return triage


# --- sms.db ----------------------------------------------------------------

def _sms_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "message_count": _count(conn, schema, "message"),
        "sent_count": None,
        "received_count": None,
        "chat_count": _count(conn, schema, "chat"),
        "handle_count": _count(conn, schema, "handle"),
        "attachment_count": _count(conn, schema, "attachment"),
        "first_message": None,
        "last_message": None,
    }
    if not _has(schema, "attachment"):
        warn(triage, "missing table attachment")

    samples: list[dict] = []
    if _has(schema, "message"):
        has_from_me = _need_column(schema, triage, "message", "is_from_me")
        has_date = _need_column(schema, triage, "message", "date")
        has_text = _need_column(schema, triage, "message", "text")
        has_handle_id = _need_column(schema, triage, "message", "handle_id")
        if has_from_me:
            summary["sent_count"] = safe_count(
                conn, "SELECT COUNT(*) FROM message WHERE is_from_me = 1")
            summary["received_count"] = safe_count(
                conn, "SELECT COUNT(*) FROM message WHERE COALESCE(is_from_me, 0) != 1")
        if has_date:
            summary["first_message"] = apple_to_iso(
                safe_scalar(conn, "SELECT MIN(date) FROM message WHERE date != 0"))
            summary["last_message"] = apple_to_iso(
                safe_scalar(conn, "SELECT MAX(date) FROM message WHERE date != 0"))

        join_handle = has_handle_id and _has(schema, "handle", "id")
        sql = (
            "SELECT "
            + ("m.date" if has_date else "NULL") + ", "
            + ("m.is_from_me" if has_from_me else "NULL") + ", "
            + ("h.id" if join_handle else "NULL") + ", "
            + ("m.text" if has_text else "NULL")
            + " FROM message m"
            + (" LEFT JOIN handle h ON h.ROWID = m.handle_id" if join_handle else "")
            + " ORDER BY " + ("m.date DESC, " if has_date else "") + "m.ROWID DESC"
            + " LIMIT ?"
        )
        for date, from_me, handle, text in _rows(conn, triage, sql, (SAMPLE_CAP,)):
            direction = None
            if has_from_me:
                direction = "sent" if from_me == 1 else "received"
            samples.append({
                "time": apple_to_iso(date),
                "direction": direction,
                "handle": truncate(handle),
                "text": truncate(text),
            })

    total = sum(summary[k] or 0 for k in ("message_count", "chat_count", "handle_count"))
    return summary, samples, total


def parse_ios_sms(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage sms.db. Required tables: message, handle, chat.
    Summary: message_count, sent_count, received_count, chat_count,
             handle_count, attachment_count, first_message, last_message.
    Samples: up to SAMPLE_CAP most-recent messages (time DESC),
             each with time, direction (sent/received), handle, text (truncated)."""
    return _triage_sqlite(path, filename, "ios_sms", ("message", "handle", "chat"),
                          _sms_body, work_dir)


# --- KnowledgeC.db ---------------------------------------------------------

def _knowledgec_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "total_rows": _count(conn, schema, "ZOBJECT"),
        "stream_counts": None,
        "top_bundles": None,
        "first_event": None,
        "last_event": None,
    }
    has_stream = _need_column(schema, triage, "ZOBJECT", "ZSTREAMNAME")
    has_value = _need_column(schema, triage, "ZOBJECT", "ZVALUESTRING")
    has_start = _need_column(schema, triage, "ZOBJECT", "ZSTARTDATE")
    has_end = _need_column(schema, triage, "ZOBJECT", "ZENDDATE")

    if has_stream:
        summary["stream_counts"] = [
            {"stream": truncate(stream), "count": int(n)}
            for stream, n in _rows(conn, triage,
                "SELECT ZSTREAMNAME, COUNT(*) AS n FROM ZOBJECT GROUP BY ZSTREAMNAME "
                "ORDER BY n DESC, ZSTREAMNAME ASC LIMIT ?", (TOP_N,))
        ]
    if has_stream and has_value:
        summary["top_bundles"] = [
            {"bundle_id": truncate(bundle), "count": int(n)}
            for bundle, n in _rows(conn, triage,
                "SELECT ZVALUESTRING, COUNT(*) AS n FROM ZOBJECT WHERE ZSTREAMNAME = ? "
                "GROUP BY ZVALUESTRING ORDER BY n DESC, ZVALUESTRING ASC LIMIT ?",
                (APP_USAGE_STREAM, TOP_N))
        ]
    if has_start:
        summary["first_event"] = apple_to_iso(
            safe_scalar(conn, "SELECT MIN(ZSTARTDATE) FROM ZOBJECT WHERE ZSTARTDATE != 0"))
        summary["last_event"] = apple_to_iso(
            safe_scalar(conn, "SELECT MAX(ZSTARTDATE) FROM ZOBJECT WHERE ZSTARTDATE != 0"))

    samples: list[dict] = []
    if has_stream:
        sql = (
            "SELECT "
            + ("ZVALUESTRING" if has_value else "NULL") + ", "
            + ("ZSTARTDATE" if has_start else "NULL") + ", "
            + ("ZENDDATE" if has_end else "NULL")
            + " FROM ZOBJECT WHERE ZSTREAMNAME = ? ORDER BY "
            + ("ZSTARTDATE DESC, " if has_start else "") + "ROWID DESC LIMIT ?"
        )
        for bundle, start, end in _rows(conn, triage, sql, (APP_USAGE_STREAM, SAMPLE_CAP)):
            samples.append({
                "bundle_id": truncate(bundle),
                "start": apple_to_iso(start),
                "end": apple_to_iso(end),
            })

    return summary, samples, summary["total_rows"] or 0


def parse_ios_knowledgec(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage KnowledgeC.db. Required table: ZOBJECT.
    Summary: total_rows, stream_counts (top TOP_N by ZSTREAMNAME),
             top_bundles (top TOP_N /app/usage bundle IDs), first_event, last_event.
    Samples: up to SAMPLE_CAP most-recent /app/usage rows,
             each with bundle_id, start (ZSTARTDATE), end (ZENDDATE)."""
    return _triage_sqlite(path, filename, "ios_knowledgec", ("ZOBJECT",),
                          _knowledgec_body, work_dir)


# --- AddressBook.sqlitedb --------------------------------------------------

def _addressbook_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "person_count": _count(conn, schema, "ABPerson"),
        "phone_count": None,
        "email_count": None,
    }
    has_mv = _has(schema, "ABMultiValue")
    if not has_mv:
        warn(triage, "missing table ABMultiValue")
    else:
        has_mv = all([
            _need_column(schema, triage, "ABMultiValue", "record_id"),
            _need_column(schema, triage, "ABMultiValue", "property"),
            _need_column(schema, triage, "ABMultiValue", "value"),
        ])
    if has_mv:
        summary["phone_count"] = safe_count(
            conn, "SELECT COUNT(*) FROM ABMultiValue WHERE property = ?", (AB_PHONE,))
        summary["email_count"] = safe_count(
            conn, "SELECT COUNT(*) FROM ABMultiValue WHERE property = ?", (AB_EMAIL,))

    names = {col: _need_column(schema, triage, "ABPerson", col)
             for col in ("First", "Last", "Organization")}
    sql = (
        "SELECT ROWID, "
        + ", ".join(col if ok else "NULL" for col, ok in names.items())
        + " FROM ABPerson ORDER BY ROWID LIMIT ?"
    )
    samples: list[dict] = []
    for rowid, first, last, org in _rows(conn, triage, sql, (SAMPLE_CAP,)):
        contact = None
        if has_mv:
            contact = safe_scalar(
                conn,
                "SELECT value FROM ABMultiValue WHERE record_id = ? AND property IN (?, ?) "
                "ORDER BY property, ROWID LIMIT 1",
                (rowid, AB_PHONE, AB_EMAIL),
            )
        samples.append({
            "first_name": truncate(first),
            "last_name": truncate(last),
            "organization": truncate(org),
            "first_phone_or_email": truncate(contact),
        })

    total = (summary["person_count"] or 0) + (summary["phone_count"] or 0) + (summary["email_count"] or 0)
    return summary, samples, total


def parse_ios_addressbook(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage AddressBook.sqlitedb. Required table: ABPerson.
    Summary: person_count, phone_count, email_count.
    Samples: up to SAMPLE_CAP persons,
             each with first_name, last_name, organization, first_phone_or_email."""
    return _triage_sqlite(path, filename, "ios_addressbook", ("ABPerson",),
                          _addressbook_body, work_dir)


# Keyed by casefolded filename → (triage.format, parser). Dispatched from
# core.pipeline.triage_file only when extraction_type is IOS_FFS and the file
# carries the SQLite header.
IOS_ARTIFACTS: dict[str, tuple[str, Callable[..., dict]]] = {
    "sms.db": ("ios_sms", parse_ios_sms),
    "knowledgec.db": ("ios_knowledgec", parse_ios_knowledgec),
    "addressbook.sqlitedb": ("ios_addressbook", parse_ios_addressbook),
}
