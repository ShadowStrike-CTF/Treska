# Treska parsers — Android logical artifact triage: mmssms.db, contacts2.db, calllog.db.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# SQL and field mapping only. Every open / count / sample / truncate / status helper
# comes from sqlite_triage (shared with ios.py) — never copied here.

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from treska.parsers.sqlite_triage import (
    SAMPLE_CAP,
    Schema,
    count_table,
    epoch_to_iso,
    fetch_rows,
    has,
    need_column,
    safe_count,
    safe_scalar,
    triage_sqlite,
    truncate,
    warn,
)

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# calls.type (CallLog.Calls.*_TYPE). Anything else counts as "other".
CALL_TYPES: dict[int, str] = {
    1: "incoming", 2: "outgoing", 3: "missed",
    4: "voicemail", 5: "rejected", 6: "blocked",
}
CALL_OTHER = "other"

# sms.type (Telephony.TextBasedSmsColumns.MESSAGE_TYPE_*).
SMS_INBOX = 1
SMS_SENT = 2

MIME_PHONE = "vnd.android.cursor.item/phone_v2"
MIME_EMAIL = "vnd.android.cursor.item/email_v2"


# --- timestamps: the unit is fixed by which function a column calls ----------

def unix_ms_to_iso(value: Any) -> str | None:
    """Convert Unix milliseconds to ISO 8601 UTC. 0 or None → None.
    For sms.date and calls.date. Never use for pdu.date — that column is seconds."""
    if value is None or isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        seconds = float(value) / 1000
    except (TypeError, ValueError):
        return None
    return epoch_to_iso(UNIX_EPOCH, seconds)


def unix_s_to_iso(value: Any) -> str | None:
    """Convert Unix seconds to ISO 8601 UTC. 0 or None → None. For pdu.date (MMS)."""
    return epoch_to_iso(UNIX_EPOCH, value)


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, (bytes, bytearray, memoryview, bool)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _call_label(value: Any) -> str:
    return CALL_TYPES.get(_int_or_none(value), CALL_OTHER)


def _calls_by_type(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]) -> dict[str, int] | None:
    """{type_label: count} for a `calls` table (calllog.db, or embedded in contacts2.db),
    in CALL_TYPES order then "other"; labels with no rows are left out."""
    if not need_column(schema, triage, "calls", "type"):
        return None
    counts: dict[str, int] = {}
    for call_type, n in fetch_rows(conn, triage, "SELECT type, COUNT(*) FROM calls GROUP BY type"):
        label = _call_label(call_type)
        counts[label] = counts.get(label, 0) + int(n)
    order = [*CALL_TYPES.values(), CALL_OTHER]
    return {label: counts[label] for label in order if label in counts}


# --- mmssms.db -------------------------------------------------------------

def _mmssms_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "total": count_table(conn, schema, "sms"),
        "inbox": None,
        "sent": None,
        "other": None,
        "mms_count": 0,
        "address_count": None,
        "first_message": None,
        "last_message": None,
        "first_mms": None,
        "last_mms": None,
    }
    has_type = need_column(schema, triage, "sms", "type")
    has_date = need_column(schema, triage, "sms", "date")
    has_address = need_column(schema, triage, "sms", "address")
    has_body = need_column(schema, triage, "sms", "body")

    if has_type:
        summary["inbox"] = safe_count(conn, "SELECT COUNT(*) FROM sms WHERE type = ?", (SMS_INBOX,))
        summary["sent"] = safe_count(conn, "SELECT COUNT(*) FROM sms WHERE type = ?", (SMS_SENT,))
        summary["other"] = safe_count(
            conn, "SELECT COUNT(*) FROM sms WHERE type IS NULL OR type NOT IN (?, ?)",
            (SMS_INBOX, SMS_SENT))
    if has_address:
        summary["address_count"] = safe_count(conn, "SELECT COUNT(DISTINCT address) FROM sms")
    if has_date:  # sms.date: Unix MILLISECONDS
        summary["first_message"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MIN(date) FROM sms WHERE date != 0"))
        summary["last_message"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MAX(date) FROM sms WHERE date != 0"))

    if has(schema, "pdu"):
        summary["mms_count"] = count_table(conn, schema, "pdu") or 0
        if need_column(schema, triage, "pdu", "date"):  # pdu.date: Unix SECONDS
            summary["first_mms"] = unix_s_to_iso(
                safe_scalar(conn, "SELECT MIN(date) FROM pdu WHERE date != 0"))
            summary["last_mms"] = unix_s_to_iso(
                safe_scalar(conn, "SELECT MAX(date) FROM pdu WHERE date != 0"))
    else:
        warn(triage, "missing table pdu")

    sql = (
        "SELECT "
        + ("date" if has_date else "NULL") + ", "
        + ("type" if has_type else "NULL") + ", "
        + ("address" if has_address else "NULL") + ", "
        + ("body" if has_body else "NULL")
        + " FROM sms ORDER BY " + ("date DESC, " if has_date else "") + "ROWID DESC LIMIT ?"
    )
    samples: list[dict] = []
    for date, sms_type, address, body in fetch_rows(conn, triage, sql, (SAMPLE_CAP,)):
        kind = _int_or_none(sms_type)
        samples.append({
            "time": unix_ms_to_iso(date),
            "direction": "received" if kind == SMS_INBOX else "sent" if kind == SMS_SENT else None,
            "address": truncate(address),
            "body": truncate(body),
        })

    return summary, samples, (summary["total"] or 0) + summary["mms_count"]


def parse_android_mmssms(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage mmssms.db. Required table: sms (pdu optional).
    Summary: total, inbox, sent, other, mms_count, address_count,
             first_message, last_message (sms.date, ms), first_mms, last_mms (pdu.date, s).
    Samples: up to SAMPLE_CAP most-recent SMS, each with time, direction, address, body."""
    return triage_sqlite(path, filename, "android_mmssms", ("sms",), _mmssms_body, work_dir)


# --- contacts2.db ----------------------------------------------------------

def _contacts_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "raw_contact_count": count_table(conn, schema, "raw_contacts"),
        "contact_count": count_table(conn, schema, "contacts"),
        "phone_count": None,
        "email_count": None,
        "embedded_calls": None,
    }
    if not has(schema, "contacts"):
        warn(triage, "missing table contacts")

    has_data = True
    for table in ("data", "mimetypes"):
        if not has(schema, table):
            warn(triage, f"missing table {table}")
            has_data = False
    if has_data:
        has_data = all([
            need_column(schema, triage, "data", "mimetype_id"),
            need_column(schema, triage, "data", "raw_contact_id"),
            need_column(schema, triage, "data", "data1"),
            need_column(schema, triage, "mimetypes", "_id"),
            need_column(schema, triage, "mimetypes", "mimetype"),
        ])
    by_mime = ("SELECT COUNT(*) FROM data d JOIN mimetypes m ON m._id = d.mimetype_id "
               "WHERE m.mimetype = ?")
    if has_data:
        summary["phone_count"] = safe_count(conn, by_mime, (MIME_PHONE,))
        summary["email_count"] = safe_count(conn, by_mime, (MIME_EMAIL,))

    if has(schema, "calls"):  # older Android keeps the call log inside contacts2.db
        summary["embedded_calls"] = {
            "count": count_table(conn, schema, "calls"),
            "types": _calls_by_type(conn, schema, triage),
        }

    has_name = need_column(schema, triage, "raw_contacts", "display_name")
    sql = ("SELECT ROWID, " + ("display_name" if has_name else "NULL")
           + " FROM raw_contacts ORDER BY ROWID LIMIT ?")
    samples: list[dict] = []
    for rowid, name in fetch_rows(conn, triage, sql, (SAMPLE_CAP,)):
        contact = None
        if has_data:
            contact = safe_scalar(
                conn,
                "SELECT d.data1 FROM data d JOIN mimetypes m ON m._id = d.mimetype_id "
                "WHERE d.raw_contact_id = ? AND m.mimetype IN (?, ?) "
                "ORDER BY m.mimetype = ? DESC, d.ROWID LIMIT 1",
                (rowid, MIME_PHONE, MIME_EMAIL, MIME_PHONE),
            )
        samples.append({
            "display_name": truncate(name),
            "first_phone_or_email": truncate(contact),
        })

    total = sum(summary[k] or 0 for k in ("raw_contact_count", "phone_count", "email_count"))
    if summary["embedded_calls"] is not None:
        total += summary["embedded_calls"]["count"] or 0
    return summary, samples, total


def parse_android_contacts(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage contacts2.db. Required table: raw_contacts.
    Summary: raw_contact_count, contact_count, phone_count, email_count (data JOIN
             mimetypes), embedded_calls (null, or {count, types} when a calls table exists).
    Samples: up to SAMPLE_CAP raw contacts, each with display_name, first_phone_or_email."""
    return triage_sqlite(path, filename, "android_contacts", ("raw_contacts",),
                         _contacts_body, work_dir)


# --- calllog.db ------------------------------------------------------------

def _calllog_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "total": count_table(conn, schema, "calls"),
        "by_type": _calls_by_type(conn, schema, triage),
        "total_duration_seconds": None,
        "first_call": None,
        "last_call": None,
    }
    has_type = has(schema, "calls", "type")  # warned by _calls_by_type
    has_date = need_column(schema, triage, "calls", "date")
    has_number = need_column(schema, triage, "calls", "number")
    has_duration = need_column(schema, triage, "calls", "duration")

    if has_duration:
        summary["total_duration_seconds"] = _int_or_none(
            safe_scalar(conn, "SELECT COALESCE(SUM(duration), 0) FROM calls"))
    if has_date:  # calls.date: Unix MILLISECONDS
        summary["first_call"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MIN(date) FROM calls WHERE date != 0"))
        summary["last_call"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MAX(date) FROM calls WHERE date != 0"))

    sql = (
        "SELECT "
        + ("date" if has_date else "NULL") + ", "
        + ("type" if has_type else "NULL") + ", "
        + ("number" if has_number else "NULL") + ", "
        + ("duration" if has_duration else "NULL")
        + " FROM calls ORDER BY " + ("date DESC, " if has_date else "") + "ROWID DESC LIMIT ?"
    )
    samples: list[dict] = []
    for date, call_type, number, duration in fetch_rows(conn, triage, sql, (SAMPLE_CAP,)):
        samples.append({
            "time": unix_ms_to_iso(date),
            "type": _call_label(call_type) if has_type else None,
            "number": truncate(number),
            "duration_seconds": _int_or_none(duration),
        })

    return summary, samples, summary["total"] or 0


def parse_android_calllog(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage calllog.db. Required table: calls.
    Summary: total, by_type (CALL_TYPES label → count, unknown → "other"),
             total_duration_seconds, first_call, last_call (calls.date, ms).
    Samples: up to SAMPLE_CAP most-recent calls,
             each with time, type, number, duration_seconds."""
    return triage_sqlite(path, filename, "android_calllog", ("calls",), _calllog_body, work_dir)


# Keyed by casefolded filename → (triage.format, parser). Dispatched from
# core.pipeline.triage_file only when extraction_type is ANDROID_LOGICAL and the
# file carries the SQLite header.
ANDROID_ARTIFACTS: dict[str, tuple[str, Callable[..., dict]]] = {
    "mmssms.db": ("android_mmssms", parse_android_mmssms),
    "contacts2.db": ("android_contacts", parse_android_contacts),
    "calllog.db": ("android_calllog", parse_android_calllog),
}
