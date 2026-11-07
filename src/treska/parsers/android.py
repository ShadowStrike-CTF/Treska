# Treska parsers — Android logical artifact triage: mmssms.db, contacts2.db, calllog.db,
# Chrome History, WhatsApp msgstore.db.
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
from urllib.parse import urlparse

from treska.parsers.sqlite_triage import (
    SAMPLE_CAP,
    Schema,
    count_map,
    count_table,
    epoch_to_iso,
    fetch_rows,
    folded_schema,
    has,
    need_column,
    open_evidence,
    ranked,
    result_skeleton,
    safe_count,
    safe_scalar,
    triage_sqlite,
    truncate,
    warn,
    whatsapp_record,
    whatsapp_summary,
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


# --- Phase 11: Chrome History ---------------------------------------------

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
CHROME_REQUIRED = ("urls", "visits")
# top_domains reads at most this many urls (most-visited first) — bounded, then
# hosts are extracted in Python. Never in SQL.
DOMAIN_ROW_CAP = 10_000


def webkit_us_to_iso(value: Any) -> str | None:
    """Convert WebKit/Chrome MICROSECONDS since 1601-01-01 UTC to ISO 8601 UTC.
    For visits.visit_time and urls.last_visit_time. 0 or None → None."""
    if value is None or isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        seconds = float(value) / 1_000_000
    except (TypeError, ValueError):
        return None
    return epoch_to_iso(WEBKIT_EPOCH, seconds)


def _url_host(url: str) -> str | None:
    try:
        return urlparse(url).netloc or None
    except ValueError:
        return None


def _chrome_body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
    summary: dict[str, Any] = {
        "url_count": count_table(conn, schema, "urls"),
        "visit_count": count_table(conn, schema, "visits"),
        "typed_count": None,
        "search_term_count": None,
        "top_domains": None,
        "first_visit": None,
        "last_visit": None,
    }
    urls = has(schema, "urls")
    visits = has(schema, "visits")
    searches = has(schema, "keyword_search_terms")
    if not searches:
        warn(triage, "missing table keyword_search_terms")

    has_id = urls and need_column(schema, triage, "urls", "id")
    has_url = urls and need_column(schema, triage, "urls", "url")
    has_title = urls and need_column(schema, triage, "urls", "title")
    has_typed = urls and need_column(schema, triage, "urls", "typed_count")
    has_last = urls and need_column(schema, triage, "urls", "last_visit_time")
    has_time = visits and need_column(schema, triage, "visits", "visit_time")
    has_link = visits and need_column(schema, triage, "visits", "url")
    join = has_id and has_link

    if has_typed:
        summary["typed_count"] = _int_or_none(
            safe_scalar(conn, "SELECT COALESCE(SUM(typed_count), 0) FROM urls"))
    if searches:
        summary["search_term_count"] = count_table(conn, schema, "keyword_search_terms")
    if join and has_url:
        summary["top_domains"] = ranked(count_map(
            conn, triage,
            "SELECT u.url, COUNT(*) AS n FROM visits v JOIN urls u ON u.id = v.url "
            "GROUP BY v.url ORDER BY n DESC, v.url ASC LIMIT ?",
            (DOMAIN_ROW_CAP,), key=_url_host), "domain")
    if has_time:  # visits.visit_time: WebKit MICROSECONDS
        summary["first_visit"] = webkit_us_to_iso(
            safe_scalar(conn, "SELECT MIN(visit_time) FROM visits WHERE visit_time != 0"))
        summary["last_visit"] = webkit_us_to_iso(
            safe_scalar(conn, "SELECT MAX(visit_time) FROM visits WHERE visit_time != 0"))

    samples: list[dict] = []
    if visits:
        sql = (
            "SELECT "
            + ("v.visit_time" if has_time else "NULL") + ", "
            + ("u.title" if join and has_title else "NULL") + ", "
            + ("u.url" if join and has_url else "NULL")
            + " FROM visits v"
            + (" LEFT JOIN urls u ON u.id = v.url" if join else "")
            + " ORDER BY " + ("v.visit_time DESC, " if has_time else "") + "v.ROWID DESC LIMIT ?"
        )
        for visit_time, title, url in fetch_rows(conn, triage, sql, (SAMPLE_CAP,)):
            samples.append({"kind": "visit", "time": webkit_us_to_iso(visit_time),
                            "title": truncate(title), "url": truncate(url), "term": None})
    if searches and need_column(schema, triage, "keyword_search_terms", "term"):
        search_join = has_id and need_column(schema, triage, "keyword_search_terms", "url_id")
        sql = (
            "SELECT "
            + ("u.last_visit_time" if search_join and has_last else "NULL") + ", "
            + ("u.title" if search_join and has_title else "NULL") + ", "
            + ("u.url" if search_join and has_url else "NULL") + ", k.term"
            + " FROM keyword_search_terms k"
            + (" LEFT JOIN urls u ON u.id = k.url_id" if search_join else "")
            + " ORDER BY " + ("u.last_visit_time DESC, " if search_join and has_last else "")
            + "k.ROWID DESC LIMIT ?"
        )
        for last_visit, title, url, term in fetch_rows(conn, triage, sql, (SAMPLE_CAP,)):
            samples.append({"kind": "search", "time": webkit_us_to_iso(last_visit),
                            "title": truncate(title), "url": truncate(url), "term": truncate(term)})

    total = sum(summary[k] or 0 for k in ("url_count", "visit_count", "search_term_count"))
    return summary, samples, total


def parse_android_chrome(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage Chrome History. Required tables: urls, visits (keyword_search_terms optional).
    Summary: url_count, visit_count, typed_count (SUM urls.typed_count), search_term_count,
             top_domains [{domain, count}] (TOP_N, host via urlparse in Python),
             first_visit, last_visit (visits.visit_time, WebKit µs).
    Samples (Q2): up to SAMPLE_CAP visits + up to SAMPLE_CAP search terms, uniform keys
             kind, time, title, url, term.
    History is a generic name: core.pipeline skips (None) a non-SQLite file or one
    missing either required table before this parser is called."""
    return triage_sqlite(path, filename, "android_chrome", CHROME_REQUIRED, _chrome_body,
                         work_dir, sample_cap=2 * SAMPLE_CAP)


# --- Phase 12: WhatsApp msgstore.db (+ optional sibling wa.db) ---------------

WHATSAPP_MODERN = ("message", "chat", "jid")
WHATSAPP_LEGACY = ("messages",)
# Either complete set claims msgstore.db (core.pipeline generic-name pre-check).
WHATSAPP_ALTERNATIVES = (WHATSAPP_MODERN, WHATSAPP_LEGACY)
WA_DB_NAME = "wa.db"          # sibling contact-name source — never dispatched itself
WA_NAME_CAP = 50_000          # max wa_contacts rows read into the name map
LEGACY_SYSTEM_JID = "-1"      # legacy messages.key_remote_jid placeholder row


def _col(schema: Schema, triage: dict[str, Any], table: str, column: str, expr: str) -> str:
    """expr when table.column exists, else "NULL" (with a missing-column warning)."""
    return expr if need_column(schema, triage, table, column) else "NULL"


def _drop_missing_table_warnings(triage: dict[str, Any], tables: tuple[str, ...]) -> None:
    """triage_sqlite warns for every absent required table; the layout not in use
    is not missing, so its warnings are removed."""
    unused = {f"missing table {t}" for t in tables}
    triage["warnings"][:] = [w for w in triage["warnings"] if w not in unused]


def _wa_names(db_path: Path, work_dir: Path | None, triage: dict[str, Any]) -> dict[str, str]:
    """{jid: display_name} from a wa.db sitting beside msgstore.db (casefolded name).

    Opened through open_evidence (read-only; Phase 9 Option A WAL rule). Absent,
    unreadable, or no wa_contacts -> warning + {} — msgstore.db never fails on wa.db.
    """
    try:
        sibling = next((p for p in Path(db_path).parent.iterdir()
                        if p.name.casefold() == WA_DB_NAME and p.is_file()), None)
    except OSError:
        sibling = None
    if sibling is None:
        warn(triage, "wa.db not found beside msgstore.db; contact names not resolved")
        return {}
    scratch = result_skeleton(sibling.name, "wa_db")
    rows: list[tuple] = []
    try:
        with open_evidence(sibling, work_dir, scratch) as conn:
            schema = folded_schema(conn)
            if not (has(schema, "wa_contacts", "jid") and has(schema, "wa_contacts", "display_name")):
                warn(triage, "wa.db has no wa_contacts(jid, display_name); contact names not resolved")
                return {}
            rows = conn.execute(
                "SELECT jid, display_name FROM wa_contacts "
                "WHERE jid IS NOT NULL AND display_name IS NOT NULL LIMIT ?", (WA_NAME_CAP,)
            ).fetchall()
    except Exception as exc:  # noqa: BLE001 — wa.db must never fail msgstore.db
        warn(triage, f"wa.db unreadable ({type(exc).__name__}: {exc}); contact names not resolved")
        return {}
    for message in scratch["warnings"]:
        warn(triage, f"wa.db: {message}")
    return {jid: name for jid, name in rows if isinstance(jid, str) and isinstance(name, str)}


def _whatsapp_modern(conn, schema, triage, summary) -> list[tuple]:
    """message JOIN chat JOIN jid. Returns sample rows (timestamp, from_me, jid, body)."""
    msg = "message"
    from_me = _col(schema, triage, msg, "from_me", "m.from_me")
    ts = _col(schema, triage, msg, "timestamp", "m.timestamp")
    text = _col(schema, triage, msg, "text_data", "m.text_data")
    has_type = need_column(schema, triage, msg, "message_type")
    join = all([
        need_column(schema, triage, msg, "chat_row_id"),
        need_column(schema, triage, "chat", "_id"),
        need_column(schema, triage, "chat", "jid_row_id"),
        need_column(schema, triage, "jid", "_id"),
        need_column(schema, triage, "jid", "raw_string"),
    ])

    summary["message_count"] = count_table(conn, schema, msg)
    summary["chat_count"] = count_table(conn, schema, "chat")
    if from_me != "NULL":
        summary["sent_count"] = safe_count(conn, "SELECT COUNT(*) FROM message WHERE from_me = 1")
        summary["received_count"] = safe_count(conn, "SELECT COUNT(*) FROM message WHERE from_me = 0")
    if text != "NULL":
        if has_type:  # message_type 0 = text (unconfirmed — see CLAUDE.md)
            summary["media_only_count"] = safe_count(
                conn, "SELECT COUNT(*) FROM message WHERE text_data IS NULL AND message_type != 0")
        else:
            warn(triage, "media_only_count counts every NULL text_data (no message_type column)")
            summary["media_only_count"] = safe_count(
                conn, "SELECT COUNT(*) FROM message WHERE text_data IS NULL")
    if join:
        summary["group_chat_count"] = safe_count(
            conn, "SELECT COUNT(*) FROM chat c JOIN jid j ON j._id = c.jid_row_id "
                  "WHERE j.raw_string LIKE '%@g.us'")
    if ts != "NULL":  # message.timestamp: Unix MILLISECONDS
        summary["first_message"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MIN(timestamp) FROM message WHERE timestamp != 0"))
        summary["last_message"] = unix_ms_to_iso(
            safe_scalar(conn, "SELECT MAX(timestamp) FROM message WHERE timestamp != 0"))

    sql = (
        f"SELECT {ts}, {from_me}, " + ("j.raw_string" if join else "NULL") + f", {text}"
        " FROM message m"
        + (" LEFT JOIN chat c ON c._id = m.chat_row_id LEFT JOIN jid j ON j._id = c.jid_row_id"
           if join else "")
        + " ORDER BY " + ("m.timestamp DESC, " if ts != "NULL" else "") + "m.ROWID DESC LIMIT ?"
    )
    return fetch_rows(conn, triage, sql, (SAMPLE_CAP,))


def _whatsapp_legacy(conn, schema, triage, summary) -> list[tuple]:
    """Legacy `messages` table; key_remote_jid '-1' rows are system rows, skipped."""
    tbl = "messages"
    has_jid = need_column(schema, triage, tbl, "key_remote_jid")
    from_me = _col(schema, triage, tbl, "key_from_me", "key_from_me")
    ts = _col(schema, triage, tbl, "timestamp", "timestamp")
    text = _col(schema, triage, tbl, "data", "data")
    has_type = need_column(schema, triage, tbl, "media_wa_type")
    where = "(key_remote_jid IS NULL OR key_remote_jid != ?)" if has_jid else "1"
    params = (LEGACY_SYSTEM_JID,) if has_jid else ()

    def count(extra: str) -> int | None:
        return safe_count(conn, f"SELECT COUNT(*) FROM messages WHERE {where}{extra}", params)

    summary["message_count"] = count("")
    if from_me != "NULL":
        summary["sent_count"] = count(" AND key_from_me = 1")
        summary["received_count"] = count(" AND key_from_me = 0")
    if text != "NULL":
        if has_type:  # media_wa_type 0 = text (unconfirmed — see CLAUDE.md)
            summary["media_only_count"] = count(" AND data IS NULL AND media_wa_type != 0")
        else:
            warn(triage, "media_only_count counts every NULL data (no media_wa_type column)")
            summary["media_only_count"] = count(" AND data IS NULL")
    if has_jid:
        summary["chat_count"] = safe_count(
            conn, "SELECT COUNT(DISTINCT key_remote_jid) FROM messages WHERE key_remote_jid != ?",
            params)
        summary["group_chat_count"] = safe_count(
            conn, "SELECT COUNT(DISTINCT key_remote_jid) FROM messages "
                  "WHERE key_remote_jid != ? AND key_remote_jid LIKE '%@g.us'", params)
    if ts != "NULL":  # messages.timestamp: Unix MILLISECONDS
        summary["first_message"] = unix_ms_to_iso(safe_scalar(
            conn, f"SELECT MIN(timestamp) FROM messages WHERE {where} AND timestamp != 0", params))
        summary["last_message"] = unix_ms_to_iso(safe_scalar(
            conn, f"SELECT MAX(timestamp) FROM messages WHERE {where} AND timestamp != 0", params))

    sql = (
        f"SELECT {ts}, {from_me}, " + ("key_remote_jid" if has_jid else "NULL") + f", {text}"
        f" FROM messages WHERE {where} ORDER BY "
        + ("timestamp DESC, " if ts != "NULL" else "") + "ROWID DESC LIMIT ?"
    )
    return fetch_rows(conn, triage, sql, (*params, SAMPLE_CAP))


def _whatsapp_body_for(path: Path, work_dir: Path | None):
    def body(conn: sqlite3.Connection, schema: Schema, triage: dict[str, Any]):
        modern = all(has(schema, t) for t in WHATSAPP_MODERN)
        legacy = has(schema, "messages")
        if modern or not legacy:
            # Modern layout (or a partial one: its missing-table warnings stay).
            _drop_missing_table_warnings(triage, WHATSAPP_LEGACY)
            summary = whatsapp_summary("modern")
            rows = _whatsapp_modern(conn, schema, triage, summary) if has(schema, "message") else []
        else:
            _drop_missing_table_warnings(triage, WHATSAPP_MODERN)
            summary = whatsapp_summary("legacy")
            rows = _whatsapp_legacy(conn, schema, triage, summary)

        names = _wa_names(path, work_dir, triage)
        summary["contact_names_resolved"] = bool(names)
        samples = [
            whatsapp_record(timestamp=unix_ms_to_iso(ts), from_me=from_me, jid=jid,
                            contact_name=names.get(jid) if isinstance(jid, str) else None,
                            body=text, platform="android")
            for ts, from_me, jid, text in rows
        ]
        return summary, samples, summary["message_count"] or 0
    return body


def parse_android_whatsapp(path: Path, filename: str, work_dir: Path | None = None) -> dict:
    """Triage WhatsApp msgstore.db. Required: the modern set (message, chat, jid) OR the
    legacy messages table. Contact names from a sibling wa.db (wa_contacts), optional.
    Summary: the 10-key WhatsApp summary (schema_layout "modern" / "legacy").
    Samples: up to SAMPLE_CAP most-recent messages as whatsapp_record() 8-key records.
    msgstore.db is a generic name: core.pipeline skips (None) a file with neither
    complete table set before this parser is called."""
    return triage_sqlite(path, filename, "android_whatsapp", (*WHATSAPP_MODERN, *WHATSAPP_LEGACY),
                         _whatsapp_body_for(Path(path), work_dir), work_dir)


# Keyed by casefolded filename → (triage.format, parser). Dispatched from
# core.pipeline.triage_file only when extraction_type is ANDROID_LOGICAL and the
# file carries the SQLite header.
ANDROID_ARTIFACTS: dict[str, tuple[str, Callable[..., dict]]] = {
    "mmssms.db": ("android_mmssms", parse_android_mmssms),
    "contacts2.db": ("android_contacts", parse_android_contacts),
    "calllog.db": ("android_calllog", parse_android_calllog),
    "history": ("android_chrome", parse_android_chrome),  # generic name — see pipeline
    "msgstore.db": ("android_whatsapp", parse_android_whatsapp),  # generic name — see pipeline
}
