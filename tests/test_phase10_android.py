# Treska Phase 10 — Android logical artifact triage (mmssms.db, contacts2.db, calllog.db).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic databases only, built in tmp_path with the real AOSP table and column
# names (DDL shared with tests/fixtures/make_android_fixture.py).

from __future__ import annotations

import hashlib
import importlib.util
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from treska.core.ingestion import cleanup
from treska.core.pipeline import parse_zip, triage_file
from treska.parsers.android import (
    ANDROID_ARTIFACTS,
    parse_android_calllog,
    parse_android_contacts,
    parse_android_mmssms,
    unix_ms_to_iso,
    unix_s_to_iso,
)
from treska.parsers.sqlite_triage import SAMPLE_CAP, TEXT_CAP, WAL_DIR

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_spec = importlib.util.spec_from_file_location(
    "make_android_fixture", FIXTURES / "make_android_fixture.py")
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

UTC = timezone.utc
FIRST = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
LAST = datetime(2024, 6, 7, 8, 9, 10, tzinfo=UTC)
FIRST_ISO = "2024-01-02T03:04:05Z"
LAST_ISO = "2024-06-07T08:09:10Z"


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _zip(tmp_path: Path, members: dict[str, bytes]) -> Path:
    zip_path = tmp_path / "case.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return zip_path


def _mmssms(path: Path, rows) -> Path:
    return fx.make_db(path, fx.MMSSMS_DDL, rows)


def _contacts(path: Path, rows, *, with_calls: bool = False) -> Path:
    ddl = fx.CONTACTS_DDL + (fx.CALLS_DDL if with_calls else "")
    return fx.make_db(path, ddl, [*fx.mimetype_rows(), *rows])


# --- mmssms.db -------------------------------------------------------------

def test_mmssms_sms_counts_by_type(tmp_path):
    ms = fx.unix_ms(FIRST)
    db = _mmssms(tmp_path / "mmssms.db", [
        fx.sms(1, "+15550100", ms, 1, "in 1"),
        fx.sms(2, "+15550100", ms, 1, "in 2"),
        fx.sms(3, "+15550101", ms, 2, "out"),
        fx.sms(4, "+15550102", ms, 3, "draft"),
        fx.sms(5, "+15550102", ms, 5, "failed"),
        ("INSERT INTO sms (_id, address, date, type, body) VALUES (6, NULL, ?, NULL, 'x')", (ms,)),
    ])
    t = parse_android_mmssms(db, "mmssms.db")
    assert t["format"] == "android_mmssms"
    assert t["status"] == "parsed"
    assert t["error"] is None and t["warnings"] == []
    assert t["wal_present"] is False and t["wal_applied"] is False
    s = t["summary"]
    assert (s["total"], s["inbox"], s["sent"], s["other"]) == (6, 2, 1, 3)
    assert s["address_count"] == 3  # COUNT(DISTINCT) ignores NULL


def test_mmssms_mms_count(tmp_path):
    db = _mmssms(tmp_path / "mmssms.db", [
        fx.sms(1, "+15550100", fx.unix_ms(FIRST), 1, "hi"),
        *[fx.pdu(i, fx.unix_s(FIRST) + i, msg_box=1 + i % 2) for i in range(1, 5)],
        fx.part(1, 1, "image/jpeg", "/data/user_de/0/no/such/PART_1"),  # never followed
    ])
    s = parse_android_mmssms(db, "mmssms.db")["summary"]
    assert s["mms_count"] == 4
    # No pdu table: mms_count 0 (not null), MMS times null, and a warning.
    ddl = "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT);"
    db2 = fx.make_db(tmp_path / "sms_only" / "mmssms.db", ddl, [
        ("INSERT INTO sms VALUES (1, '+15550100', ?, 1, 'hi')", (fx.unix_ms(FIRST),)),
    ])
    t = parse_android_mmssms(db2, "mmssms.db")
    assert t["status"] == "parsed"
    assert t["summary"]["mms_count"] == 0
    assert t["summary"]["first_mms"] is None and t["summary"]["last_mms"] is None
    assert "missing table pdu" in t["warnings"]


def test_mmssms_epoch_seconds_vs_ms(tmp_path):
    """INV-P10-1: sms.date is Unix ms, pdu.date is Unix seconds — each column's
    unit is fixed in code, so both land on the same wall-clock instants."""
    db = _mmssms(tmp_path / "mmssms.db", [
        fx.sms(1, "a", fx.unix_ms(LAST), 1, "late"),
        fx.sms(2, "a", fx.unix_ms(FIRST), 2, "early"),
        fx.pdu(1, fx.unix_s(LAST)),
        fx.pdu(2, fx.unix_s(FIRST)),
    ])
    s = parse_android_mmssms(db, "mmssms.db")["summary"]
    assert (s["first_message"], s["last_message"]) == (FIRST_ISO, LAST_ISO)
    assert (s["first_mms"], s["last_mms"]) == (FIRST_ISO, LAST_ISO)
    # The converters agree on the instant only when fed their own unit.
    assert unix_ms_to_iso(fx.unix_ms(FIRST)) == unix_s_to_iso(fx.unix_s(FIRST)) == FIRST_ISO
    assert unix_ms_to_iso(fx.unix_s(FIRST)) != FIRST_ISO  # seconds read as ms → 1970
    assert unix_s_to_iso(fx.unix_ms(FIRST)) != FIRST_ISO  # ms read as seconds → out of range
    for convert in (unix_ms_to_iso, unix_s_to_iso):
        assert convert(0) is None and convert(None) is None and convert(b"\x00") is None


def test_mmssms_samples_capped_recent_truncated(tmp_path):
    base = fx.unix_ms(FIRST)
    order = [3, 7, 0, 9, 5, 1, 8, 2, 6, 4]  # out of date order: the sort decides
    long_body = "B" * 1000
    rows = [
        fx.sms(i + 1, "+15550100", base + n * 60_000, 1 + n % 2,
               long_body if n == 9 else f"msg {n}")
        for i, n in enumerate(order)
    ]
    t = parse_android_mmssms(_mmssms(tmp_path / "mmssms.db", rows), "mmssms.db")
    assert t["summary"]["total"] == 10
    assert len(t["samples"]) == SAMPLE_CAP == 3
    assert [x["body"] for x in t["samples"]] == [long_body[:TEXT_CAP], "msg 8", "msg 7"]
    assert len(t["samples"][0]["body"]) == TEXT_CAP == 200
    times = [x["time"] for x in t["samples"]]
    assert times == sorted(times, reverse=True)
    assert [x["direction"] for x in t["samples"]] == ["sent", "received", "sent"]
    assert all(x["address"] == "+15550100" for x in t["samples"])


def test_mmssms_empty(tmp_path):
    t = parse_android_mmssms(_mmssms(tmp_path / "mmssms.db", []), "mmssms.db")
    assert t["status"] == "empty"
    assert t["error"] is None
    s = t["summary"]
    assert (s["total"], s["inbox"], s["sent"], s["other"], s["mms_count"]) == (0, 0, 0, 0, 0)
    assert s["first_message"] is None and s["first_mms"] is None
    assert t["samples"] == []


def test_mmssms_not_sqlite_corrupt(tmp_path):
    junk = os.urandom(4096)
    fake_header = b"SQLite format 3\x00" + os.urandom(4080)
    zip_path = _zip(tmp_path, {
        "data/data/com.android.providers.telephony/databases/mmssms.db": junk,
        "data/data/com.android.providers.contacts/databases/contacts2.db": fake_header,
    })
    result = parse_zip(zip_path)  # must not raise
    assert result.extraction_type == "ANDROID_LOGICAL"
    by_name = {Path(e.path).name: e.triage for e in result.inventory}
    mms = by_name["mmssms.db"]
    assert mms["format"] == "android_mmssms" and mms["status"] == "corrupt"
    assert mms["error"] == "not a SQLite database"
    assert mms["summary"] is None and mms["samples"] == []
    contacts = by_name["contacts2.db"]
    assert contacts["format"] == "android_contacts" and contacts["status"] == "corrupt"
    assert contacts["error"]
    # A direct parser call on garbage reports corrupt rather than raising.
    (tmp_path / "raw.db").write_bytes(junk)
    assert parse_android_mmssms(tmp_path / "raw.db", "raw.db")["status"] == "corrupt"


# --- contacts2.db ----------------------------------------------------------

def test_contacts_counts_via_mimetypes(tmp_path):
    # mimetypes._id differs per device: the counts must join on the mimetype name.
    ddl = fx.CONTACTS_DDL
    db = fx.make_db(tmp_path / "contacts2.db", ddl, [
        ("INSERT INTO mimetypes (_id, mimetype) VALUES (11, ?)", (fx.MIME_PHONE,)),
        ("INSERT INTO mimetypes (_id, mimetype) VALUES (12, ?)", (fx.MIME_EMAIL,)),
        ("INSERT INTO mimetypes (_id, mimetype) VALUES (13, ?)", (fx.MIME_NAME,)),
        fx.raw_contact(1, "Ana"), fx.raw_contact(2, "Ivo"),
        fx.contact(1, 1), fx.contact(2, 2),
        *[("INSERT INTO data (_id, mimetype_id, raw_contact_id, data1) VALUES (?, ?, ?, ?)", r)
          for r in [(1, 11, 1, "+1"), (2, 11, 1, "+2"), (3, 11, 2, "+3"),
                    (4, 12, 1, "a@x"), (5, 12, 2, "i@x"), (6, 13, 1, "Ana")]],
    ])
    t = parse_android_contacts(db, "contacts2.db")
    assert t["format"] == "android_contacts" and t["status"] == "parsed"
    assert t["warnings"] == []
    assert t["summary"] == {
        "raw_contact_count": 2, "contact_count": 2,
        "phone_count": 3, "email_count": 2, "embedded_calls": None,
    }


def test_contacts_samples(tmp_path):
    db = _contacts(tmp_path / "contacts2.db", [
        fx.raw_contact(1, "Ana Petrova"),
        fx.raw_contact(2, "Harbour Freight"),
        fx.raw_contact(3, None),
        fx.raw_contact(4, "Late Entry"),
        fx.data(1, 1, fx.MIME_EMAIL, "ana@example.org"),
        fx.data(2, 1, fx.MIME_PHONE, "+15550100"),
        fx.data(3, 2, fx.MIME_EMAIL, "ops@harbour.example"),
        fx.data(4, 3, fx.MIME_NAME, "not a phone or email"),
    ])
    t = parse_android_contacts(db, "contacts2.db")
    assert t["samples"] == [
        {"display_name": "Ana Petrova", "first_phone_or_email": "+15550100"},  # phone first
        {"display_name": "Harbour Freight", "first_phone_or_email": "ops@harbour.example"},
        {"display_name": None, "first_phone_or_email": None},
    ]
    assert "missing table contacts" not in t["warnings"]


def test_contacts_embedded_calls_table(tmp_path):
    ms = fx.unix_ms(FIRST)
    db = _contacts(tmp_path / "contacts2.db", [
        fx.raw_contact(1, "Ana"),
        fx.call(1, "+15550100", ms, 10, 1),
        fx.call(2, "+15550100", ms, 20, 1),
        fx.call(3, "+15550101", ms, 0, 3),
        fx.call(4, "+15550102", ms, 0, 42),
    ], with_calls=True)
    t = parse_android_contacts(db, "contacts2.db")
    assert t["status"] == "parsed"
    assert t["summary"]["embedded_calls"] == {
        "count": 4, "types": {"incoming": 2, "missed": 1, "other": 1},
    }
    # Embedded calls alone still make the db non-empty.
    db2 = _contacts(tmp_path / "calls_only" / "contacts2.db",
                    [fx.call(1, "+1", ms, 5, 2)], with_calls=True)
    t2 = parse_android_contacts(db2, "contacts2.db")
    assert t2["status"] == "parsed"
    assert t2["summary"]["embedded_calls"] == {"count": 1, "types": {"outgoing": 1}}


# --- calllog.db ------------------------------------------------------------

def test_calllog_counts_by_type_and_duration(tmp_path):
    base = fx.unix_ms(FIRST)
    rows = [
        fx.call(1, "+15550100", base, 60, 1, "Ana"),
        fx.call(2, "+15550100", base + 60_000, 30, 2),
        fx.call(3, "+15550101", base + 120_000, 0, 3),
        fx.call(4, "+15550101", base + 180_000, 0, 3),
        fx.call(5, "+15550102", base + 240_000, 15, 4),
        fx.call(6, "+15550103", base + 300_000, 0, 5),
        fx.call(7, "+15550104", fx.unix_ms(LAST), 0, 6),
    ]
    t = parse_android_calllog(fx.make_db(tmp_path / "calllog.db", fx.CALLS_DDL, rows), "calllog.db")
    assert t["format"] == "android_calllog" and t["status"] == "parsed"
    assert t["warnings"] == []
    s = t["summary"]
    assert s["total"] == 7
    assert s["by_type"] == {"incoming": 1, "outgoing": 1, "missed": 2,
                            "voicemail": 1, "rejected": 1, "blocked": 1}
    assert s["total_duration_seconds"] == 105
    assert (s["first_call"], s["last_call"]) == (FIRST_ISO, LAST_ISO)
    assert len(t["samples"]) == SAMPLE_CAP
    assert t["samples"][0] == {"time": LAST_ISO, "type": "blocked",
                               "number": "+15550104", "duration_seconds": 0}
    assert [x["type"] for x in t["samples"]] == ["blocked", "rejected", "voicemail"]


def test_calllog_unknown_type_counted_as_other(tmp_path):
    ms = fx.unix_ms(FIRST)
    db = fx.make_db(tmp_path / "calllog.db", fx.CALLS_DDL, [
        fx.call(1, "+15550100", ms, 5, 1),
        fx.call(2, "+15550101", ms + 1000, 7, 99),
        fx.call(3, "+15550102", ms + 2000, 9, 0),
    ])
    t = parse_android_calllog(db, "calllog.db")
    assert t["summary"]["by_type"] == {"incoming": 1, "other": 2}
    assert [x["type"] for x in t["samples"]] == ["other", "other", "incoming"]
    # Empty calls table: status empty, duration 0, no types.
    empty = parse_android_calllog(
        fx.make_db(tmp_path / "e" / "calllog.db", fx.CALLS_DDL, []), "calllog.db")
    assert empty["status"] == "empty"
    assert empty["summary"]["by_type"] == {} and empty["summary"]["total_duration_seconds"] == 0


# --- pipeline dispatch -----------------------------------------------------

def test_android_triage_gated_on_extraction_type(tmp_path):
    """Known limitation, pinned: iOS wins detection, so a zip carrying both iOS
    and Android markers is IOS_FFS and its Android DBs get no Android triage."""
    sms_db = fx.make_db(tmp_path / "src" / "mmssms.db", fx.MMSSMS_DDL,
                        [fx.sms(1, "+15550100", fx.unix_ms(FIRST), 1, "hi")])
    zip_path = _zip(tmp_path, {
        "HomeDomain/Library/SMS/sms.db": b"not even sqlite",  # iOS marker by name
        "data/data/com.android.providers.telephony/databases/mmssms.db": sms_db.read_bytes(),
    })
    result = parse_zip(zip_path)
    assert result.extraction_type == "IOS_FFS"
    by_name = {Path(e.path).name: e.triage for e in result.inventory}
    assert by_name["mmssms.db"] is None
    assert by_name["sms.db"]["format"] == "ios_sms"  # the iOS side still triages

    args = (sms_db, "mmssms.db", "db", "application/vnd.sqlite3")
    assert triage_file(*args) is None  # default extraction_type is UNKNOWN
    assert triage_file(*args, "UNKNOWN") is None
    assert triage_file(*args, "IOS_FFS") is None
    triaged = triage_file(*args, "ANDROID_LOGICAL")
    assert triaged["format"] == "android_mmssms" and triaged["status"] == "parsed"
    # Case-insensitive names; non-artifact SQLite in an Android tree gets no triage.
    assert triage_file(sms_db, "MMSSMS.DB", "db", "x", "ANDROID_LOGICAL")["format"] == "android_mmssms"
    assert triage_file(sms_db, "telephony.db", "db", "x", "ANDROID_LOGICAL") is None
    assert set(ANDROID_ARTIFACTS) == {"mmssms.db", "contacts2.db", "calllog.db"}


def test_android_evidence_untouched(tmp_path):
    """INV-P9-1: parsing (including WAL replay) never changes, adds or removes
    evidence files — every extracted original still matches the zip byte for
    byte and the ParseResult SHA-256, and WAL copies live apart in .treska_wal."""
    zip_path = fx.make_android_zip(tmp_path / "android.zip")
    with zipfile.ZipFile(zip_path) as zf:
        members = {n: hashlib.sha256(zf.read(n)).hexdigest() for n in zf.namelist()}
    assert fx.MMSSMS_PATH + "-wal" in members and fx.CONTACTS_PATH + "-wal" in members

    seen: list[Path] = []
    result = parse_zip(zip_path, keep=True, on_extract=seen.append)
    temp_dir = seen[0]
    try:
        on_disk = {
            p.relative_to(temp_dir).as_posix(): _sha256(p)
            for p in temp_dir.rglob("*")
            if p.is_file() and WAL_DIR not in p.relative_to(temp_dir).parts
        }
        assert on_disk == members  # same listing, same bytes
        assert {e.path: e.sha256 for e in result.inventory} == members
        assert (temp_dir / WAL_DIR).is_dir()  # the WAL copies went elsewhere
        triages = {e.triage["format"]: e.triage for e in result.inventory if e.triage}
        for fmt in ("android_mmssms", "android_contacts"):
            assert triages[fmt]["wal_present"] is True and triages[fmt]["wal_applied"] is True
        assert triages["android_calllog"]["wal_present"] is False
        # Rows that exist only in the WAL are visible after replay.
        assert triages["android_mmssms"]["samples"][0]["body"] == "Delete this thread"
        assert triages["android_contacts"]["summary"]["raw_contact_count"] == 3
    finally:
        cleanup(temp_dir)
