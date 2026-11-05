# Treska Phase 9 — iOS FFS artifact triage (sms.db, KnowledgeC.db, AddressBook.sqlitedb).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic databases only, built in tmp_path with the real iOS table and
# column names (DDL shared with tests/fixtures/make_ios_fixture.py).

from __future__ import annotations

import hashlib
import importlib.util
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from treska.core.ingestion import cleanup
from treska.core.pipeline import parse_zip, triage_file
from treska.parsers.ios import (
    IOS_ARTIFACTS,
    apple_to_iso,
    parse_ios_addressbook,
    parse_ios_knowledgec,
    parse_ios_sms,
)
from treska.parsers.sqlite_triage import SAMPLE_CAP, TEXT_CAP, TOP_N, WAL_DIR

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_spec = importlib.util.spec_from_file_location("make_ios_fixture", FIXTURES / "make_ios_fixture.py")
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

UTC = timezone.utc
FIRST = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
LAST = datetime(2024, 6, 7, 8, 9, 10, tzinfo=UTC)


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _sms_db(path: Path, messages, *, handles=None, chats=None, attachments=0, wal_rows=None):
    handles = handles if handles is not None else [(1, "+15550100")]
    chats = chats if chats is not None else [(1, "+15550100")]
    rows = [fx.sms_handle(*h) for h in handles] + [fx.sms_chat(*c) for c in chats]
    rows += [fx.sms_attachment(i + 1, f"IMG_{i}.HEIC") for i in range(attachments)]
    rows += [fx.sms_message(*m) for m in messages]
    return fx.make_db(path, fx.SMS_DDL, rows, wal_rows=wal_rows)


def _zip(tmp_path: Path, members: dict[str, bytes]) -> Path:
    zip_path = tmp_path / "case.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return zip_path


# --- sms.db ----------------------------------------------------------------

def test_sms_parsed_counts(tmp_path):
    db = _sms_db(
        tmp_path / "sms.db",
        messages=[
            (1, "a", 1, fx.cocoa_ns(FIRST), 0),
            (2, "b", 2, fx.cocoa_ns(FIRST), 1),
            (3, "c", 2, fx.cocoa_ns(FIRST), 1),
            (4, "d", 3, fx.cocoa_ns(FIRST), 0),
            (5, "e", 3, fx.cocoa_ns(FIRST), 0),
        ],
        handles=[(1, "+15550100"), (2, "+15550101"), (3, "x@example.org")],
        chats=[(1, "+15550100"), (2, "group-1")],
        attachments=2,
    )
    t = parse_ios_sms(db, "sms.db")
    assert t["format"] == "ios_sms"
    assert t["status"] == "parsed"
    assert t["error"] is None and t["warnings"] == []
    assert t["wal_present"] is False and t["wal_applied"] is False
    s = t["summary"]
    assert (s["message_count"], s["sent_count"], s["received_count"]) == (5, 2, 3)
    assert (s["chat_count"], s["handle_count"], s["attachment_count"]) == (2, 3, 2)


def test_sms_date_range_seconds(tmp_path):
    secs = (fx.cocoa_seconds(LAST), fx.cocoa_seconds(FIRST))
    db = _sms_db(tmp_path / "sms.db", messages=[(1, "x", 1, secs[0], 0), (2, "y", 1, secs[1], 1)])
    s = parse_ios_sms(db, "sms.db")["summary"]
    assert s["first_message"] == "2024-01-02T03:04:05Z"
    assert s["last_message"] == "2024-06-07T08:09:10Z"
    assert apple_to_iso(0) is None and apple_to_iso(None) is None
    assert apple_to_iso(b"\x00blob") is None


def test_sms_date_range_nanoseconds(tmp_path):
    db = _sms_db(tmp_path / "sms.db", messages=[
        (1, "x", 1, fx.cocoa_ns(LAST), 0), (2, "y", 1, fx.cocoa_ns(FIRST), 1),
    ])
    s = parse_ios_sms(db, "sms.db")["summary"]
    assert s["first_message"] == "2024-01-02T03:04:05Z"
    assert s["last_message"] == "2024-06-07T08:09:10Z"
    assert apple_to_iso(fx.cocoa_ns(FIRST)) == apple_to_iso(fx.cocoa_seconds(FIRST))


def test_sms_samples_capped_and_recent(tmp_path):
    base = fx.cocoa_seconds(FIRST)
    # Insert out of date order so the sort, not ROWID, decides.
    order = [3, 7, 0, 9, 5, 1, 8, 2, 6, 4]
    db = _sms_db(tmp_path / "sms.db", messages=[
        (i + 1, f"msg {n}", 1, base + n * 60, n % 2) for i, n in enumerate(order)
    ])
    t = parse_ios_sms(db, "sms.db")
    assert t["summary"]["message_count"] == 10
    assert len(t["samples"]) == SAMPLE_CAP == 3
    assert [x["text"] for x in t["samples"]] == ["msg 9", "msg 8", "msg 7"]
    times = [x["time"] for x in t["samples"]]
    assert times == sorted(times, reverse=True)
    assert [x["direction"] for x in t["samples"]] == ["sent", "received", "sent"]
    assert all(x["handle"] == "+15550100" for x in t["samples"])


def test_sms_text_truncated(tmp_path):
    body = "A" * 1000
    db = _sms_db(tmp_path / "sms.db", messages=[(1, body, 1, fx.cocoa_ns(FIRST), 0)])
    sample = parse_ios_sms(db, "sms.db")["samples"][0]
    assert len(sample["text"]) <= TEXT_CAP == 200
    assert sample["text"] == body[:TEXT_CAP]


def test_sms_empty(tmp_path):
    db = _sms_db(tmp_path / "sms.db", messages=[], handles=[], chats=[])
    t = parse_ios_sms(db, "sms.db")
    assert t["status"] == "empty"
    assert t["error"] is None
    assert t["summary"]["message_count"] == 0
    assert t["summary"]["first_message"] is None
    assert t["samples"] == []


def test_sms_not_sqlite_corrupt(tmp_path):
    junk = os.urandom(4096)
    fake_header = b"SQLite format 3\x00" + os.urandom(4080)
    zip_path = _zip(tmp_path, {
        "HomeDomain/Library/SMS/sms.db": junk,
        "private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db": fake_header,
    })
    result = parse_zip(zip_path)  # must not raise
    by_path = {e.path: e for e in result.inventory}
    sms = by_path["HomeDomain/Library/SMS/sms.db"].triage
    assert sms["format"] == "ios_sms" and sms["status"] == "corrupt"
    assert sms["error"] == "not a SQLite database"
    assert sms["summary"] is None and sms["samples"] == []
    kc = by_path["private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db"].triage
    assert kc["format"] == "ios_knowledgec" and kc["status"] == "corrupt"
    assert kc["error"]
    # A direct parser call on garbage reports corrupt rather than raising.
    (tmp_path / "raw.db").write_bytes(junk)
    assert parse_ios_sms(tmp_path / "raw.db", "raw.db")["status"] == "corrupt"


def test_sms_missing_optional_column_warns(tmp_path):
    ddl = """
    CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL, service TEXT);
    CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT, chat_identifier TEXT);
    CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT,
        handle_id INTEGER, date INTEGER);
    """
    db = fx.make_db(tmp_path / "sms.db", ddl, [
        ("INSERT INTO handle VALUES (1, '+15550100', 'SMS')", ()),
        ("INSERT INTO message VALUES (1, 'g1', 'hi', 1, ?)", (fx.cocoa_ns(FIRST),)),
    ])
    t = parse_ios_sms(db, "sms.db")
    assert t["status"] == "parsed"
    assert "missing column message.is_from_me" in t["warnings"]
    assert "missing table attachment" in t["warnings"]
    s = t["summary"]
    assert s["message_count"] == 1
    assert s["sent_count"] is None and s["received_count"] is None
    assert s["attachment_count"] is None
    assert t["samples"][0]["direction"] is None
    assert t["samples"][0]["text"] == "hi"


# --- KnowledgeC.db ---------------------------------------------------------

def test_knowledgec_top_bundles(tmp_path):
    rows, pk = [], 0
    base = fx.cocoa_seconds(FIRST)
    for i in range(TOP_N + 2):  # 12 bundles: bundle i has i + 1 usage rows
        for _ in range(i + 1):
            pk += 1
            rows.append(fx.kc_event(pk, "/app/usage", f"com.example.app{i:02d}",
                                    base + pk * 60, base + pk * 60 + 30))
    for _ in range(50):  # same value on another stream must not count as usage
        pk += 1
        rows.append(fx.kc_event(pk, "/app/inFocus", "com.example.app00", base, base))
    db = fx.make_db(tmp_path / "knowledgeC.db", fx.KNOWLEDGEC_DDL, rows)
    t = parse_ios_knowledgec(db, "knowledgeC.db")
    assert t["status"] == "parsed"
    bundles = t["summary"]["top_bundles"]
    assert len(bundles) == TOP_N == 10
    assert bundles[0] == {"bundle_id": "com.example.app11", "count": 12}
    assert [b["count"] for b in bundles] == list(range(12, 2, -1))
    assert "com.example.app00" not in {b["bundle_id"] for b in bundles}
    # Samples: newest /app/usage rows only.
    assert len(t["samples"]) == SAMPLE_CAP
    assert all(s["bundle_id"] == "com.example.app11" for s in t["samples"])
    starts = [s["start"] for s in t["samples"]]
    assert starts == sorted(starts, reverse=True)
    assert t["samples"][0]["end"] is not None


def test_knowledgec_streams(tmp_path):
    base = fx.cocoa_seconds(FIRST)
    counts = {"/app/usage": 4, "/device/isLocked": 2, "/display/isBacklit": 3, "/safari/history": 1}
    rows, pk = [], 0
    for stream, n in counts.items():
        for _ in range(n):
            pk += 1
            rows.append(fx.kc_event(pk, stream, "com.apple.x", base + pk, base + pk + 1))
    db = fx.make_db(tmp_path / "knowledgeC.db", fx.KNOWLEDGEC_DDL, rows)
    s = parse_ios_knowledgec(db, "knowledgeC.db")["summary"]
    assert s["total_rows"] == sum(counts.values())
    assert {x["stream"]: x["count"] for x in s["stream_counts"]} == counts
    assert [x["count"] for x in s["stream_counts"]] == [4, 3, 2, 1]
    assert s["first_event"] == "2024-01-02T03:04:06Z"
    assert s["last_event"] == apple_to_iso(base + pk)


# --- AddressBook.sqlitedb --------------------------------------------------

def test_addressbook_counts_and_samples(tmp_path):
    db = fx.make_db(tmp_path / "AddressBook.sqlitedb", fx.ADDRESSBOOK_DDL, [
        fx.ab_person(1, "Ana", "Petrova", None),
        fx.ab_person(2, None, None, "Harbour Freight"),
        fx.ab_person(3, "Ivo", "Kos", None),
        fx.ab_person(4, "Late", "Entry", None),
        fx.ab_value(1, 1, fx.AB_EMAIL, "ana@example.org"),
        fx.ab_value(2, 1, fx.AB_PHONE, "+15550100"),
        fx.ab_value(3, 2, fx.AB_EMAIL, "ops@harbour.example"),
        fx.ab_value(4, 4, fx.AB_PHONE, "+15550199"),
        fx.ab_value(5, 4, 22, "https://not-a-phone.example"),  # URL property — ignored
    ])
    t = parse_ios_addressbook(db, "AddressBook.sqlitedb")
    assert t["status"] == "parsed" and t["warnings"] == []
    assert t["summary"] == {"person_count": 4, "phone_count": 2, "email_count": 2}
    assert t["samples"] == [
        {"first_name": "Ana", "last_name": "Petrova", "organization": None,
         "first_phone_or_email": "+15550100"},  # phone preferred over email
        {"first_name": None, "last_name": None, "organization": "Harbour Freight",
         "first_phone_or_email": "ops@harbour.example"},
        {"first_name": "Ivo", "last_name": "Kos", "organization": None,
         "first_phone_or_email": None},
    ]


# --- pipeline dispatch -----------------------------------------------------

def test_ios_triage_gated_on_extraction_type(tmp_path):
    # AddressBook.sqlitedb is itself an IOS_FFS marker, so a parse_zip tree that
    # contains it is always IOS_FFS; the gate is exercised at triage_file.
    db = fx.make_db(tmp_path / "AddressBook.sqlitedb", fx.ADDRESSBOOK_DDL,
                    [fx.ab_person(1, "Ana", None, None)])
    args = (db, "AddressBook.sqlitedb", "sqlitedb", "application/vnd.sqlite3")
    assert triage_file(*args) is None  # default extraction_type is UNKNOWN
    assert triage_file(*args, "UNKNOWN") is None
    assert triage_file(*args, "ANDROID_LOGICAL") is None
    triaged = triage_file(*args, "IOS_FFS")
    assert triaged["format"] == "ios_addressbook" and triaged["status"] == "parsed"
    # Non-artifact SQLite in an iOS tree: no triage.
    other = fx.make_db(tmp_path / "Calendar.sqlitedb", fx.ADDRESSBOOK_DDL, [])
    assert triage_file(other, "Calendar.sqlitedb", "sqlitedb", "x", "IOS_FFS") is None
    assert set(IOS_ARTIFACTS) == {"sms.db", "knowledgec.db", "addressbook.sqlitedb"}


def test_ios_case_insensitive_name(tmp_path):
    db = _sms_db(tmp_path / "src.db", messages=[(1, "hi", 1, fx.cocoa_ns(FIRST), 1)])
    zip_path = _zip(tmp_path, {"HomeDomain/Library/SMS/SMS.DB": db.read_bytes()})
    result = parse_zip(zip_path)
    assert result.extraction_type == "IOS_FFS"
    triage = result.inventory[0].triage
    assert triage["format"] == "ios_sms" and triage["status"] == "parsed"
    assert triage["filename"] == "HomeDomain/Library/SMS/SMS.DB"
    assert triage["summary"]["sent_count"] == 1


def test_ios_evidence_untouched(tmp_path):
    """INV-P9-1: parsing (including WAL replay) never changes, adds or removes
    evidence files — every extracted original still matches the zip byte for
    byte and the ParseResult SHA-256, and the WAL copy lives apart in .treska_wal."""
    zip_path = fx.make_ios_zip(tmp_path / "ios.zip")
    with zipfile.ZipFile(zip_path) as zf:
        members = {n: hashlib.sha256(zf.read(n)).hexdigest() for n in zf.namelist()}
    assert "HomeDomain/Library/SMS/sms.db-wal" in members

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
        assert (temp_dir / WAL_DIR).is_dir()  # the WAL copy went elsewhere
        sms = next(e for e in result.inventory if e.path.endswith("sms.db")).triage
        assert sms["wal_present"] is True and sms["wal_applied"] is True
    finally:
        cleanup(temp_dir)


def test_ios_wal_applied_from_copy(tmp_path):
    base = fx.cocoa_ns(FIRST)
    db = _sms_db(
        tmp_path / "sms.db",
        messages=[(1, "checkpointed", 1, base, 0)],
        wal_rows=[fx.sms_message(2, "only in wal", 1, base + 60 * 10**9, 1)],
    )
    before = {p.name: _sha256(p) for p in tmp_path.iterdir()}
    assert {"sms.db", "sms.db-wal"} <= set(before)

    t = parse_ios_sms(db, "sms.db")  # no work_dir: private temp staging
    assert t["wal_present"] is True and t["wal_applied"] is True
    assert t["summary"]["message_count"] == 2
    assert t["samples"][0]["text"] == "only in wal"
    assert {p.name: _sha256(p) for p in tmp_path.iterdir()} == before

    # Without the WAL sidecar, the same file reads immutable: WAL rows unseen.
    (tmp_path / "sms.db-wal").unlink()
    (tmp_path / "sms.db-shm").unlink(missing_ok=True)
    t = parse_ios_sms(db, "sms.db")
    assert t["wal_present"] is False and t["wal_applied"] is False
    assert t["summary"]["message_count"] == 1

    # parse_zip stages under its temp dir, which is removed afterwards.
    zip_path = fx.make_ios_zip(tmp_path / "ios.zip")
    seen: list[Path] = []
    parse_zip(zip_path, on_extract=seen.append)
    assert not seen[0].exists()
