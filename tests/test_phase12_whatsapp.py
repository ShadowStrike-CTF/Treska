# Treska Phase 12 — WhatsApp triage (Android msgstore.db + wa.db, iOS ChatStorage.sqlite).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic databases only, built in tmp_path with the real WhatsApp table and column
# names (DDL shared with tests/fixtures/make_*_fixture.py).

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from treska.core.pipeline import GENERIC_ARTIFACT_NAMES, parse_zip, triage_file
from treska.parsers.android import ANDROID_ARTIFACTS, parse_android_whatsapp
from treska.parsers.ios import IOS_ARTIFACTS, parse_ios_whatsapp
from treska.parsers.sqlite_triage import SAMPLE_CAP, strip_jid, whatsapp_record

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parent.parent / "src"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ios_fx = _load("make_ios_fixture")
android_fx = _load("make_android_fixture")

UTC = timezone.utc
T1 = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
T2 = datetime(2024, 6, 7, 8, 9, 10, tzinfo=UTC)
T1_ISO = "2024-01-02T03:04:05Z"
T2_ISO = "2024-06-07T08:09:10Z"
SQLITE_MIME = "application/vnd.sqlite3"
USER = "15550100@s.whatsapp.net"
GROUP = "120363000000000009@g.us"
SAMPLE_KEYS = {"kind", "timestamp", "direction", "contact", "contact_name", "is_group",
               "body", "platform"}
SUMMARY_KEYS = {"message_count", "sent_count", "received_count", "media_only_count",
                "chat_count", "group_chat_count", "first_message", "last_message",
                "contact_names_resolved", "schema_layout"}

ms = android_fx.unix_ms
cocoa = ios_fx.cocoa_seconds


# --- builders ---------------------------------------------------------------

def _msgstore(path: Path, rows, wal_rows=None) -> Path:
    return android_fx.make_db(path, android_fx.MSGSTORE_MODERN_DDL, rows, wal_rows=wal_rows)


def _modern_rows(text_2: str | None = "see you", type_2: int = 0):
    fx = android_fx
    return [
        fx.wa_jid(1, USER), fx.wa_jid(2, GROUP),
        fx.wa_chat(1, 1), fx.wa_chat(2, 2, "Crew"),
        fx.wa_message(1, 1, 0, ms(T1), "hello"),
        fx.wa_message(2, 2, 1, ms(T2), text_2, message_type=type_2),
    ]


def _wa_db(path: Path, rows) -> Path:
    return android_fx.make_db(path, android_fx.WA_DB_DDL, rows)


def _chatstorage(path: Path, rows, ddl: str | None = None, wal_rows=None) -> Path:
    return ios_fx.make_db(path, ddl or ios_fx.CHATSTORAGE_DDL, rows, wal_rows=wal_rows)


def _ios_rows(text_2: str | None = "see you", type_2: int = 0, push: bool = True):
    fx = ios_fx
    rows = [
        fx.wa_session(1, USER, "Partner Ana"),
        fx.wa_session(2, GROUP, "Crew", session_type=1),
        fx.wa_message(1, 1, 0, cocoa(T1), "hello"),
        fx.wa_message(2, 2, 1, cocoa(T2), text_2, message_type=type_2),
    ]
    if push:
        rows.append(fx.wa_push(1, USER, "Ana Push"))
    return rows


def _by_contact(triage: dict) -> dict:
    return {s["contact"]: s for s in triage["samples"]}


def _zip_tree(tmp_path: Path, build) -> Path:
    """build(root) writes files under root and returns them; zipped to tmp_path/case.zip."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        files = build(root)
        return android_fx.zip_tree(root, files, tmp_path / "case.zip")


def _hits(result) -> list[tuple[str, str]]:
    return [(h["path"], h["match"]) for h in result.flag_hits]


# --- Android ----------------------------------------------------------------

def test_android_modern_layout(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    t = parse_android_whatsapp(db, "msgstore.db")
    assert t["status"] == "parsed" and t["format"] == "android_whatsapp"
    s = t["summary"]
    assert set(s) == SUMMARY_KEYS
    assert s["schema_layout"] == "modern"
    assert (s["message_count"], s["sent_count"], s["received_count"]) == (2, 1, 1)
    assert (s["chat_count"], s["group_chat_count"], s["media_only_count"]) == (2, 1, 0)
    assert (s["first_message"], s["last_message"]) == (T1_ISO, T2_ISO)
    # Most-recent first; the legacy table is not "missing" for a modern db.
    assert [x["timestamp"] for x in t["samples"]] == [T2_ISO, T1_ISO]
    assert not any("messages" in w for w in t["warnings"])


def test_android_legacy_layout(tmp_path):
    fx = android_fx
    db = fx.make_db(tmp_path / "msgstore.db", fx.MSGSTORE_LEGACY_DDL, [
        fx.wa_legacy(1, "-1", 0, ms(T1), None),  # system row — skipped
        fx.wa_legacy(2, USER, 0, ms(T1), "hi"),
        fx.wa_legacy(3, USER, 1, ms(T2), "yo"),
        fx.wa_legacy(4, GROUP, 0, ms(T2), None, media_wa_type="1"),
    ])
    t = parse_android_whatsapp(db, "msgstore.db")
    s = t["summary"]
    assert t["status"] == "parsed" and s["schema_layout"] == "legacy"
    assert (s["message_count"], s["sent_count"], s["received_count"]) == (3, 1, 2)
    assert (s["chat_count"], s["group_chat_count"], s["media_only_count"]) == (2, 1, 1)
    assert s["first_message"] == T1_ISO
    assert "-1" not in {x["contact"] for x in t["samples"]}
    assert not any(w.startswith("missing table") for w in t["warnings"])


def test_android_wa_db_name_resolution(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    _wa_db(tmp_path / "WA.DB", [android_fx.wa_contact(1, USER, "Ana Petrova")])  # casefolded
    t = parse_android_whatsapp(db, "msgstore.db")
    assert t["summary"]["contact_names_resolved"] is True
    samples = _by_contact(t)
    assert samples["15550100"]["contact_name"] == "Ana Petrova"
    assert samples["120363000000000009"]["contact_name"] is None


def test_android_no_wa_db(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    t = parse_android_whatsapp(db, "msgstore.db")
    assert t["status"] == "parsed"
    assert t["summary"]["contact_names_resolved"] is False
    assert all(x["contact_name"] is None for x in t["samples"])
    assert any("wa.db not found" in w for w in t["warnings"])


def test_android_corrupt_wa_db(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    (tmp_path / "wa.db").write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)
    t = parse_android_whatsapp(db, "msgstore.db")
    assert t["status"] == "parsed" and t["summary"]["message_count"] == 2
    assert t["summary"]["contact_names_resolved"] is False
    assert any(w.startswith("wa.db unreadable") for w in t["warnings"])


def test_android_group_jid(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    group = _by_contact(parse_android_whatsapp(db, "msgstore.db"))["120363000000000009"]
    assert group["is_group"] is True and group["direction"] == "sent"
    assert strip_jid(USER) == "15550100"
    assert strip_jid(GROUP) == "120363000000000009"
    assert strip_jid("123@lid") == "123@lid" and strip_jid("status@broadcast") == "status@broadcast"


def test_android_media_only(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows(text_2=None, type_2=1))
    t = parse_android_whatsapp(db, "msgstore.db")
    assert t["summary"]["media_only_count"] == 1
    assert t["samples"][0]["body"] == ""


def test_android_wal(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows(),
                   wal_rows=[android_fx.wa_message(3, 1, 1, ms(T2) + 1000, "wal only")])
    t = parse_android_whatsapp(db, "msgstore.db", work_dir=tmp_path / "work")
    assert t["wal_present"] is True and t["wal_applied"] is True
    assert t["summary"]["message_count"] == 3
    assert t["samples"][0]["body"] == "wal only"


def test_android_not_whatsapp(tmp_path):
    # Right name, wrong tables: some other app's msgstore.db — skipped, not corrupt.
    db = android_fx.make_db(tmp_path / "msgstore.db", "CREATE TABLE notes (id INTEGER);", [])
    assert triage_file(db, "x/msgstore.db", "db", SQLITE_MIME, "ANDROID_LOGICAL") is None
    text = tmp_path / "t" / "msgstore.db"
    text.parent.mkdir()
    text.write_text("not sqlite")
    assert triage_file(text, "t/msgstore.db", "db", "text/plain", "ANDROID_LOGICAL") is None


def test_android_unknown_gating(tmp_path):
    db = _msgstore(tmp_path / "msgstore.db", _modern_rows())
    assert triage_file(db, "x/msgstore.db", "db", SQLITE_MIME, "UNKNOWN") is None
    assert triage_file(db, "x/msgstore.db", "db", SQLITE_MIME, "IOS_FFS") is None
    t = triage_file(db, "x/msgstore.db", "db", SQLITE_MIME, "ANDROID_LOGICAL")
    assert t["format"] == "android_whatsapp" and t["status"] == "parsed"


# --- iOS ----------------------------------------------------------------------

def test_ios_push_names(tmp_path):
    db = _chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows())
    t = parse_ios_whatsapp(db, "ChatStorage.sqlite")
    s = t["summary"]
    assert t["status"] == "parsed" and t["format"] == "ios_whatsapp"
    assert set(s) == SUMMARY_KEYS and s["schema_layout"] == "coredata"
    assert (s["message_count"], s["sent_count"], s["received_count"]) == (2, 1, 1)
    assert (s["chat_count"], s["group_chat_count"]) == (2, 1)
    assert s["contact_names_resolved"] is True
    samples = _by_contact(t)
    assert samples["15550100"]["contact_name"] == "Ana Push"  # push name beats partner
    assert samples["120363000000000009"]["contact_name"] == "Crew"  # no push row → partner
    assert t["warnings"] == []


def test_ios_partner_name_fallback(tmp_path):
    ddl = ios_fx.CHATSTORAGE_DDL.split("CREATE TABLE ZWAPROFILEPUSHNAME")[0]
    db = _chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows(push=False), ddl=ddl)
    t = parse_ios_whatsapp(db, "ChatStorage.sqlite")
    assert t["status"] == "parsed"
    assert _by_contact(t)["15550100"]["contact_name"] == "Partner Ana"
    assert any("ZWAPROFILEPUSHNAME" in w for w in t["warnings"])


def test_ios_orphan_fk(tmp_path):
    rows = _ios_rows() + [ios_fx.wa_message(3, 99, 0, cocoa(T2) + 60, "orphan")]
    t = parse_ios_whatsapp(_chatstorage(tmp_path / "ChatStorage.sqlite", rows), "ChatStorage.sqlite")
    assert t["summary"]["message_count"] == 3
    orphan = t["samples"][0]
    assert orphan["body"] == "orphan" and orphan["contact"] is None
    assert orphan["contact_name"] is None and orphan["is_group"] is False
    assert "1 messages reference a missing chat session" in t["warnings"]


def test_ios_cocoa_timestamp(tmp_path):
    t = parse_ios_whatsapp(_chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows()),
                           "ChatStorage.sqlite")
    assert (t["summary"]["first_message"], t["summary"]["last_message"]) == (T1_ISO, T2_ISO)
    assert [x["timestamp"] for x in t["samples"]] == [T2_ISO, T1_ISO]


def test_ios_media_only(tmp_path):
    db = _chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows(text_2=None, type_2=1))
    t = parse_ios_whatsapp(db, "ChatStorage.sqlite")
    assert t["summary"]["media_only_count"] == 1
    assert t["samples"][0]["body"] == ""


def test_ios_group(tmp_path):
    t = parse_ios_whatsapp(_chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows()),
                           "ChatStorage.sqlite")
    samples = _by_contact(t)
    assert samples["120363000000000009"]["is_group"] is True
    assert samples["15550100"]["is_group"] is False


def test_ios_wal(tmp_path):
    db = _chatstorage(tmp_path / "ChatStorage.sqlite", _ios_rows(),
                      wal_rows=[ios_fx.wa_message(3, 1, 0, cocoa(T2) + 60, "wal only")])
    t = parse_ios_whatsapp(db, "ChatStorage.sqlite", work_dir=tmp_path / "work")
    assert t["wal_present"] is True and t["wal_applied"] is True
    assert t["samples"][0]["body"] == "wal only"


# --- shared -------------------------------------------------------------------

def test_whatsapp_uniform_sample_keys(tmp_path):
    a = parse_android_whatsapp(_msgstore(tmp_path / "a" / "msgstore.db", _modern_rows()), "msgstore.db")
    i = parse_ios_whatsapp(_chatstorage(tmp_path / "i" / "ChatStorage.sqlite", _ios_rows()),
                           "ChatStorage.sqlite")
    samples = a["samples"] + i["samples"]
    assert samples and all(set(x) == SAMPLE_KEYS for x in samples)
    assert {x["platform"] for x in samples} == {"android", "ios"}
    assert all(x["kind"] == "whatsapp_msg" for x in samples)
    assert len(a["samples"]) <= SAMPLE_CAP and len(i["samples"]) <= SAMPLE_CAP
    rec = whatsapp_record(timestamp=None, from_me=None, jid=None, contact_name=None,
                          body=b"\x00blob", platform="ios")
    assert set(rec) == SAMPLE_KEYS and rec["body"] == "" and rec["direction"] is None


# --- flag scan ----------------------------------------------------------------

def _android_case(root: Path, rows, wal_rows=None) -> list[Path]:
    db = _msgstore(root / android_fx.MSGSTORE_PATH, rows, wal_rows=wal_rows)
    marker = root / android_fx.MMSSMS_PATH  # ANDROID_LOGICAL marker by name
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b"x")
    return [db, marker] + [Path(str(db) + s) for s in ("-wal", "-shm") if Path(str(db) + s).is_file()]


def test_flag_in_whatsapp_body(tmp_path):
    zip_path = _zip_tree(tmp_path, lambda r: _android_case(r, _modern_rows(text_2="flag{wa_body}")))
    assert (android_fx.MSGSTORE_PATH, "flag{...}") in _hits(parse_zip(zip_path))
    result = parse_zip(zip_path, reveal_flags=True)
    assert (android_fx.MSGSTORE_PATH, "flag{wa_body}") in _hits(result)
    triage = next(e.triage for e in result.inventory if e.path == android_fx.MSGSTORE_PATH)
    assert triage["format"] == "android_whatsapp"
    assert "flag{wa_body}" in [x["body"] for x in triage["samples"]]


def test_flag_only_in_wal(tmp_path):
    wal_rows = [android_fx.wa_message(3, 1, 1, ms(T2) + 1000, "flag{wal_only}")]
    zip_path = _zip_tree(tmp_path, lambda r: _android_case(r, _modern_rows(), wal_rows))
    assert (android_fx.MSGSTORE_PATH + "-wal", "flag{...}") in _hits(parse_zip(zip_path))
    hits = _hits(parse_zip(zip_path, reveal_flags=True))
    assert (android_fx.MSGSTORE_PATH + "-wal", "flag{wal_only}") in hits
    assert (android_fx.MSGSTORE_PATH, "flag{wal_only}") not in hits  # uncheckpointed


def test_flag_unclosed_decoy(tmp_path):
    zip_path = _zip_tree(tmp_path, lambda r: _android_case(
        r, _modern_rows(text_2="Flag{wrong_case} and flag{never_closed")))
    assert parse_zip(zip_path).flag_hits == []


def test_no_flag_scan_opt_out(tmp_path):
    zip_path = _zip_tree(tmp_path, lambda r: _android_case(r, _modern_rows(text_2="flag{x}")))
    assert parse_zip(zip_path, no_flag_scan=True).flag_hits is None
    proc = subprocess.run(
        [sys.executable, "-m", "treska.cli", "--json", "--no-flag-scan", str(zip_path)],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["flag_hits"] is None
    assert any(e["triage"] and e["triage"]["format"] == "android_whatsapp" for e in data["inventory"])


# --- dispatch -----------------------------------------------------------------

def test_dispatch_tables_superset():
    assert set(IOS_ARTIFACTS) == {"sms.db", "knowledgec.db", "addressbook.sqlitedb",
                                  "callhistory.storedata", "history.db", "chatstorage.sqlite"}
    assert set(ANDROID_ARTIFACTS) == {"mmssms.db", "contacts2.db", "calllog.db", "history",
                                      "msgstore.db"}
    assert GENERIC_ARTIFACT_NAMES == frozenset(
        {"history", "history.db", "msgstore.db", "chatstorage.sqlite"})
    assert IOS_ARTIFACTS["chatstorage.sqlite"][0] == "ios_whatsapp"
    assert ANDROID_ARTIFACTS["msgstore.db"][0] == "android_whatsapp"
    assert "wa.db" not in ANDROID_ARTIFACTS
