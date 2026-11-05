# Treska Android test fixture — regenerate with: python tests/fixtures/make_android_fixture.py
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic Android logical tree (no real case data): mmssms.db and contacts2.db
# (each with an uncheckpointed -wal/-shm sidecar; contacts2.db also carries the
# older embedded `calls` table) and calllog.db, using the real AOSP table and
# column names. Also imported by tests/test_phase10_android.py for its DDL and
# builders. make_db / zip_tree come from make_ios_fixture — one implementation.

from __future__ import annotations

import importlib.util
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("make_ios_fixture", HERE / "make_ios_fixture.py")
_ios = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ios)
make_db = _ios.make_db
zip_tree = _ios.zip_tree

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

DB_DIR = "data/data/com.android.providers.{}/databases"
MMSSMS_PATH = DB_DIR.format("telephony") + "/mmssms.db"
CONTACTS_PATH = DB_DIR.format("contacts") + "/contacts2.db"
CALLLOG_PATH = DB_DIR.format("contacts") + "/calllog.db"

# Subset of the AOSP TelephonyProvider schema (MmsSmsDatabaseHelper).
MMSSMS_DDL = """
CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER,
    date INTEGER, date_sent INTEGER DEFAULT 0, protocol INTEGER, read INTEGER DEFAULT 0,
    status INTEGER DEFAULT -1, type INTEGER, reply_path_present INTEGER, subject TEXT,
    body TEXT, service_center TEXT, locked INTEGER DEFAULT 0, sub_id INTEGER DEFAULT -1,
    error_code INTEGER DEFAULT 0, creator TEXT, seen INTEGER DEFAULT 0);
CREATE TABLE pdu (_id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER, date INTEGER,
    date_sent INTEGER DEFAULT 0, msg_box INTEGER, read INTEGER DEFAULT 0, m_id TEXT, sub TEXT,
    sub_cs INTEGER, ct_t TEXT, m_type INTEGER, m_size INTEGER, tr_id TEXT,
    locked INTEGER DEFAULT 0, sub_id INTEGER DEFAULT -1, seen INTEGER DEFAULT 0,
    creator TEXT, text_only INTEGER DEFAULT 0);
CREATE TABLE part (_id INTEGER PRIMARY KEY AUTOINCREMENT, mid INTEGER, seq INTEGER DEFAULT 0,
    ct TEXT, name TEXT, chset INTEGER, cd TEXT, fn TEXT, cid TEXT, cl TEXT, ctt_s INTEGER,
    ctt_t TEXT, _data TEXT, text TEXT);
CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, contact_id INTEGER,
    address TEXT, type INTEGER, charset INTEGER);
CREATE TABLE threads (_id INTEGER PRIMARY KEY AUTOINCREMENT, date INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0, recipient_ids TEXT, snippet TEXT,
    snippet_cs INTEGER DEFAULT 0, read INTEGER DEFAULT 1, type INTEGER DEFAULT 0);
"""

# Subset of the AOSP ContactsProvider schema (ContactsDatabaseHelper).
CONTACTS_DDL = """
CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype TEXT NOT NULL);
CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER,
    sourceid TEXT, version INTEGER NOT NULL DEFAULT 1, dirty INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0, contact_id INTEGER, starred INTEGER NOT NULL DEFAULT 0,
    display_name TEXT, display_name_alt TEXT, display_name_source INTEGER NOT NULL DEFAULT 0,
    sort_key TEXT);
CREATE TABLE contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, name_raw_contact_id INTEGER,
    photo_id INTEGER, starred INTEGER NOT NULL DEFAULT 0,
    times_contacted INTEGER NOT NULL DEFAULT 0, last_time_contacted INTEGER, lookup TEXT,
    contact_last_updated_timestamp INTEGER);
CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT, package_id INTEGER,
    mimetype_id INTEGER NOT NULL, raw_contact_id INTEGER NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0, is_super_primary INTEGER NOT NULL DEFAULT 0,
    data_version INTEGER NOT NULL DEFAULT 0, data1 TEXT, data2 TEXT, data3 TEXT,
    data4 TEXT, data15 BLOB);
"""

# CallLogProvider `calls` — its own calllog.db on Android 7+, inside contacts2.db before.
CALLS_DDL = """
CREATE TABLE calls (_id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT,
    presentation INTEGER NOT NULL DEFAULT 1, date INTEGER, duration INTEGER,
    data_usage INTEGER, type INTEGER, features INTEGER NOT NULL DEFAULT 0,
    subscription_component_name TEXT, subscription_id TEXT, new INTEGER, name TEXT,
    numbertype INTEGER, numberlabel TEXT, countryiso TEXT, voicemail_uri TEXT,
    is_read INTEGER, geocoded_location TEXT, normalized_number TEXT,
    photo_id INTEGER NOT NULL DEFAULT 0, formatted_number TEXT, last_modified INTEGER DEFAULT 0);
"""

MIME_EMAIL = "vnd.android.cursor.item/email_v2"
MIME_PHONE = "vnd.android.cursor.item/phone_v2"
MIME_NAME = "vnd.android.cursor.item/name"
# mimetypes._id assignment as seen on a typical device (the ids vary; the join is by name).
MIMETYPE_IDS = {MIME_EMAIL: 1, MIME_PHONE: 5, MIME_NAME: 7}


def unix_ms(dt: datetime) -> int:
    """datetime (UTC) -> Unix milliseconds (sms.date, calls.date)."""
    return int((dt - UNIX_EPOCH).total_seconds()) * 1000


def unix_s(dt: datetime) -> int:
    """datetime (UTC) -> Unix seconds (pdu.date)."""
    return int((dt - UNIX_EPOCH).total_seconds())


def sms(rowid: int, address: str | None, date_ms: int, sms_type: int, body: str | None):
    return (
        "INSERT INTO sms (_id, thread_id, address, date, type, body) VALUES (?, 1, ?, ?, ?, ?)",
        (rowid, address, date_ms, sms_type, body),
    )


def pdu(rowid: int, date_s: int, msg_box: int = 1):
    return ("INSERT INTO pdu (_id, thread_id, date, msg_box, m_type) VALUES (?, 1, ?, ?, 132)",
            (rowid, date_s, msg_box))


def part(rowid: int, mid: int, ct: str, data_path: str | None, text: str | None = None):
    return ("INSERT INTO part (_id, mid, ct, _data, text) VALUES (?, ?, ?, ?, ?)",
            (rowid, mid, ct, data_path, text))


def mimetype_rows():
    return [("INSERT INTO mimetypes (_id, mimetype) VALUES (?, ?)", (i, m))
            for m, i in MIMETYPE_IDS.items()]


def raw_contact(rowid: int, display_name: str | None):
    return ("INSERT INTO raw_contacts (_id, contact_id, display_name) VALUES (?, ?, ?)",
            (rowid, rowid, display_name))


def contact(rowid: int, raw_id: int):
    return ("INSERT INTO contacts (_id, name_raw_contact_id) VALUES (?, ?)", (rowid, raw_id))


def data(rowid: int, raw_id: int, mimetype: str, value: str):
    return ("INSERT INTO data (_id, mimetype_id, raw_contact_id, data1) VALUES (?, ?, ?, ?)",
            (rowid, MIMETYPE_IDS[mimetype], raw_id, value))


def call(rowid: int, number: str | None, date_ms: int, duration: int, call_type: int,
         name: str | None = None):
    return (
        "INSERT INTO calls (_id, number, date, duration, type, name) VALUES (?, ?, ?, ?, ?, ?)",
        (rowid, number, date_ms, duration, call_type, name),
    )


def build_android_tree(root: Path) -> list[Path]:
    """Write the sample Android logical tree under root; return every file written."""
    root = Path(root)
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    at = lambda minutes: base.replace(minute=minutes)  # noqa: E731

    mmssms = make_db(
        root / MMSSMS_PATH, MMSSMS_DDL,
        rows=[
            sms(1, "+15550100", unix_ms(at(1)), 1, "Meet at the usual place"),
            sms(2, "+15550100", unix_ms(at(2)), 2, "On my way"),
            sms(3, "+15550111", unix_ms(at(3)), 1, "Bring the drive"),
            pdu(1, unix_s(at(4)), msg_box=1),
            # part._data is a device path — counted, never followed.
            part(1, 1, "image/jpeg", "/data/user_de/0/com.android.providers.telephony/app_parts/PART_1"),
        ],
        # Only visible once the WAL is replayed.
        wal_rows=[
            sms(4, "+15550111", unix_ms(at(5)), 2, "Drive is in locker 12"),
            sms(5, "+15550111", unix_ms(at(6)), 1, "Delete this thread"),
            pdu(2, unix_s(at(7)), msg_box=2),
        ],
    )

    contacts = make_db(
        root / CONTACTS_PATH, CONTACTS_DDL + CALLS_DDL,
        rows=[
            *mimetype_rows(),
            raw_contact(1, "Ana Petrova"), contact(1, 1),
            raw_contact(2, "Marko"), contact(2, 2),
            data(1, 1, MIME_NAME, "Ana Petrova"),
            data(2, 1, MIME_EMAIL, "ana@example.org"),
            data(3, 1, MIME_PHONE, "+15550100"),
            data(4, 2, MIME_EMAIL, "analyst@example.org"),
            # Embedded (pre-Android 7) call log.
            call(1, "+15550100", unix_ms(at(10)), 42, 1, "Ana Petrova"),
            call(2, "+15550111", unix_ms(at(11)), 0, 3),
        ],
        wal_rows=[
            raw_contact(3, "Locker Guy"), contact(3, 3),
            data(5, 3, MIME_PHONE, "+15550112"),
        ],
    )

    calllog = make_db(
        root / CALLLOG_PATH, CALLS_DDL,
        rows=[
            call(1, "+15550100", unix_ms(at(20)), 65, 1, "Ana Petrova"),
            call(2, "+15550111", unix_ms(at(21)), 30, 2),
            call(3, "+15550111", unix_ms(at(22)), 0, 3),
            call(4, "+15550112", unix_ms(at(23)), 0, 6),
        ],
    )

    readme = root / "readme.txt"
    readme.write_bytes(b"Treska synthetic Android logical fixture.\n")
    written = [mmssms, contacts, calllog, readme]
    for db in (mmssms, contacts):
        written += [Path(str(db) + s) for s in ("-wal", "-shm") if Path(str(db) + s).is_file()]
    return sorted(written)


def make_android_zip(zip_path: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="treska_android_fixture_") as tmp:
        root = Path(tmp)
        return zip_tree(root, build_android_tree(root), Path(zip_path))


if __name__ == "__main__":
    print(make_android_zip(HERE / "android_sample.zip"))
