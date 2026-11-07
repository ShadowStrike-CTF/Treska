# Treska Android test fixture — regenerate with: python tests/fixtures/make_android_fixture.py
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic Android logical tree (no real case data): mmssms.db and contacts2.db
# (each with an uncheckpointed -wal/-shm sidecar; contacts2.db also carries the
# older embedded `calls` table) and calllog.db, using the real AOSP table and
# column names. Phase 11 adds Chrome History (no extension) with a planted
# flag{ph11} in a page title and a keyword_search_terms row. Phase 12 adds WhatsApp
# com.whatsapp/databases/msgstore.db (modern layout, uncheckpointed -wal/-shm, a group
# chat, a media-only row, flag{ph12} in one body) and a sibling wa.db. Also imported by
# tests/test_phase10_android.py and tests/test_phase11.py for its DDL and builders. make_db / zip_tree come from make_ios_fixture — one implementation.

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
CHROME_PATH = "data/data/com.android.chrome/app_chrome/Default/History"
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
PLANTED_FLAG = "flag{ph11}"
WHATSAPP_DIR = "data/data/com.whatsapp/databases"
MSGSTORE_PATH = WHATSAPP_DIR + "/msgstore.db"
WA_DB_PATH = WHATSAPP_DIR + "/wa.db"
PHASE12_FLAG = "flag{ph12}"

# Subset of the modern (2021+) WhatsApp msgstore.db schema.
MSGSTORE_MODERN_DDL = """
CREATE TABLE jid (_id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, server TEXT NOT NULL,
    agent INTEGER, device INTEGER, type INTEGER, raw_string TEXT);
CREATE TABLE chat (_id INTEGER PRIMARY KEY AUTOINCREMENT, jid_row_id INTEGER UNIQUE,
    hidden INTEGER, subject TEXT, created_timestamp INTEGER, archived INTEGER,
    sort_timestamp INTEGER);
CREATE TABLE message (_id INTEGER PRIMARY KEY AUTOINCREMENT, chat_row_id INTEGER NOT NULL,
    from_me INTEGER NOT NULL, key_id TEXT NOT NULL, sender_jid_row_id INTEGER,
    status INTEGER, broadcast INTEGER, recipient_count INTEGER, participant_hash TEXT,
    origination_flags INTEGER, origin INTEGER, timestamp INTEGER, received_timestamp INTEGER,
    receipt_server_timestamp INTEGER, message_type INTEGER, text_data TEXT, starred INTEGER,
    lookup_tables INTEGER, sort_id INTEGER NOT NULL DEFAULT 0);
"""

# Legacy (pre-2021) msgstore.db `messages` table.
MSGSTORE_LEGACY_DDL = """
CREATE TABLE messages (_id INTEGER PRIMARY KEY AUTOINCREMENT, key_remote_jid TEXT NOT NULL,
    key_from_me INTEGER, key_id TEXT NOT NULL, status INTEGER, needs_push INTEGER, data TEXT,
    timestamp INTEGER, media_url TEXT, media_mime_type TEXT, media_wa_type TEXT,
    media_size INTEGER, media_name TEXT, latitude REAL, longitude REAL, remote_resource TEXT,
    received_timestamp INTEGER, send_timestamp INTEGER, receipt_server_timestamp INTEGER);
"""

# Subset of wa.db.
WA_DB_DDL = """
CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, jid TEXT NOT NULL,
    is_whatsapp_user BOOLEAN NOT NULL, status TEXT, number TEXT, raw_contact_id INTEGER,
    display_name TEXT, given_name TEXT, family_name TEXT, wa_name TEXT);
"""

# Subset of the Chromium History schema (history_database / url_database).
CHROME_DDL = """
CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
    visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
    last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits (id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
    visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL,
    segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL,
    incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL);
CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL,
    term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL);
"""

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


def webkit_us(dt: datetime) -> int:
    """datetime (UTC) -> WebKit/Chrome microseconds since 1601-01-01."""
    return int((dt - WEBKIT_EPOCH).total_seconds()) * 1_000_000


def chrome_url(url_id: int, url: str, title: str | None, last_visit_us: int,
               visits: int = 1, typed: int = 0):
    return (
        "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (url_id, url, title, visits, typed, last_visit_us),
    )


def chrome_visit(visit_id: int, url_id: int, visit_us: int):
    return ("INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)",
            (visit_id, url_id, visit_us))


def chrome_search(url_id: int, term: str, keyword_id: int = 2):
    return (
        "INSERT INTO keyword_search_terms (keyword_id, url_id, term, normalized_term) "
        "VALUES (?, ?, ?, ?)",
        (keyword_id, url_id, term, term.lower()),
    )


def wa_jid(rowid: int, raw: str):
    user, server = raw.split("@", 1)
    return ("INSERT INTO jid (_id, user, server, raw_string) VALUES (?, ?, ?, ?)",
            (rowid, user, server, raw))


def wa_chat(rowid: int, jid_row: int, subject: str | None = None):
    return ("INSERT INTO chat (_id, jid_row_id, subject) VALUES (?, ?, ?)", (rowid, jid_row, subject))


def wa_message(rowid: int, chat_row: int, from_me: int, ts_ms: int, text: str | None,
               message_type: int = 0):
    return (
        "INSERT INTO message (_id, chat_row_id, from_me, key_id, timestamp, message_type, "
        "text_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rowid, chat_row, from_me, f"KEY{rowid}", ts_ms, message_type, text),
    )


def wa_legacy(rowid: int, jid: str, from_me: int, ts_ms: int, data: str | None,
              media_wa_type: str = "0"):
    return (
        "INSERT INTO messages (_id, key_remote_jid, key_from_me, key_id, data, timestamp, "
        "media_wa_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rowid, jid, from_me, f"KEY{rowid}", data, ts_ms, media_wa_type),
    )


def wa_contact(rowid: int, jid: str, display_name: str | None):
    return ("INSERT INTO wa_contacts (_id, jid, is_whatsapp_user, display_name) VALUES (?, ?, 1, ?)",
            (rowid, jid, display_name))


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

    w = lambda minutes: webkit_us(at(minutes))  # noqa: E731
    chrome = make_db(
        root / CHROME_PATH, CHROME_DDL,
        rows=[
            chrome_url(1, "https://maps.example.com/locker?id=12", "Locker map", w(31), 2, 1),
            chrome_url(2, "https://www.google.com/search?q=locker+12+key",
                       "locker 12 key - Google Search", w(32), 1, 0),
            chrome_url(3, "https://paste.example.net/raw/abc", PLANTED_FLAG, w(33), 1, 1),
            chrome_visit(1, 1, w(30)),
            chrome_visit(2, 1, w(31)),
            chrome_visit(3, 2, w(32)),
            chrome_visit(4, 3, w(33)),
            chrome_search(2, "locker 12 key"),
        ],
    )

    group = "120363000000000001@g.us"
    msgstore = make_db(
        root / MSGSTORE_PATH, MSGSTORE_MODERN_DDL,
        rows=[
            wa_jid(1, "15550100@s.whatsapp.net"), wa_jid(2, group),
            wa_chat(1, 1), wa_chat(2, 2, "Locker crew"),
            wa_message(1, 1, 0, unix_ms(at(40)), "Did you get the key?"),
            wa_message(2, 1, 1, unix_ms(at(41)), PHASE12_FLAG),
            wa_message(3, 2, 0, unix_ms(at(42)), None, message_type=1),  # image, no caption
        ],
        wal_rows=[wa_message(4, 2, 1, unix_ms(at(43)), "Moved it to locker 14")],
    )
    wa_db = make_db(
        root / WA_DB_PATH, WA_DB_DDL,
        rows=[wa_contact(1, "15550100@s.whatsapp.net", "Ana Petrova"),
              wa_contact(2, group, "Locker crew")],
    )

    readme = root / "readme.txt"
    readme.write_bytes(b"Treska synthetic Android logical fixture.\n")
    written = [mmssms, contacts, calllog, chrome, msgstore, wa_db, readme]
    for db in (mmssms, contacts, msgstore):
        written += [Path(str(db) + s) for s in ("-wal", "-shm") if Path(str(db) + s).is_file()]
    return sorted(written)


def make_android_zip(zip_path: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="treska_android_fixture_") as tmp:
        root = Path(tmp)
        return zip_tree(root, build_android_tree(root), Path(zip_path))


if __name__ == "__main__":
    print(make_android_zip(HERE / "android_sample.zip"))
