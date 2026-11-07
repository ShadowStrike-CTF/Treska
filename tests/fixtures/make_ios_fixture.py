# Treska iOS test fixture — regenerate with: python tests/fixtures/make_ios_fixture.py
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic iOS FFS tree (no real case data): sms.db (with an uncheckpointed
# -wal/-shm sidecar), knowledgeC.db and AddressBook.sqlitedb, using the real iOS
# table and column names. Phase 11 adds CallHistory.storedata (uncheckpointed
# -wal/-shm, one ZADDRESS stored as a BLOB) and Safari History.db. Phase 12 adds WhatsApp
# ChatStorage.sqlite (uncheckpointed -wal/-shm, push names, a group session, a media-only
# row, flag{ph12} in one body). Also imported by tests/test_phase9_ios.py for its DDL
# and builders, so there is one source of the synthetic schemas.

from __future__ import annotations

import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZIP_TIMESTAMP = (2026, 9, 25, 12, 30, 0)
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

SMS_PATH = "HomeDomain/Library/SMS/sms.db"
KNOWLEDGEC_PATH = "private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db"
ADDRESSBOOK_PATH = "HomeDomain/Library/AddressBook/AddressBook.sqlitedb"
CALLHISTORY_PATH = "private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"
SAFARI_PATH = "private/var/mobile/Library/Safari/History.db"
CHATSTORAGE_PATH = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite"
PHASE12_FLAG = "flag{ph12}"

SMS_DDL = """
CREATE TABLE handle (ROWID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, id TEXT NOT NULL,
    country TEXT, service TEXT NOT NULL, uncanonicalized_id TEXT, person_centric_id TEXT,
    UNIQUE (id, service));
CREATE TABLE chat (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT UNIQUE NOT NULL,
    style INTEGER, state INTEGER, account_id TEXT, chat_identifier TEXT,
    service_name TEXT, display_name TEXT);
CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT UNIQUE NOT NULL,
    text TEXT, handle_id INTEGER DEFAULT 0, service TEXT, date INTEGER, date_read INTEGER,
    date_delivered INTEGER, is_from_me INTEGER DEFAULT 0, cache_has_attachments INTEGER DEFAULT 0);
CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT UNIQUE NOT NULL,
    created_date INTEGER DEFAULT 0, filename TEXT, mime_type TEXT, transfer_name TEXT,
    total_bytes INTEGER DEFAULT 0);
CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER,
    message_date INTEGER DEFAULT 0, PRIMARY KEY (chat_id, message_id));
CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER, UNIQUE (chat_id, handle_id));
"""

KNOWLEDGEC_DDL = """
CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZUUID VARCHAR,
    ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP,
    ZCREATIONDATE TIMESTAMP, ZSECONDSFROMGMT INTEGER);
"""

ADDRESSBOOK_DDL = """
CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, First TEXT, Last TEXT,
    Middle TEXT, Organization TEXT, Department TEXT, Note TEXT, Kind INTEGER,
    CreationDate INTEGER, ModificationDate INTEGER);
CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, property INTEGER,
    identifier INTEGER, label INTEGER, value TEXT, guid TEXT);
"""

# Subset of the CoreData CallHistory model (ZCALLRECORD).
CALLHISTORY_DDL = """
CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
    ZANSWERED INTEGER, ZCALLTYPE INTEGER, ZDISCONNECTED_CAUSE INTEGER, ZFACE_TIME_DATA BLOB,
    ZNUMBER_AVAILABILITY INTEGER, ZORIGINATED INTEGER, ZREAD INTEGER, ZDATE TIMESTAMP,
    ZDURATION FLOAT, ZADDRESS VARCHAR, ZDEVICE_ID VARCHAR, ZISO_COUNTRY_CODE VARCHAR,
    ZLOCATION VARCHAR, ZNAME VARCHAR, ZSERVICE_PROVIDER VARCHAR, ZUNIQUE_ID VARCHAR);
"""

# Subset of the Safari History.db schema.
SAFARI_DDL = """
CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
    domain_expansion TEXT NULL, visit_count INTEGER NOT NULL DEFAULT 0,
    daily_visit_counts BLOB NOT NULL DEFAULT x'', weekly_visit_counts BLOB NULL,
    autocomplete_triggers BLOB NULL,
    should_recompute_derived_visit_counts INTEGER NOT NULL DEFAULT 0,
    visit_count_score INTEGER NOT NULL DEFAULT 0);
CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE,
    visit_time REAL NOT NULL, title TEXT NULL, load_successful BOOLEAN NOT NULL DEFAULT 1,
    http_non_get BOOLEAN NOT NULL DEFAULT 0, synthesized BOOLEAN NOT NULL DEFAULT 0,
    redirect_source INTEGER NULL UNIQUE, redirect_destination INTEGER NULL UNIQUE,
    origin INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0,
    attributes INTEGER NOT NULL DEFAULT 0, score INTEGER NOT NULL DEFAULT 0);
"""

# Subset of the WhatsApp ChatStorage.sqlite Core Data model.
CHATSTORAGE_DDL = """
CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
    ZSESSIONTYPE INTEGER, ZUNREADCOUNT INTEGER, ZLASTMESSAGEDATE TIMESTAMP,
    ZCONTACTJID VARCHAR, ZPARTNERNAME VARCHAR, ZLASTMESSAGETEXT VARCHAR);
CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
    ZCHATSESSION INTEGER, ZISFROMME INTEGER, ZMESSAGESTATUS INTEGER, ZMESSAGETYPE INTEGER,
    ZMESSAGEDATE TIMESTAMP, ZSENTDATE TIMESTAMP, ZFROMJID VARCHAR, ZTOJID VARCHAR,
    ZSTANZAID VARCHAR, ZTEXT VARCHAR);
CREATE TABLE ZWAPROFILEPUSHNAME (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
    ZJID VARCHAR, ZPUSHNAME VARCHAR);
"""

AB_PHONE = 3
AB_EMAIL = 4
SERVICE_TELEPHONY = "com.apple.Telephony"
SERVICE_FACETIME = "com.apple.FaceTime"


def cocoa_seconds(dt: datetime) -> int:
    """datetime (UTC) -> Cocoa epoch seconds (since 2001-01-01)."""
    return int((dt - COCOA_EPOCH).total_seconds())


def cocoa_ns(dt: datetime) -> int:
    """datetime (UTC) -> Cocoa epoch nanoseconds (iOS 11+ sms.db)."""
    return cocoa_seconds(dt) * 1_000_000_000


def make_db(path: Path, ddl: str, rows: list[tuple[str, tuple]],
            wal_rows: list[tuple[str, tuple]] | None = None) -> Path:
    """Create a SQLite db at path from ddl + rows.

    With wal_rows, the db is switched to WAL mode and wal_rows are left
    UNcheckpointed in <path>-wal (with <path>-shm) — as on a live iPhone. The
    files are snapshotted while the connection is open, because close() would
    checkpoint the WAL into the main file and delete it.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(ddl)
        for sql, params in rows:
            conn.execute(sql, params)
        conn.commit()
        if wal_rows is None:
            return path
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        for sql, params in wal_rows:
            conn.execute(sql, params)
        conn.commit()
        snapshot = {
            suffix: Path(str(path) + suffix).read_bytes()
            for suffix in ("", "-wal", "-shm")
            if Path(str(path) + suffix).is_file()
        }
    finally:
        conn.close()
    for suffix, data in snapshot.items():
        Path(str(path) + suffix).write_bytes(data)
    return path


def sms_message(rowid: int, text: str | None, handle_id: int, date: int, from_me: int):
    return (
        "INSERT INTO message (ROWID, guid, text, handle_id, service, date, is_from_me) "
        "VALUES (?, ?, ?, ?, 'iMessage', ?, ?)",
        (rowid, f"msg-{rowid}", text, handle_id, date, from_me),
    )


def sms_handle(rowid: int, ident: str):
    return ("INSERT INTO handle (ROWID, id, service) VALUES (?, ?, 'iMessage')", (rowid, ident))


def sms_chat(rowid: int, ident: str):
    return ("INSERT INTO chat (ROWID, guid, chat_identifier) VALUES (?, ?, ?)",
            (rowid, f"iMessage;-;{ident}", ident))


def sms_attachment(rowid: int, name: str):
    return ("INSERT INTO attachment (ROWID, guid, filename) VALUES (?, ?, ?)",
            (rowid, f"att-{rowid}", name))


def kc_event(pk: int, stream: str, value: str | None, start: float, end: float):
    return (
        "INSERT INTO ZOBJECT (Z_PK, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE) "
        "VALUES (?, ?, ?, ?, ?)",
        (pk, stream, value, start, end),
    )


def ab_person(rowid: int, first: str | None, last: str | None, org: str | None):
    return ("INSERT INTO ABPerson (ROWID, First, Last, Organization) VALUES (?, ?, ?, ?)",
            (rowid, first, last, org))


def ab_value(uid: int, record_id: int, prop: int, value: str):
    return ("INSERT INTO ABMultiValue (UID, record_id, property, value) VALUES (?, ?, ?, ?)",
            (uid, record_id, prop, value))


def call_record(pk: int, address, date: float, duration: float, originated: int,
                answered: int, service: str | None = SERVICE_TELEPHONY):
    """address may be str or bytes — bytes is stored as a BLOB (some iOS versions)."""
    return (
        "INSERT INTO ZCALLRECORD (Z_PK, ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED, "
        "ZSERVICE_PROVIDER) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (pk, address, date, duration, originated, answered, service),
    )


def safari_item(item_id: int, url: str, domain: str | None, visits: int = 1):
    return ("INSERT INTO history_items (id, url, domain_expansion, visit_count) VALUES (?, ?, ?, ?)",
            (item_id, url, domain, visits))


def safari_visit(visit_id: int, item_id: int, visit_time: float, title: str | None):
    return ("INSERT INTO history_visits (id, history_item, visit_time, title) VALUES (?, ?, ?, ?)",
            (visit_id, item_id, visit_time, title))


def wa_session(pk: int, jid: str, partner: str | None, session_type: int = 0):
    return ("INSERT INTO ZWACHATSESSION (Z_PK, ZCONTACTJID, ZPARTNERNAME, ZSESSIONTYPE) "
            "VALUES (?, ?, ?, ?)", (pk, jid, partner, session_type))


def wa_message(pk: int, session: int | None, from_me: int, date: float, text: str | None,
               message_type: int = 0):
    return ("INSERT INTO ZWAMESSAGE (Z_PK, ZCHATSESSION, ZISFROMME, ZMESSAGEDATE, ZTEXT, "
            "ZMESSAGETYPE) VALUES (?, ?, ?, ?, ?, ?)",
            (pk, session, from_me, date, text, message_type))


def wa_push(pk: int, jid: str, name: str | None):
    return ("INSERT INTO ZWAPROFILEPUSHNAME (Z_PK, ZJID, ZPUSHNAME) VALUES (?, ?, ?)",
            (pk, jid, name))


def build_ios_tree(root: Path) -> list[Path]:
    """Write the sample iOS FFS tree under root; return every file written."""
    root = Path(root)
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    t = lambda minutes: cocoa_ns(base.replace(minute=minutes))  # noqa: E731

    sms = make_db(
        root / SMS_PATH, SMS_DDL,
        rows=[
            sms_handle(1, "+15550100"), sms_handle(2, "analyst@example.org"),
            sms_chat(1, "+15550100"), sms_chat(2, "analyst@example.org"),
            sms_message(1, "Meet at the usual place", 1, t(1), 0),
            sms_message(2, "On my way", 1, t(2), 1),
            sms_message(3, "Bring the drive", 2, t(3), 0),
            sms_attachment(1, "~/Library/SMS/Attachments/ab/IMG_0001.HEIC"),
        ],
        # Only visible once the WAL is replayed.
        wal_rows=[
            sms_message(4, "Drive is in locker 12", 2, t(4), 1),
            sms_message(5, "Delete this thread", 2, t(5), 0),
        ],
    )

    day = cocoa_seconds(base)
    knowledgec = make_db(
        root / KNOWLEDGEC_PATH, KNOWLEDGEC_DDL,
        rows=[
            kc_event(1, "/app/usage", "com.apple.MobileSMS", day, day + 120),
            kc_event(2, "/app/usage", "com.apple.mobilesafari", day + 300, day + 900),
            kc_event(3, "/app/usage", "com.apple.MobileSMS", day + 1000, day + 1100),
            kc_event(4, "/device/isLocked", None, day + 1200, day + 1300),
            kc_event(5, "/display/isBacklit", None, day + 1400, day + 1500),
        ],
    )

    addressbook = make_db(
        root / ADDRESSBOOK_PATH, ADDRESSBOOK_DDL,
        rows=[
            ab_person(1, "Ana", "Petrova", None),
            ab_person(2, "Marko", None, "Harbour Freight"),
            ab_value(1, 1, AB_PHONE, "+15550100"),
            ab_value(2, 1, AB_EMAIL, "ana@example.org"),
            ab_value(3, 2, AB_EMAIL, "analyst@example.org"),
        ],
    )

    # ZDATE / visit_time: Cocoa SECONDS (REAL), not nanoseconds.
    callhistory = make_db(
        root / CALLHISTORY_PATH, CALLHISTORY_DDL,
        rows=[
            call_record(1, "+15550100", day + 60, 42.4, 0, 1),
            call_record(2, b"+15550111", day + 120, 0.0, 0, 0),  # ZADDRESS as BLOB
            call_record(3, "analyst@example.org", day + 180, 125.6, 1, 1, SERVICE_FACETIME),
        ],
        # Only visible once the WAL is replayed.
        wal_rows=[call_record(4, "+15550112", day + 240, 12.0, 1, 1)],
    )

    safari = make_db(
        root / SAFARI_PATH, SAFARI_DDL,
        rows=[
            safari_item(1, "https://maps.example.com/locker", "maps.example.com", 2),
            safari_item(2, "https://news.example.org/", "news.example.org", 1),
            safari_visit(1, 1, day + 30, "Locker map"),
            safari_visit(2, 2, day + 90, "Morning news"),
            safari_visit(3, 1, day + 150, "Locker map"),
        ],
    )

    # ZMESSAGEDATE: Cocoa SECONDS (REAL).
    group = "120363000000000002@g.us"
    chatstorage = make_db(
        root / CHATSTORAGE_PATH, CHATSTORAGE_DDL,
        rows=[
            wa_session(1, "15550100@s.whatsapp.net", "Ana"),
            wa_session(2, group, "Locker crew", session_type=1),
            wa_push(1, "15550100@s.whatsapp.net", "Ana Petrova"),
            wa_message(1, 1, 0, day + 2400, "Did you get the key?"),
            wa_message(2, 1, 1, day + 2460, PHASE12_FLAG),
            wa_message(3, 2, 0, day + 2520, None, message_type=1),  # image, no caption
        ],
        wal_rows=[wa_message(4, 2, 1, day + 2580, "Moved it to locker 14")],
    )

    readme = root / "readme.txt"
    readme.write_bytes(b"Treska synthetic iOS FFS fixture.\n")
    written = [sms, knowledgec, addressbook, callhistory, safari, chatstorage, readme]
    for db in (sms, callhistory, chatstorage):
        written += [Path(str(db) + s) for s in ("-wal", "-shm") if Path(str(db) + s).is_file()]
    return sorted(written)


def zip_tree(root: Path, files: list[Path], zip_path: Path) -> Path:
    """Zip files (relative to root) with a fixed timestamp."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            info = zipfile.ZipInfo(path.relative_to(root).as_posix(), ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())
    return zip_path


def make_ios_zip(zip_path: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="treska_ios_fixture_") as tmp:
        root = Path(tmp)
        return zip_tree(root, build_ios_tree(root), Path(zip_path))


if __name__ == "__main__":
    print(make_ios_zip(HERE / "ios_sample.zip"))
