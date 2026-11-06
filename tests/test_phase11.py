# Treska Phase 11 — iOS call history, Safari, Chrome history, flag scan.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic databases only, built in tmp_path with the real iOS / Chromium table and
# column names (DDL shared with tests/fixtures/make_*_fixture.py).

from __future__ import annotations

import base64
import importlib.util
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from treska.core import flag_scan
from treska.core.ingestion import cleanup
from treska.core.pipeline import GENERIC_ARTIFACT_NAMES, parse_zip, triage_file
from treska.parsers.android import ANDROID_ARTIFACTS, parse_android_chrome, webkit_us_to_iso
from treska.parsers.ios import (
    IOS_ARTIFACTS,
    apple_to_iso,
    cocoa_s_to_iso,
    parse_ios_callhistory,
    parse_ios_safari,
)
from treska.parsers.sqlite_triage import SAMPLE_CAP, TEXT_CAP, WAL_DIR

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ios_fx = _load("make_ios_fixture")
android_fx = _load("make_android_fixture")

UTC = timezone.utc
FIRST = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
LAST = datetime(2024, 6, 7, 8, 9, 10, tzinfo=UTC)
FIRST_ISO = "2024-01-02T03:04:05Z"
LAST_ISO = "2024-06-07T08:09:10Z"
SQLITE_MIME = "application/vnd.sqlite3"


def _zip(tmp_path: Path, members: dict[str, bytes], name: str = "case.zip") -> Path:
    zip_path = tmp_path / name
    with zipfile.ZipFile(zip_path, "w") as zf:
        for member, data in members.items():
            zf.writestr(member, data)
    return zip_path


def _calls(path: Path, rows, wal_rows=None) -> Path:
    return ios_fx.make_db(path, ios_fx.CALLHISTORY_DDL, rows, wal_rows=wal_rows)


def _safari(path: Path, rows, ddl: str | None = None) -> Path:
    return ios_fx.make_db(path, ddl or ios_fx.SAFARI_DDL, rows)


def _chrome(path: Path, rows, ddl: str | None = None) -> Path:
    return android_fx.make_db(path, ddl or android_fx.CHROME_DDL, rows)


# --- iOS CallHistory.storedata ----------------------------------------------

def test_callhistory_counts_and_directions(tmp_path):
    first, last = ios_fx.cocoa_seconds(FIRST), ios_fx.cocoa_seconds(LAST)
    db = _calls(tmp_path / "CallHistory.storedata", [
        ios_fx.call_record(1, "+15550100", first, 10.4, 0, 1),           # incoming answered
        ios_fx.call_record(2, "+15550101", first + 60, 0.0, 0, 0),       # missed
        ios_fx.call_record(3, "+15550102", first + 120, 0.0, 0, 0),      # missed
        ios_fx.call_record(4, "a@example.org", last, 99.6, 1, 1, ios_fx.SERVICE_FACETIME),
        ios_fx.call_record(5, "+15550103", 0, 5.0, 1, 0, None),          # no date, no service
    ])
    t = parse_ios_callhistory(db, "CallHistory.storedata")
    assert t["format"] == "ios_callhistory" and t["status"] == "parsed", t
    assert t["summary"] == {
        "total": 5, "incoming": 3, "outgoing": 2, "answered": 1, "missed": 2,
        "by_service": {"com.apple.Telephony": 3, "com.apple.FaceTime": 1, "unknown": 1},
        "total_duration_seconds": 115,  # round(10.4 + 99.6 + 5.0)
        "first_call": FIRST_ISO, "last_call": LAST_ISO,
    }
    assert len(t["samples"]) == SAMPLE_CAP
    assert t["samples"][0] == {"time": LAST_ISO, "direction": "outgoing", "address": "a@example.org",
                               "duration_seconds": 100, "service": "com.apple.FaceTime"}
    assert t["samples"][1]["direction"] == "incoming"


def test_callhistory_zaddress_blob_decoded(tmp_path):
    """Q3 named exception: a BLOB ZADDRESS is decoded UTF-8 (errors=replace), TEXT_CAP applies."""
    when = ios_fx.cocoa_seconds(FIRST)
    db = _calls(tmp_path / "CallHistory.storedata", [
        ios_fx.call_record(1, b"+15550111", when + 3, 1.0, 0, 1),
        ios_fx.call_record(2, b"\xff\xfe+1555", when + 2, 1.0, 0, 1),     # invalid UTF-8
        ios_fx.call_record(3, b"9" * (TEXT_CAP + 50), when + 1, 1.0, 0, 1),
    ])
    samples = parse_ios_callhistory(db, "CallHistory.storedata")["samples"]
    assert samples[0]["address"] == "+15550111"
    assert samples[1]["address"] == "��+1555"
    assert samples[2]["address"] == "9" * TEXT_CAP


def test_callhistory_wal_applied_and_fixed_cocoa_seconds(tmp_path):
    when = ios_fx.cocoa_seconds(FIRST)
    db = _calls(tmp_path / "CallHistory.storedata",
                rows=[ios_fx.call_record(1, "+15550100", when, 1.0, 0, 1)],
                wal_rows=[ios_fx.call_record(2, "+15550199", ios_fx.cocoa_seconds(LAST), 2.0, 1, 1)])
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    t = parse_ios_callhistory(db, "CallHistory.storedata", work_dir=tmp_path / "work")
    assert t["wal_present"] is True and t["wal_applied"] is True
    assert t["summary"]["total"] == 2 and t["summary"]["last_call"] == LAST_ISO
    # Evidence untouched: the copy lives under work_dir/WAL_DIR.
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.name != "work"} == before
    assert (tmp_path / "work" / WAL_DIR).is_dir()


def test_cocoa_s_to_iso_is_a_fixed_unit():
    assert cocoa_s_to_iso(ios_fx.cocoa_seconds(FIRST)) == FIRST_ISO
    assert cocoa_s_to_iso(ios_fx.cocoa_seconds(FIRST) + 0.75) == FIRST_ISO
    for empty in (None, 0, b"\x01", "x", float("nan")):
        assert cocoa_s_to_iso(empty) is None
    # A huge value is NOT reinterpreted as nanoseconds (that is apple_to_iso's heuristic).
    huge = ios_fx.cocoa_ns(FIRST)
    assert apple_to_iso(huge) == FIRST_ISO
    assert cocoa_s_to_iso(huge) != FIRST_ISO


def test_callhistory_missing_columns_warn_and_null(tmp_path):
    ddl = ("CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZORIGINATED INTEGER, "
           "ZDATE TIMESTAMP, ZADDRESS VARCHAR);")
    db = ios_fx.make_db(tmp_path / "CallHistory.storedata", ddl, [
        ("INSERT INTO ZCALLRECORD VALUES (1, 0, ?, '+1')", (ios_fx.cocoa_seconds(FIRST),)),
    ])
    t = parse_ios_callhistory(db, "CallHistory.storedata")
    assert t["status"] == "parsed"
    s = t["summary"]
    assert s["incoming"] == 1 and s["answered"] is None and s["missed"] is None
    assert s["by_service"] is None and s["total_duration_seconds"] is None
    assert "missing column ZCALLRECORD.ZANSWERED" in t["warnings"]
    assert t["samples"][0]["service"] is None and t["samples"][0]["duration_seconds"] is None


# --- iOS Safari History.db --------------------------------------------------

def test_safari_counts_and_top_domains(tmp_path):
    first, last = ios_fx.cocoa_seconds(FIRST), ios_fx.cocoa_seconds(LAST)
    db = _safari(tmp_path / "History.db", [
        ios_fx.safari_item(1, "https://a.example/1", "a.example"),
        ios_fx.safari_item(2, "https://a.example/2", "a.example"),
        ios_fx.safari_item(3, "https://b.example/", "b.example"),
        ios_fx.safari_item(4, "https://c.example/", None),
        ios_fx.safari_visit(1, 1, first, "A1"),
        ios_fx.safari_visit(2, 2, first + 10, "A2"),
        ios_fx.safari_visit(3, 3, first + 20, "B"),
        ios_fx.safari_visit(4, 1, first + 30, "A1 again"),
        ios_fx.safari_visit(5, 4, last, "<b>C</b>"),
    ])
    t = parse_ios_safari(db, "History.db")
    assert t["format"] == "ios_safari" and t["status"] == "parsed" and t["warnings"] == []
    assert t["summary"] == {
        "url_count": 4, "visit_count": 5, "domain_count": 2,
        "top_domains": [{"domain": "a.example", "count": 3}, {"domain": "b.example", "count": 1},
                        {"domain": "unknown", "count": 1}],
        "first_visit": FIRST_ISO, "last_visit": LAST_ISO,
    }
    assert t["samples"][0] == {"time": LAST_ISO, "title": "<b>C</b>", "url": "https://c.example/"}
    assert len(t["samples"]) == SAMPLE_CAP


def test_safari_missing_domain_expansion(tmp_path):
    ddl = ("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT);"
           "CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, "
           "visit_time REAL, title TEXT);")
    db = _safari(tmp_path / "History.db", [
        ("INSERT INTO history_items VALUES (1, 'https://x.example/')", ()),
        ("INSERT INTO history_visits VALUES (1, 1, ?, 'X')", (ios_fx.cocoa_seconds(FIRST),)),
    ], ddl=ddl)
    t = parse_ios_safari(db, "History.db")
    assert t["status"] == "parsed"
    assert t["summary"]["domain_count"] is None and t["summary"]["top_domains"] is None
    assert "missing column history_items.domain_expansion" in t["warnings"]
    assert t["samples"] == [{"time": FIRST_ISO, "title": "X", "url": "https://x.example/"}]


def test_safari_generic_name_skipped_not_corrupt(tmp_path):
    """Q1: History.db is generic — not SQLite, or SQLite without BOTH required tables,
    is some other app's file: triage None. Non-generic names stay corrupt-not-skipped."""
    text = tmp_path / "text" / "History.db"
    text.parent.mkdir()
    text.write_bytes(b"just a text file named History.db\n")
    foreign = ios_fx.make_db(tmp_path / "foreign" / "History.db",
                             "CREATE TABLE history (id INTEGER, cmd TEXT);", [])
    partial = ios_fx.make_db(tmp_path / "partial" / "History.db",
                             "CREATE TABLE history_items (id INTEGER, url TEXT);", [])
    real = _safari(tmp_path / "real" / "History.db",
                   [ios_fx.safari_item(1, "https://a.example/", "a.example")])
    for path in (text, foreign, partial):
        assert triage_file(path, "x/History.db", "db", SQLITE_MIME, "IOS_FFS") is None
    assert triage_file(real, "x/HISTORY.DB", "db", SQLITE_MIME, "IOS_FFS")["status"] == "parsed"
    # Unchanged rule for every non-generic artifact name: no header -> corrupt.
    for name in ("sms.db", "CallHistory.storedata"):
        t = triage_file(text, f"x/{name}", "db", "text/plain", "IOS_FFS")
        assert t["status"] == "corrupt" and t["error"] == "not a SQLite database"


# --- Android Chrome History -------------------------------------------------

def test_chrome_counts_and_search_term_samples(tmp_path):
    w = android_fx.webkit_us
    db = _chrome(tmp_path / "History", [
        android_fx.chrome_url(1, "https://a.example/x", "A", w(FIRST), 3, 2),
        android_fx.chrome_url(2, "https://a.example/y", "A2", w(FIRST), 1, 1),
        android_fx.chrome_url(3, "https://www.google.com/search?q=secret", "secret - Google", w(LAST)),
        android_fx.chrome_visit(1, 1, w(FIRST)),
        android_fx.chrome_visit(2, 1, w(FIRST) + 1_000_000),
        android_fx.chrome_visit(3, 2, w(FIRST) + 2_000_000),
        android_fx.chrome_visit(4, 3, w(LAST)),
        android_fx.chrome_search(3, "secret"),
    ])
    t = parse_android_chrome(db, "History")
    assert t["format"] == "android_chrome" and t["status"] == "parsed" and t["warnings"] == []
    assert t["summary"] == {
        "url_count": 3, "visit_count": 4, "typed_count": 3, "search_term_count": 1,
        "top_domains": [{"domain": "a.example", "count": 3}, {"domain": "www.google.com", "count": 1}],
        "first_visit": FIRST_ISO, "last_visit": LAST_ISO,
    }
    # Q2: ≤ SAMPLE_CAP visits + ≤ SAMPLE_CAP searches, one uniform key set.
    visits = [s for s in t["samples"] if s["kind"] == "visit"]
    searches = [s for s in t["samples"] if s["kind"] == "search"]
    assert len(visits) == SAMPLE_CAP and len(searches) == 1
    assert all(set(s) == {"kind", "time", "title", "url", "term"} for s in t["samples"])
    assert visits[0] == {"kind": "visit", "time": LAST_ISO, "title": "secret - Google",
                         "url": "https://www.google.com/search?q=secret", "term": None}
    assert searches[0] == {"kind": "search", "time": LAST_ISO, "title": "secret - Google",
                           "url": "https://www.google.com/search?q=secret", "term": "secret"}


def test_chrome_without_keyword_search_terms(tmp_path):
    ddl = android_fx.CHROME_DDL.split("CREATE TABLE keyword_search_terms")[0]
    db = _chrome(tmp_path / "History", [
        android_fx.chrome_url(1, "https://a.example/", "A", android_fx.webkit_us(FIRST)),
        android_fx.chrome_visit(1, 1, android_fx.webkit_us(FIRST)),
    ], ddl=ddl)
    t = parse_android_chrome(db, "History")
    assert t["status"] == "parsed"
    assert t["summary"]["search_term_count"] is None
    assert "missing table keyword_search_terms" in t["warnings"]
    assert [s["kind"] for s in t["samples"]] == ["visit"]


def test_webkit_us_to_iso():
    assert webkit_us_to_iso(android_fx.webkit_us(FIRST)) == FIRST_ISO
    assert webkit_us_to_iso(13_000_000_000_000_000) == "2012-12-14T23:06:40Z"
    for empty in (None, 0, b"\x00", "nope"):
        assert webkit_us_to_iso(empty) is None


def test_chrome_generic_name_skipped_not_corrupt(tmp_path):
    """Q1: `History` (no extension) is generic: shell history, other apps' files -> None."""
    shell = tmp_path / "shell" / "history"
    shell.parent.mkdir()
    shell.write_bytes(b"ls -la\ncat flag.txt\n")
    foreign = android_fx.make_db(tmp_path / "foreign" / "History",
                                 "CREATE TABLE urls (id INTEGER, url TEXT);", [])
    real = _chrome(tmp_path / "real" / "History", [])
    for path in (shell, foreign):
        assert triage_file(path, "x/History", "", SQLITE_MIME, "ANDROID_LOGICAL") is None
    t = triage_file(real, "x/History", "", SQLITE_MIME, "ANDROID_LOGICAL")
    assert t["format"] == "android_chrome" and t["status"] == "empty"
    # The Android-only name gets nothing in an iOS tree; non-generic names stay corrupt.
    assert triage_file(real, "x/History", "", SQLITE_MIME, "IOS_FFS") is None
    assert triage_file(shell, "x/mmssms.db", "db", "text/plain", "ANDROID_LOGICAL")["status"] == "corrupt"


def test_phase11_dispatch_tables_pinned():
    assert set(IOS_ARTIFACTS) == {"sms.db", "knowledgec.db", "addressbook.sqlitedb",
                                  "callhistory.storedata", "history.db"}
    assert set(ANDROID_ARTIFACTS) == {"mmssms.db", "contacts2.db", "calllog.db", "history"}
    assert GENERIC_ARTIFACT_NAMES == frozenset({"history", "history.db"})
    assert IOS_ARTIFACTS["callhistory.storedata"][0] == "ios_callhistory"
    assert IOS_ARTIFACTS["history.db"][0] == "ios_safari"
    assert ANDROID_ARTIFACTS["history"][0] == "android_chrome"


# --- flag scan ----------------------------------------------------------------

def _scan(tmp_path: Path, data: bytes, name: str = "blob.bin") -> list[dict]:
    path = tmp_path / name
    path.write_bytes(data)
    return flag_scan.scan_file(path, display=name)


def test_flag_scan_all_prefixes_exact_case(tmp_path):
    data = (b"..flag{one}..ctf{two}..FLAG{three}..CTF{four}.."
            b"Flag{no}..Ctf{no}..fLaG{no}..flag{unclosed ..flag{}..")
    hits = _scan(tmp_path, data)
    assert [(h["encoding"], h["match"]) for h in hits] == [
        ("ascii", "flag{one}"), ("ascii", "ctf{two}"), ("ascii", "FLAG{three}"), ("ascii", "CTF{four}")]
    assert hits[0] == {"path": "blob.bin", "offset": 2, "encoding": "ascii", "match": "flag{one}"}


def test_flag_scan_utf16le(tmp_path):
    data = b"\x00\x01" + "header CTF{wide_flag} trailer".encode("utf-16-le")
    hits = _scan(tmp_path, data)
    assert hits == [{"path": "blob.bin", "offset": 2 + 14, "encoding": "utf-16le",
                     "match": "CTF{wide_flag}"}]


@pytest.mark.parametrize("align", [0, 1, 2])
def test_flag_scan_base64_each_alignment(tmp_path, align):
    flag = f"flag{{aligned_{align}}}".encode()
    encoded = base64.b64encode(b"Z" * align + flag + b" and more text")
    assert (len(b"Z" * align) % 3) == align  # the prefix starts `align` bytes into a group
    hits = _scan(tmp_path, b"note: " + encoded + b"\n")
    assert [(h["encoding"], h["match"]) for h in hits] == [("base64", flag.decode())]
    # Base64 that decodes to a prefix without a full flag is not a hit.
    assert _scan(tmp_path, base64.b64encode(b"Z" * align + b"flag{never closed"), "x.bin") == []


def test_flag_scan_chunk_boundary(tmp_path):
    for cut in (1, 3, 5):  # the needle itself straddles the chunk edge
        data = b"A" * (flag_scan.CHUNK_SIZE - cut) + b"flag{straddle}" + b"B" * 64
        hits = _scan(tmp_path, data, f"edge{cut}.bin")
        assert [(h["offset"], h["match"]) for h in hits] == [
            (flag_scan.CHUNK_SIZE - cut, "flag{straddle}")]


def test_flag_scan_per_file_cap_and_dedupe(tmp_path):
    many = b" ".join(b"flag{n%02d}" % i for i in range(flag_scan.PER_FILE_CAP + 5))
    hits = _scan(tmp_path, many)
    assert len(hits) == flag_scan.PER_FILE_CAP
    assert [h["match"] for h in hits] == [f"flag{{n{i:02d}}}" for i in range(flag_scan.PER_FILE_CAP)]
    # The same flag repeated (and in another encoding) is reported once per file.
    again = b"flag{same} flag{same} " + "flag{same}".encode("utf-16-le")
    assert [h["match"] for h in _scan(tmp_path, again, "dupe.bin")] == ["flag{same}"]


def test_flag_scan_total_cap(tmp_path):
    members = {
        f"f{f}.txt": b" ".join(b"ctf{f%d_%d}" % (f, i) for i in range(flag_scan.PER_FILE_CAP))
        for f in range(6)
    }
    result = parse_zip(_zip(tmp_path, members))
    assert len(result.flag_hits) == flag_scan.FLAG_HIT_CAP
    assert [(h["path"], h["offset"]) for h in result.flag_hits] == sorted(
        (h["path"], h["offset"]) for h in result.flag_hits)
    assert {h["path"] for h in result.flag_hits} <= set(members)


def test_no_flag_scan_gives_null(tmp_path):
    zip_path = _zip(tmp_path, {"notes.txt": b"flag{hidden}"})
    assert [h["match"] for h in parse_zip(zip_path).flag_hits] == ["flag{hidden}"]
    assert parse_zip(zip_path, no_flag_scan=True).flag_hits is None
    assert flag_scan.scan_zip([tmp_path / "anything"], skip=True) is None


def test_flag_scan_never_reads_wal_copies(tmp_path, monkeypatch):
    """The scan reads extracted originals only — never anything under .treska_wal."""
    zip_path = FIXTURES / "android_sample.zip"  # mmssms.db + contacts2.db ship -wal sidecars
    scanned: list[Path] = []
    real_scan_file = flag_scan.scan_file

    def spy(path, display=None):
        scanned.append(Path(path))
        return real_scan_file(path, display=display)

    monkeypatch.setattr(flag_scan, "scan_file", spy)
    kept: list[Path] = []
    result = parse_zip(zip_path, keep=True, on_extract=kept.append)
    try:
        temp_dir = kept[0]
        assert (temp_dir / WAL_DIR).is_dir(), "fixture must stage WAL copies"
        assert scanned and all(WAL_DIR not in p.parts for p in scanned)
        assert len(scanned) == result.file_count
        # Direct call with a WAL copy in the list: refused, even with a flag inside.
        planted = temp_dir / WAL_DIR / "x" / "copy.db"
        planted.parent.mkdir(parents=True)
        planted.write_bytes(b"flag{from_wal_copy}")
        scanned.clear()
        assert flag_scan.scan_zip([planted], root=temp_dir) == []
        assert scanned == []
    finally:
        cleanup(kept[0])
