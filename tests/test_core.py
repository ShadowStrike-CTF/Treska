# Treska core library tests.
# © 2026 Strategos Pty Ltd. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from treska.core.hashing import PARALLEL_THRESHOLD, compute_hashes
from treska.core.heuristics import flag_file
from treska.core.ingestion import cleanup, extract
from treska.core.inventory import build_inventory
from treska.core.magic_check import check_magic
from treska.core.output import FileEntry, ParseResult, build_parse_result
from treska.core.pipeline import parse_zip
from treska.core.sqlite_probe import probe_sqlite

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parents[1] / "src"
SAMPLE_ZIP = FIXTURES / "sample.zip"
SAMPLE_MEMBERS = {
    "readme.txt",
    "evidence/mismatch.txt",
    "evidence/image.png",
    "evidence/empty.bin",
    "db/sample.db",
}


def _entry(path: str, flags: list[str]) -> FileEntry:
    return FileEntry(
        path=path, size_bytes=1, extension="", zip_timestamp=None,
        magic_type="data", mime="application/octet-stream", mismatch=False,
        flags=flags, md5=None, sha256=None, sqlite_schema=None,
    )


# --- ingestion -------------------------------------------------------------

def test_ingestion_extracts():
    temp_dir, files = extract(SAMPLE_ZIP)
    try:
        assert len(files) == len(SAMPLE_MEMBERS)
        assert {f.relative_to(temp_dir).as_posix() for f in files} == SAMPLE_MEMBERS
        assert all(f.is_file() for f in files)
    finally:
        cleanup(temp_dir)


def test_ingestion_cleanup():
    # Run in a child interpreter so the atexit cleanup genuinely fires on exit.
    script = (
        "import sys; sys.path.insert(0, sys.argv[1])\n"
        "from pathlib import Path\n"
        "from treska.core.ingestion import extract\n"
        "temp_dir, files = extract(Path(sys.argv[2]), keep=False)\n"
        "print(temp_dir)\n"
        "print(temp_dir.is_dir() and all(f.is_file() for f in files))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, str(SRC), str(SAMPLE_ZIP)],
        capture_output=True, text=True, check=True,
    )
    temp_line, existed_line = proc.stdout.strip().splitlines()
    assert existed_line == "True"
    assert not Path(temp_line).exists()


def test_ingestion_keep_persists():
    temp_dir, files = extract(SAMPLE_ZIP, keep=True)
    try:
        assert temp_dir.is_dir() and files
    finally:
        cleanup(temp_dir)
    assert not temp_dir.exists()


def test_ingestion_invalid_zip(tmp_path):
    not_zip = tmp_path / "fake.zip"
    not_zip.write_text("definitely not a zip")
    with pytest.raises(ValueError):
        extract(not_zip)
    with pytest.raises(ValueError):
        extract(tmp_path / "missing.zip")


def test_inventory_paths_and_timestamps():
    temp_dir, files = extract(SAMPLE_ZIP)
    try:
        for rows in (build_inventory(files, SAMPLE_ZIP, root=temp_dir),
                     build_inventory(files, SAMPLE_ZIP)):
            assert {r["path"] for r in rows} == SAMPLE_MEMBERS
            assert all(r["zip_timestamp"] == "2026-09-25T12:30:00" for r in rows)
            by_path = {r["path"]: r for r in rows}
            assert by_path["db/sample.db"]["extension"] == "db"
            assert by_path["evidence/empty.bin"]["size_bytes"] == 0
    finally:
        cleanup(temp_dir)


# --- magic -----------------------------------------------------------------

def test_magic_mismatch_detected():
    result = check_magic(FIXTURES / "mismatch.txt")
    assert result["extension"] == "txt"
    assert result["mismatch"] is True
    assert "PNG" in result["magic_type"]
    assert result["mime"] == "image/png"


def test_magic_no_mismatch():
    assert check_magic(FIXTURES / "readme.txt")["mismatch"] is False
    assert check_magic(FIXTURES / "sample.db")["mismatch"] is False


def test_magic_unreadable_file(tmp_path):
    result = check_magic(tmp_path / "does_not_exist.png")
    assert result["magic_type"] == "unknown"
    assert result["mismatch"] is False


# --- sqlite ----------------------------------------------------------------

def test_sqlite_detected():
    db = FIXTURES / "sample.db"
    flags = flag_file(db, [db.stat().st_size], check_magic(db))
    assert "sqlite" in flags


def test_sqlite_probe_returns_schema():
    db = FIXTURES / "sample.db"
    before = db.read_bytes()
    schema = probe_sqlite(db)
    assert schema is not None
    tables = {t["name"]: [c["name"] for c in t["columns"]] for t in schema["tables"]}
    assert tables["messages"] == ["id", "sender", "body", "sent_at"]
    assert tables["contacts"] == ["id", "name", "phone"]
    assert db.read_bytes() == before  # read-only
    assert not db.with_name("sample.db-journal").exists()


def test_sqlite_probe_non_sqlite():
    assert probe_sqlite(FIXTURES / "readme.txt") is None
    assert probe_sqlite(FIXTURES / "mismatch.txt") is None


# --- heuristics ------------------------------------------------------------

def test_heuristics_zero_bytes():
    empty = FIXTURES / "empty.bin"
    assert "zero_bytes" in flag_file(empty, [0, 10, 20], check_magic(empty))


def test_heuristics_no_extension(tmp_path):
    f = tmp_path / "README"
    f.write_text("plain text\n")
    assert "no_extension" in flag_file(f, [f.stat().st_size], check_magic(f))


def test_heuristics_double_extension(tmp_path):
    f = tmp_path / "photo.jpg.exe"
    f.write_bytes(b"not really an exe")
    assert "suspicious_name" in flag_file(f, [f.stat().st_size], check_magic(f))


def test_heuristics_benign_double_extension_not_flagged(tmp_path):
    f = tmp_path / "backup.tar.gz"
    f.write_bytes(b"x")
    assert "suspicious_name" not in flag_file(f, [1], check_magic(f))


def test_heuristics_size_outlier(tmp_path):
    f = tmp_path / "big.txt"
    f.write_text("a" * 100)
    assert "size_outlier" in flag_file(f, [10, 10, 10, 100], check_magic(f))
    assert "size_outlier" not in flag_file(f, [100, 100, 100], check_magic(f))


# --- hashing ---------------------------------------------------------------

def test_no_hash_columns_present():
    readme = FIXTURES / "readme.txt"
    hashes = compute_hashes([readme], skip=True)
    assert hashes == {readme: (None, None)}
    md5, sha256 = hashes[readme]
    entry = FileEntry(
        path="readme.txt", size_bytes=readme.stat().st_size, extension="txt",
        zip_timestamp=None, magic_type="ASCII text", mime="text/plain",
        mismatch=False, flags=[], md5=md5, sha256=sha256, sqlite_schema=None,
    )
    assert entry.md5 is None and entry.sha256 is None
    as_dict = asdict(entry)
    assert "md5" in as_dict and "sha256" in as_dict
    dumped = json.loads(json.dumps(as_dict))
    assert dumped["md5"] is None and dumped["sha256"] is None


def test_hash_correct():
    readme = FIXTURES / "readme.txt"
    data = readme.read_bytes()
    assert compute_hashes([readme])[readme] == (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def test_hash_threadpool_path(tmp_path):
    paths = []
    for i in range(PARALLEL_THRESHOLD + 5):
        p = tmp_path / f"f{i}.txt"
        p.write_text(str(i))
        paths.append(p)
    hashes = compute_hashes(paths)
    assert len(hashes) == len(paths)
    for p in paths:
        assert hashes[p][1] == hashlib.sha256(p.read_bytes()).hexdigest()


# --- output ----------------------------------------------------------------

def test_parse_result_flagged_subset():
    entries = [
        _entry("b.txt", []),
        _entry("a.bin", ["zero_bytes"]),
        _entry("c.db", ["sqlite", "magic_mismatch"]),
    ]
    result = build_parse_result("x.zip", entries)
    assert [e.path for e in result.inventory] == ["a.bin", "b.txt", "c.db"]
    assert [e.path for e in result.flagged] == ["c.db", "a.bin"]
    assert result.file_count == 3
    # same objects, not copies
    for f in result.flagged:
        assert any(f is e for e in result.inventory)
    assert all(e.flags for e in result.flagged)


def test_schema_version():
    assert ParseResult().schema_version == "1.0.0"


# --- pipeline --------------------------------------------------------------

def test_parse_zip_end_to_end():
    result = parse_zip(SAMPLE_ZIP)
    assert result.schema_version == "1.0.0"
    assert result.file_count == len(SAMPLE_MEMBERS)
    by_path = {e.path: e for e in result.inventory}
    assert set(by_path) == SAMPLE_MEMBERS
    assert "magic_mismatch" in by_path["evidence/mismatch.txt"].flags
    assert by_path["evidence/image.png"].mismatch is False
    assert "zero_bytes" in by_path["evidence/empty.bin"].flags
    db = by_path["db/sample.db"]
    assert "sqlite" in db.flags
    assert {t["name"] for t in db.sqlite_schema["tables"]} == {"contacts", "messages"}
    assert all(e.md5 and e.sha256 for e in result.inventory)
    assert all(not e.path.startswith("/") and "treska_" not in e.path for e in result.inventory)


def test_parse_zip_no_hash():
    result = parse_zip(SAMPLE_ZIP, no_hash=True)
    assert all(e.md5 is None and e.sha256 is None for e in result.inventory)
