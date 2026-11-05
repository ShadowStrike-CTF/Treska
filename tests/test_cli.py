# Treska CLI tests — run the real CLI in a child interpreter.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parent.parent / "src"
SAMPLE_ZIP = FIXTURES / "sample.zip"


def _run(*args: str, env_extra: dict | None = None, text: bool = True) -> subprocess.CompletedProcess:
    # PYTHONPATH=src so the tests don't depend on the console script being installed.
    env = {**os.environ, "PYTHONPATH": str(SRC), **(env_extra or {})}
    return subprocess.run(
        [sys.executable, "-m", "treska.cli", *args],
        capture_output=True, text=text, env=env,
    )


def test_cli_help():
    proc = _run("--help")
    assert proc.returncode == 0
    assert "zip_path" in proc.stdout
    for flag in ("--json", "--verbose", "--out", "--no-hash", "--keep"):
        assert flag in proc.stdout


def test_cli_nonexistent_file(tmp_path):
    proc = _run(str(tmp_path / "missing.zip"))
    assert proc.returncode == 1
    assert "not found" in proc.stderr


def test_cli_not_a_zip():
    proc = _run(str(FIXTURES / "readme.txt"))
    assert proc.returncode == 2
    assert "parse error" in proc.stderr


def test_cli_valid_zip_default():
    proc = _run(str(SAMPLE_ZIP))
    assert proc.returncode == 0
    assert proc.stdout.strip()


def test_cli_valid_zip_json_flag():
    proc = _run(str(SAMPLE_ZIP), "--json")
    assert proc.returncode == 0
    json.loads(proc.stdout)


def test_cli_valid_zip_json_structure():
    data = json.loads(_run(str(SAMPLE_ZIP), "--json").stdout)
    assert set(data) == {
        "schema_version", "zip_path", "file_count", "flagged", "inventory", "deferred_files",
        "extraction_type",
    }
    assert data["schema_version"] == "1.4.0"
    assert isinstance(data["zip_path"], str)
    assert data["file_count"] == len(data["inventory"])
    for entry in data["inventory"]:
        assert "md5" in entry and "sha256" in entry


def test_cli_verbose_flag():
    proc = _run(str(SAMPLE_ZIP), "--verbose")
    assert proc.returncode == 0
    assert "Inventory" in proc.stdout


def test_cli_json_and_verbose_together():
    proc = _run(str(SAMPLE_ZIP), "--json", "--verbose")
    assert proc.returncode == 0
    json.loads(proc.stdout)


# ---------------------------------------------------------------- Phase 8: --out

def test_cli_out_json_writes_file(tmp_path):
    out = tmp_path / "result.json"
    proc = _run(str(SAMPLE_ZIP), "--json", "--out", str(out))
    assert proc.returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == "1.4.0"
    assert not (tmp_path / "result.json.partial").exists()


def test_cli_out_json_matches_stdout(tmp_path):
    out = tmp_path / "result.json"
    assert _run(str(SAMPLE_ZIP), "--json", "--out", str(out)).returncode == 0
    stdout = _run(str(SAMPLE_ZIP), "--json", text=False).stdout
    assert out.read_bytes() == stdout


def test_cli_out_stdout_only_written_to(tmp_path):
    out = tmp_path / "result.json"
    proc = _run(str(SAMPLE_ZIP), "--json", "--out", str(out))
    assert proc.returncode == 0
    assert proc.stdout == f"Written to: {out.resolve()}\n"
    assert proc.stderr == ""


def test_cli_out_pretty_plain_text(tmp_path):
    out = tmp_path / "result.txt"
    proc = _run(str(SAMPLE_ZIP), "--verbose", "--out", str(out))
    assert proc.returncode == 0
    assert proc.stdout == f"Written to: {out.resolve()}\n"
    text = out.read_text(encoding="utf-8")
    assert "\x1b[" not in text
    assert "schema 1.4.0" in text and "files" in text and "flagged" in text
    assert "Inventory" in text


def test_cli_out_unwritable_exit_3(tmp_path):
    out = tmp_path / "no_such_dir" / "result.json"
    proc = _run(str(SAMPLE_ZIP), "--json", "--out", str(out))
    assert proc.returncode == 3
    assert proc.stderr.startswith(f"treska: cannot write output: {out.resolve()}: ")
    assert proc.stdout == ""
    assert not out.exists()
    assert not out.parent.exists()


def test_cli_out_parse_error_no_file(tmp_path):
    out = tmp_path / "result.json"
    proc = _run(str(FIXTURES / "readme.txt"), "--json", "--out", str(out))
    assert proc.returncode == 2
    assert "parse error" in proc.stderr
    assert not out.exists()
    assert not (tmp_path / "result.json.partial").exists()


def test_cli_out_parse_error_keeps_existing_file(tmp_path):
    out = tmp_path / "result.json"
    out.write_text("previous run", encoding="utf-8")
    proc = _run(str(FIXTURES / "readme.txt"), "--out", str(out))
    assert proc.returncode == 2
    assert out.read_text(encoding="utf-8") == "previous run"


# ---------------------------------------------------------------- Phase 8: --no-hash

def test_cli_no_hash_json_nulls():
    data = json.loads(_run(str(SAMPLE_ZIP), "--no-hash", "--json").stdout)
    assert data["inventory"]
    for entry in data["inventory"] + data["flagged"]:
        assert "md5" in entry and "sha256" in entry
        assert entry["md5"] is None and entry["sha256"] is None


def test_cli_no_hash_pretty_dash():
    proc = _run(str(SAMPLE_ZIP), "--no-hash", "--verbose")
    assert proc.returncode == 0
    assert "md5    —" in proc.stdout
    assert "sha256 —" in proc.stdout


def test_cli_no_hash_keeps_mismatch():
    hashed = json.loads(_run(str(SAMPLE_ZIP), "--json").stdout)
    unhashed = json.loads(_run(str(SAMPLE_ZIP), "--no-hash", "--json").stdout)
    entry = next(e for e in unhashed["inventory"] if e["path"] == "evidence/mismatch.txt")
    assert entry["mismatch"] is True
    # INV-04: --no-hash changes hashes only — mismatch and flags are identical.
    assert [(e["path"], e["mismatch"], e["flags"]) for e in unhashed["inventory"]] == \
           [(e["path"], e["mismatch"], e["flags"]) for e in hashed["inventory"]]


# ---------------------------------------------------------------- Phase 8: --keep

def _treska_dirs(root: Path) -> list[Path]:
    return [p for p in root.iterdir() if p.is_dir() and p.name.startswith("treska_")]


def test_cli_keep_leaves_dir(tmp_path):
    proc = _run(str(SAMPLE_ZIP), "--keep", "--json", env_extra={"TMPDIR": str(tmp_path)})
    assert proc.returncode == 0
    json.loads(proc.stdout)  # stdout stays pure JSON — Kept: goes to stderr
    match = re.search(r"^Kept: (.+)$", proc.stderr, re.MULTILINE)
    assert match
    kept = Path(match.group(1))
    try:
        assert kept.is_dir()
        assert (kept / "readme.txt").is_file()
    finally:
        shutil.rmtree(kept, ignore_errors=True)


def test_cli_default_cleans_temp(tmp_path):
    proc = _run(str(SAMPLE_ZIP), "--json", env_extra={"TMPDIR": str(tmp_path)})
    assert proc.returncode == 0
    assert "Kept:" not in proc.stderr
    assert _treska_dirs(tmp_path) == []
