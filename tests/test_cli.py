# Treska CLI tests — run the real CLI in a child interpreter.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parent.parent / "src"
SAMPLE_ZIP = FIXTURES / "sample.zip"


def _run(*args: str) -> subprocess.CompletedProcess:
    # PYTHONPATH=src so the tests don't depend on the console script being installed.
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    return subprocess.run(
        [sys.executable, "-m", "treska.cli", *args],
        capture_output=True, text=True, env=env,
    )


def test_cli_help():
    proc = _run("--help")
    assert proc.returncode == 0
    assert "zip_path" in proc.stdout


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
    assert set(data) == {"schema_version", "zip_path", "file_count", "flagged", "inventory"}
    assert data["schema_version"] == "1.0.0"
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
