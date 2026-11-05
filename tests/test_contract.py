# Treska JSON contract — pins the exact shape Sarissa consumes, per schema_version.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Stdlib only (no jsonschema). Key sets must match EXACTLY: an added, removed or
# retyped field fails here until CONTRACT is updated — and a schema_version bump
# without a matching CONTRACT entry fails test_contract_version_registered.

from __future__ import annotations

import json
import os
import subprocess
import sys
import types
import typing
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from treska.core.output import SCHEMA_VERSION
from treska.web.main import create_app

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parent.parent / "src"
SAMPLE_ZIP = FIXTURES / "sample.zip"

CONTRACT: dict[str, dict[str, dict[str, object]]] = {
    "1.2.0": {
        "result": {
            "schema_version": str,
            "zip_path": str,
            "file_count": int,
            "flagged": list,
            "inventory": list,
            "deferred_files": list,
            "extraction_type": str,
        },
        "file_entry": {
            "path": str,
            "size_bytes": int,
            "extension": str,
            "zip_timestamp": str | None,
            "magic_type": str,
            "mime": str,
            "mismatch": bool,
            "flags": list,
            "md5": str | None,
            "sha256": str | None,
            "sqlite_schema": dict | None,
            "triage": dict | None,
        },
        "deferred": {
            "filename": str,
            "format": str,
            "status": str,
            "message": str,
        },
    },
}


def _allowed(spec: object) -> tuple[type, ...]:
    # `T | None` -> (T, NoneType); a bare type -> (T,).
    if isinstance(spec, types.UnionType) or typing.get_origin(spec) is typing.Union:
        return tuple(type(None) if a is None else a for a in typing.get_args(spec))
    return (spec,)


def _check(obj: dict, shape: dict[str, object], where: str) -> None:
    assert isinstance(obj, dict), f"{where}: not an object"
    assert set(obj) == set(shape), (
        f"{where}: keys differ — extra {sorted(set(obj) - set(shape))}, "
        f"missing {sorted(set(shape) - set(obj))}"
    )
    for key, spec in shape.items():
        # Exact type match: bool must not pass as int, nor int as bool.
        assert type(obj[key]) in _allowed(spec), (
            f"{where}.{key}: {type(obj[key]).__name__} not in "
            f"{[t.__name__ for t in _allowed(spec)]}"
        )


def _check_contract(data: dict, *, expect_deferred: bool = False) -> None:
    contract = CONTRACT[data["schema_version"]]
    _check(data, contract["result"], "result")
    for i, entry in enumerate(data["inventory"]):
        _check(entry, contract["file_entry"], f"inventory[{i}]")
    for i, entry in enumerate(data["flagged"]):
        _check(entry, contract["file_entry"], f"flagged[{i}]")
    for i, entry in enumerate(data["deferred_files"]):
        _check(entry, contract["deferred"], f"deferred_files[{i}]")
    assert data["inventory"], "contract fixture must produce inventory entries"
    if expect_deferred:
        assert data["deferred_files"], "deferred fixture must produce a deferred entry"


@pytest.fixture
def deferred_zip(tmp_path: Path) -> Path:
    # A one-byte-header E01 stand-in: EVF magic is enough for detect-and-defer.
    path = tmp_path / "deferred.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("images/disk.E01", b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
        zf.writestr("notes.txt", b"hello")
    return path


def _cli_json(zip_path: Path) -> dict:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", "treska.cli", "--json", str(zip_path)],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _web_json(zip_path: Path) -> dict:
    client = TestClient(create_app())
    resp = client.post(
        "/api/parse", files={"file": (zip_path.name, zip_path.read_bytes(), "application/zip")}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_contract_version_registered():
    assert SCHEMA_VERSION in CONTRACT, (
        f"schema_version {SCHEMA_VERSION} has no CONTRACT entry — add one before shipping"
    )


def test_contract_cli(deferred_zip):
    data = _cli_json(SAMPLE_ZIP)
    assert data["schema_version"] == SCHEMA_VERSION
    _check_contract(data)
    _check_contract(_cli_json(deferred_zip), expect_deferred=True)


def test_contract_web(deferred_zip):
    data = _web_json(SAMPLE_ZIP)
    assert data["schema_version"] == SCHEMA_VERSION
    _check_contract(data)
    _check_contract(_web_json(deferred_zip), expect_deferred=True)
