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
IOS_ZIP = FIXTURES / "ios_sample.zip"

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

# 1.3.0 (Phase 9): top-level, file_entry and deferred shapes are unchanged from
# 1.2.0; FileEntry.triage gains three iOS formats, each pinned here. Every iOS
# triage dict carries the same top-level keys (sqlite_triage.result_skeleton).
_IOS_TRIAGE: dict[str, object] = {
    "filename": str,
    "format": str,
    "status": str,
    "error": str | None,
    "warnings": list,
    "wal_present": bool,
    "wal_applied": bool,
    "summary": dict | None,
    "samples": list,
}
CONTRACT["1.3.0"] = {
    **{key: dict(shape) for key, shape in CONTRACT["1.2.0"].items()},
    "triage": {
        "ios_sms": {
            "triage": _IOS_TRIAGE,
            "summary": {
                "message_count": int | None,
                "sent_count": int | None,
                "received_count": int | None,
                "chat_count": int | None,
                "handle_count": int | None,
                "attachment_count": int | None,
                "first_message": str | None,
                "last_message": str | None,
            },
            "sample": {
                "time": str | None,
                "direction": str | None,
                "handle": str | None,
                "text": str | None,
            },
            "items": {},
        },
        "ios_knowledgec": {
            "triage": _IOS_TRIAGE,
            "summary": {
                "total_rows": int | None,
                "stream_counts": list | None,
                "top_bundles": list | None,
                "first_event": str | None,
                "last_event": str | None,
            },
            "sample": {
                "bundle_id": str | None,
                "start": str | None,
                "end": str | None,
            },
            "items": {
                "stream_counts": {"stream": str | None, "count": int},
                "top_bundles": {"bundle_id": str | None, "count": int},
            },
        },
        "ios_addressbook": {
            "triage": _IOS_TRIAGE,
            "summary": {
                "person_count": int | None,
                "phone_count": int | None,
                "email_count": int | None,
            },
            "sample": {
                "first_name": str | None,
                "last_name": str | None,
                "organization": str | None,
                "first_phone_or_email": str | None,
            },
            "items": {},
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


def _check_triage(triage: dict, shape: dict, where: str) -> None:
    _check(triage, shape["triage"], where)
    summary = triage["summary"]
    if summary is not None:
        _check(summary, shape["summary"], f"{where}.summary")
        for key, item_shape in shape["items"].items():
            for j, item in enumerate(summary[key] or []):
                _check(item, item_shape, f"{where}.summary.{key}[{j}]")
    for j, sample in enumerate(triage["samples"]):
        _check(sample, shape["sample"], f"{where}.samples[{j}]")


def _check_contract(
    data: dict, *, expect_deferred: bool = False, expect_formats: frozenset[str] = frozenset()
) -> None:
    contract = CONTRACT[data["schema_version"]]
    _check(data, contract["result"], "result")
    triage_shapes = contract.get("triage", {})
    seen: set[str] = set()
    for i, entry in enumerate(data["inventory"]):
        _check(entry, contract["file_entry"], f"inventory[{i}]")
        triage = entry["triage"]
        if triage is not None and triage.get("format") in triage_shapes:
            seen.add(triage["format"])
            _check_triage(triage, triage_shapes[triage["format"]], f"inventory[{i}].triage")
    for i, entry in enumerate(data["flagged"]):
        _check(entry, contract["file_entry"], f"flagged[{i}]")
    for i, entry in enumerate(data["deferred_files"]):
        _check(entry, contract["deferred"], f"deferred_files[{i}]")
    assert data["inventory"], "contract fixture must produce inventory entries"
    if expect_deferred:
        assert data["deferred_files"], "deferred fixture must produce a deferred entry"
    assert expect_formats <= seen, f"fixture must exercise {sorted(expect_formats - seen)}"


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


IOS_FORMATS = frozenset({"ios_sms", "ios_knowledgec", "ios_addressbook"})


def test_contract_1_3_0():
    """Phase 9: CLI and web output for an iOS FFS zip match CONTRACT["1.3.0"],
    including every iOS triage, summary and sample shape."""
    assert "1.3.0" in CONTRACT and "1.2.0" in CONTRACT
    for data in (_cli_json(IOS_ZIP), _web_json(IOS_ZIP)):
        assert data["schema_version"] == "1.3.0"
        assert data["extraction_type"] == "IOS_FFS"
        _check_contract(data, expect_formats=IOS_FORMATS)
        statuses = {
            e["triage"]["format"]: e["triage"]["status"]
            for e in data["inventory"] if e["triage"] is not None
        }
        assert statuses == dict.fromkeys(IOS_FORMATS, "parsed")
