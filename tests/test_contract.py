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
ANDROID_ZIP = FIXTURES / "android_sample.zip"
FLAG_ZIP = FIXTURES / "flag_scan_sample.zip"

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

# 1.4.0 (Phase 10): additive — everything in 1.3.0 unchanged, plus three Android
# formats with the same 9-key triage dict. "objects" pins nested summary objects
# (when not null); "count_maps" names summary maps of {label: int}.
_SQLITE_TRIAGE = _IOS_TRIAGE
CONTRACT["1.4.0"] = {
    **{key: dict(shape) for key, shape in CONTRACT["1.3.0"].items()},
    "triage": {
        **CONTRACT["1.3.0"]["triage"],
        "android_mmssms": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "total": int | None,
                "inbox": int | None,
                "sent": int | None,
                "other": int | None,
                "mms_count": int,
                "address_count": int | None,
                "first_message": str | None,
                "last_message": str | None,
                "first_mms": str | None,
                "last_mms": str | None,
            },
            "sample": {
                "time": str | None,
                "direction": str | None,
                "address": str | None,
                "body": str | None,
            },
            "items": {},
        },
        "android_contacts": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "raw_contact_count": int | None,
                "contact_count": int | None,
                "phone_count": int | None,
                "email_count": int | None,
                "embedded_calls": dict | None,
            },
            "sample": {
                "display_name": str | None,
                "first_phone_or_email": str | None,
            },
            "items": {},
            "objects": {
                "embedded_calls": {"count": int | None, "types": dict | None},
            },
            "count_maps": ("embedded_calls.types",),
        },
        "android_calllog": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "total": int | None,
                "by_type": dict | None,
                "total_duration_seconds": int | None,
                "first_call": str | None,
                "last_call": str | None,
            },
            "sample": {
                "time": str | None,
                "type": str | None,
                "number": str | None,
                "duration_seconds": int | None,
            },
            "items": {},
            "count_maps": ("by_type",),
        },
    },
}

# 1.5.0 (Phase 11): additive — everything in 1.4.0 unchanged, plus ParseResult.flag_hits
# (list, or null when --no-flag-scan) with one pinned item shape, and three formats.
CONTRACT["1.5.0"] = {
    **{key: dict(shape) for key, shape in CONTRACT["1.4.0"].items()},
    "result": {**CONTRACT["1.4.0"]["result"], "flag_hits": list | None},
    "flag_hit": {"path": str, "offset": int, "encoding": str, "match": str},
    "triage": {
        **CONTRACT["1.4.0"]["triage"],
        "ios_callhistory": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "total": int | None,
                "incoming": int | None,
                "outgoing": int | None,
                "answered": int | None,
                "missed": int | None,
                "by_service": dict | None,
                "total_duration_seconds": int | None,
                "first_call": str | None,
                "last_call": str | None,
            },
            "sample": {
                "time": str | None,
                "direction": str | None,
                "address": str | None,
                "duration_seconds": int | None,
                "service": str | None,
            },
            "items": {},
            "count_maps": ("by_service",),
        },
        "ios_safari": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "url_count": int | None,
                "visit_count": int | None,
                "domain_count": int | None,
                "top_domains": list | None,
                "first_visit": str | None,
                "last_visit": str | None,
            },
            "sample": {
                "time": str | None,
                "title": str | None,
                "url": str | None,
            },
            "items": {"top_domains": {"domain": str, "count": int}},
        },
        "android_chrome": {
            "triage": _SQLITE_TRIAGE,
            "summary": {
                "url_count": int | None,
                "visit_count": int | None,
                "typed_count": int | None,
                "search_term_count": int | None,
                "top_domains": list | None,
                "first_visit": str | None,
                "last_visit": str | None,
            },
            "sample": {
                "kind": str,
                "time": str | None,
                "title": str | None,
                "url": str | None,
                "term": str | None,
            },
            "items": {"top_domains": {"domain": str, "count": int}},
        },
    },
}

# 1.6.0 (Phase 12): additive — everything in 1.5.0 unchanged, plus two WhatsApp formats.
# Both share one 10-key summary and one 8-key sample record (whatsapp_record).
_WHATSAPP = {
    "triage": _SQLITE_TRIAGE,
    "summary": {
        "message_count": int | None,
        "sent_count": int | None,
        "received_count": int | None,
        "media_only_count": int | None,
        "chat_count": int | None,
        "group_chat_count": int | None,
        "first_message": str | None,
        "last_message": str | None,
        "contact_names_resolved": bool,
        "schema_layout": str,
    },
    "sample": {
        "kind": str,
        "timestamp": str | None,
        "direction": str | None,
        "contact": str | None,
        "contact_name": str | None,
        "is_group": bool,
        "body": str,
        "platform": str,
    },
    "items": {},
}
CONTRACT["1.6.0"] = {
    **{key: dict(shape) for key, shape in CONTRACT["1.5.0"].items()},
    "triage": {
        **CONTRACT["1.5.0"]["triage"],
        "android_whatsapp": _WHATSAPP,
        "ios_whatsapp": _WHATSAPP,
    },
}


def _allowed(spec: object) -> tuple[type, ...]:
    # `T | None` -> (T, NoneType); a bare type -> (T,).
    if isinstance(spec, types.UnionType) or typing.get_origin(spec) is typing.Union:
        return tuple(type(None) if a is None else a for a in typing.get_args(spec))
    return (spec,)


def _check(obj: dict, shape: dict[str, object], where: str, *, additive: bool = False) -> None:
    # additive: obj may carry keys added by a later schema (a pinned older contract
    # checked against current output); every pinned key must still match exactly.
    assert isinstance(obj, dict), f"{where}: not an object"
    missing = set(shape) - set(obj)
    extra = set(obj) - set(shape)
    assert not missing and (additive or not extra), (
        f"{where}: keys differ — extra {sorted(extra)}, missing {sorted(missing)}"
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
        for key, obj_shape in shape.get("objects", {}).items():
            if summary[key] is not None:
                _check(summary[key], obj_shape, f"{where}.summary.{key}")
        for dotted in shape.get("count_maps", ()):
            value: object = summary
            for part in dotted.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            for label, count in (value or {}).items():
                assert type(label) is str and type(count) is int, (
                    f"{where}.summary.{dotted}[{label!r}]: {type(count).__name__} not int")
    for j, sample in enumerate(triage["samples"]):
        _check(sample, shape["sample"], f"{where}.samples[{j}]")


def _check_contract(
    data: dict,
    *,
    version: str | None = None,
    expect_deferred: bool = False,
    expect_formats: frozenset[str] = frozenset(),
) -> None:
    # version pins an older CONTRACT entry: additive bumps keep older shapes valid,
    # so the top level may carry later keys (e.g. 1.5.0 flag_hits); all else is exact.
    contract = CONTRACT[version or data["schema_version"]]
    pinned_older = version is not None and version != data["schema_version"]
    _check(data, contract["result"], "result", additive=pinned_older)
    if "flag_hit" in contract:
        for i, hit in enumerate(data["flag_hits"] or []):
            _check(hit, contract["flag_hit"], f"flag_hits[{i}]")
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


def _cli_json(zip_path: Path, *extra: str) -> dict:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", "treska.cli", "--json", *extra, str(zip_path)],
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
    including every iOS triage, summary and sample shape. Since 1.4.0 is additive,
    the iOS output must still match the unchanged 1.3.0 shapes as well as the
    current contract."""
    assert "1.3.0" in CONTRACT and "1.2.0" in CONTRACT
    for data in (_cli_json(IOS_ZIP), _web_json(IOS_ZIP)):
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["extraction_type"] == "IOS_FFS"
        _check_contract(data, version="1.3.0", expect_formats=IOS_FORMATS)
        _check_contract(data, expect_formats=IOS_FORMATS)
        statuses = {
            e["triage"]["format"]: e["triage"]["status"]
            for e in data["inventory"]
            if e["triage"] is not None and e["triage"]["format"] in IOS_FORMATS
        }
        # Only the 1.3.0 formats: the fixture gained Phase 11 artifacts since.
        assert statuses == dict.fromkeys(IOS_FORMATS, "parsed")


ANDROID_FORMATS = frozenset({"android_mmssms", "android_contacts", "android_calllog"})


def test_contract_1_4_0():
    """Phase 10: CLI and web output for an Android logical zip match CONTRACT["1.4.0"],
    including every Android triage, summary, sample, nested object and count map."""
    assert {"1.2.0", "1.3.0", "1.4.0"} <= set(CONTRACT)
    # Additive: every 1.3.0 shape is carried into 1.4.0 unchanged.
    for key, shape in CONTRACT["1.3.0"].items():
        if key != "triage":
            assert CONTRACT["1.4.0"][key] == shape
    for fmt, shape in CONTRACT["1.3.0"]["triage"].items():
        assert CONTRACT["1.4.0"]["triage"][fmt] is shape
    for data in (_cli_json(ANDROID_ZIP), _web_json(ANDROID_ZIP)):
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["extraction_type"] == "ANDROID_LOGICAL"
        # 1.5.0 is additive: Android output still matches the unchanged 1.4.0 shapes.
        _check_contract(data, version="1.4.0", expect_formats=ANDROID_FORMATS)
        _check_contract(data, expect_formats=ANDROID_FORMATS)
        triages = {e["triage"]["format"]: e["triage"]
                   for e in data["inventory"]
                   if e["triage"] is not None and e["triage"]["format"] in ANDROID_FORMATS}
        assert {f: t["status"] for f, t in triages.items()} == dict.fromkeys(ANDROID_FORMATS, "parsed")
        # The fixture's contacts2.db carries the embedded calls table: the nested
        # object and its count map are exercised, not just allowed to be null.
        assert triages["android_contacts"]["summary"]["embedded_calls"] is not None


PHASE11_IOS = frozenset({"ios_callhistory", "ios_safari"})
PHASE11_ANDROID = frozenset({"android_chrome"})


def test_contract_1_5_0():
    """Phase 11: CLI and web output match CONTRACT["1.5.0"] — the three new formats
    (every triage, summary, sample, ranked list and count map), flag_hits items, and
    flag_hits null under --no-flag-scan. Every 1.4.0 shape is carried over unchanged."""
    assert {"1.2.0", "1.3.0", "1.4.0", "1.5.0"} <= set(CONTRACT)
    for key, shape in CONTRACT["1.4.0"].items():
        if key not in ("triage", "result"):
            assert CONTRACT["1.5.0"][key] == shape
    assert CONTRACT["1.5.0"]["result"] == {**CONTRACT["1.4.0"]["result"], "flag_hits": list | None}
    for fmt, shape in CONTRACT["1.4.0"]["triage"].items():
        assert CONTRACT["1.5.0"]["triage"][fmt] is shape

    cases = ((IOS_ZIP, "IOS_FFS", IOS_FORMATS | PHASE11_IOS),
             (ANDROID_ZIP, "ANDROID_LOGICAL", ANDROID_FORMATS | PHASE11_ANDROID))
    for zip_path, extraction, formats in cases:
        for data in (_cli_json(zip_path), _web_json(zip_path)):
            assert data["schema_version"] == SCHEMA_VERSION
            assert data["extraction_type"] == extraction
            # 1.6.0 is additive: output still matches the unchanged 1.5.0 shapes.
            _check_contract(data, version="1.5.0", expect_formats=formats)
            _check_contract(data, expect_formats=formats)
            # Only the 1.5.0 formats: the fixtures gained Phase 12 artifacts since.
            statuses = {e["triage"]["format"]: e["triage"]["status"]
                        for e in data["inventory"]
                        if e["triage"] is not None and e["triage"]["format"] in formats}
            assert statuses == dict.fromkeys(formats, "parsed")
            assert isinstance(data["flag_hits"], list)

    # Flag text is hidden by default (web always); --reveal-flags shows it.
    android = _web_json(ANDROID_ZIP)
    assert android["flag_hits"] and {h["match"] for h in android["flag_hits"]} == {"flag{...}"}
    assert "flag{ph11}" in [h["match"] for h in _cli_json(ANDROID_ZIP, "--reveal-flags")["flag_hits"]]
    flags = _cli_json(FLAG_ZIP)
    _check_contract(flags)
    assert [(h["encoding"], h["match"]) for h in flags["flag_hits"]] == [("base64", "flag{...}")]
    revealed = _cli_json(FLAG_ZIP, "--reveal-flags")
    _check_contract(revealed)
    assert [(h["encoding"], h["match"]) for h in revealed["flag_hits"]] == [
        ("base64", "flag{b64_wrapped_ph11}")]

    skipped = _cli_json(ANDROID_ZIP, "--no-flag-scan")
    assert "flag_hits" in skipped and skipped["flag_hits"] is None
    _check_contract(skipped, expect_formats=ANDROID_FORMATS | PHASE11_ANDROID)


WHATSAPP_FORMATS = {"IOS_FFS": "ios_whatsapp", "ANDROID_LOGICAL": "android_whatsapp"}


def test_contract_1_6_0():
    """Phase 12: CLI and web output match CONTRACT["1.6.0"] — both WhatsApp formats
    (triage, 10-key summary, 8-key sample), every 1.5.0 shape carried over unchanged,
    flag{ph12} found on both platforms, and flag_hits null under --no-flag-scan."""
    assert {"1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0"} <= set(CONTRACT)
    for key, shape in CONTRACT["1.5.0"].items():
        if key != "triage":
            assert CONTRACT["1.6.0"][key] == shape
    for fmt, shape in CONTRACT["1.5.0"]["triage"].items():
        assert CONTRACT["1.6.0"]["triage"][fmt] is shape

    cases = ((IOS_ZIP, "IOS_FFS", IOS_FORMATS | PHASE11_IOS),
             (ANDROID_ZIP, "ANDROID_LOGICAL", ANDROID_FORMATS | PHASE11_ANDROID))
    for zip_path, extraction, older in cases:
        wa = WHATSAPP_FORMATS[extraction]
        formats = older | {wa}
        for data in (_cli_json(zip_path), _web_json(zip_path)):
            assert data["schema_version"] == "1.6.0"
            assert data["extraction_type"] == extraction
            _check_contract(data, expect_formats=formats)
            statuses = {e["triage"]["format"]: e["triage"]["status"]
                        for e in data["inventory"] if e["triage"] is not None}
            assert statuses == dict.fromkeys(formats, "parsed")
            triage = next(e["triage"] for e in data["inventory"]
                          if e["triage"] is not None and e["triage"]["format"] == wa)
            assert triage["wal_applied"] is True and triage["samples"]
            assert data["flag_hits"] and {h["match"] for h in data["flag_hits"]} == {"flag{...}"}
        revealed = _cli_json(zip_path, "--reveal-flags")
        _check_contract(revealed, expect_formats=formats)
        assert "flag{ph12}" in [h["match"] for h in revealed["flag_hits"]]

    skipped = _cli_json(ANDROID_ZIP, "--no-flag-scan")
    assert skipped["flag_hits"] is None
    _check_contract(skipped, expect_formats=ANDROID_FORMATS | PHASE11_ANDROID | {"android_whatsapp"})
