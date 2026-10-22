# Treska parsers — EVTX triage: flag candidates and high-value EventIDs from Windows Event Logs.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any

try:
    # python-evtx: pure Python (PyInstaller-clean), imported as "Evtx".
    from Evtx.Evtx import FileHeader
except ImportError:
    FileHeader = None  # fail-closed: parse_evtx reports status "corrupt"

EVTX_MAGIC = b"ElfFile\x00"

# High-value EventIDs — module-level constant, never hardcoded inline.
# Extensible: add entries here without structural change.
HIGH_VALUE_IDS: dict[int, str] = {
    4624: "Logon success",
    4625: "Logon failure",
    4720: "User account created",
    4722: "User account enabled",
    4725: "User account disabled",
    4732: "User added to privileged group",
    4769: "Kerberos service ticket requested",
    4776: "NTLM authentication attempt",
    4104: "Script block logged (execution payload)",
    4103: "Module logging",
    1: "Process creation (Sysmon)",
    3: "Network connection (Sysmon)",
    7: "Image loaded (Sysmon)",
    11: "File created (Sysmon)",
    1033: "Installer activity",
    4657: "Registry value modified",
}

SAMPLE_CAP = 3  # max samples per high-value EventID — triage, not dump
TOP_N = 10
_CHUNK_SIZE = 0x10000


def _local(tag: str) -> str:
    """Strip the "{namespace}" prefix ElementTree puts on every tag."""
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    return next((c for c in parent if _local(c.tag) == name), None)


def _event_data(event: ET.Element) -> dict[str, str]:
    """EventData/Data (Name -> text), else UserData leaves (tag -> text). Flat strings only."""
    data: dict[str, str] = {}
    event_data = _child(event, "EventData")
    if event_data is not None:
        for i, item in enumerate(event_data):
            key = item.get("Name") or f"{_local(item.tag)}_{i}"
            data[key] = (item.text or "").strip()
        return data
    user_data = _child(event, "UserData")
    if user_data is not None:
        for node in user_data.iter():
            if len(node) == 0 and node is not user_data:
                data[_local(node.tag)] = (node.text or "").strip()
    return data


def _parse_record(record: Any) -> dict[str, Any]:
    """One rendered record -> {event_id, time_created, computer, event_data}. Raises on bad XML."""
    event = ET.fromstring(record.xml())
    system = _child(event, "System")
    event_id = int((_child(system, "EventID").text or "").strip())
    created = _child(system, "TimeCreated")
    time_created = created.get("SystemTime") if created is not None else None
    if not time_created:
        time_created = record.timestamp().isoformat()
    computer = _child(system, "Computer")
    return {
        "event_id": event_id,
        "time_created": time_created,
        "computer": (computer.text or "").strip() if computer is not None else "",
        "event_data": _event_data(event),
    }


def _result(filename: str, status: str, **extra: Any) -> dict[str, Any]:
    return {
        "filename": filename,
        "format": "evtx",
        "status": status,
        "event_count": 0,
        "record_errors": 0,
        "top_event_ids": [],
        "high_value_events": [],
        **extra,
    }


def parse_evtx(file_bytes: bytes, filename: str = "") -> dict[str, Any]:
    """Parse EVTX bytes; return the per-file triage dict.

    python-evtx parses a buffer in place and yields chunks and records lazily,
    so only counters and at most SAMPLE_CAP samples per high-value ID are held.
    status: "parsed", "empty" (no records), or "corrupt" (bad header, parser
    unavailable, or no record could be read). A record that fails to render,
    or a declared chunk that is missing, is counted in record_errors rather
    than sinking the whole file.
    """
    if FileHeader is None:
        return _result(filename, "corrupt", error="python-evtx is not installed")
    if file_bytes[: len(EVTX_MAGIC)] != EVTX_MAGIC:
        return _result(filename, "corrupt", error="missing ElfFile header")

    counts: Counter[int] = Counter()
    samples: dict[int, list[dict[str, Any]]] = {}
    errors = 0
    try:
        header = FileHeader(file_bytes, 0)
        # chunks() quietly stops at a chunk cut short, so count those as errors.
        declared = header.chunk_count()
        present = max(0, (len(file_bytes) - header.header_chunk_size()) // _CHUNK_SIZE)
        errors += max(0, declared - present)
        for chunk in header.chunks():
            if not chunk.check_magic():
                errors += 1
                continue
            for record in chunk.records():
                try:
                    event = _parse_record(record)
                except Exception:  # noqa: BLE001 — any malformed record
                    errors += 1
                    continue
                event_id = event.pop("event_id")
                counts[event_id] += 1
                if event_id in HIGH_VALUE_IDS:
                    bucket = samples.setdefault(event_id, [])
                    if len(bucket) < SAMPLE_CAP:
                        bucket.append(event)
    except Exception as exc:  # noqa: BLE001 — header/chunk structure unreadable
        return _result(filename, "corrupt", record_errors=errors, error=f"{type(exc).__name__}: {exc}")

    event_count = sum(counts.values())
    if event_count == 0:
        if errors:
            return _result(filename, "corrupt", record_errors=errors, error="no readable records")
        return _result(filename, "empty")

    # most_common sorts by count descending; ties keep first-seen order.
    top = [{"event_id": eid, "count": n} for eid, n in counts.most_common(TOP_N)]
    high_value = [
        {"event_id": eid, "label": HIGH_VALUE_IDS[eid], "count": counts[eid], "samples": samples[eid]}
        for eid in sorted(samples, key=lambda e: (-counts[e], e))
    ]
    return _result(
        filename, "parsed",
        event_count=event_count, record_errors=errors,
        top_event_ids=top, high_value_events=high_value,
    )
