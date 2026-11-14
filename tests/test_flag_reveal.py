# Treska flag text masking — hidden by default, shown only with --reveal-flags.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from treska.core import flag_scan
from treska.core.pipeline import FLAG_MASK, mask_flag_hits, parse_zip
from treska.web.main import create_app

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parent.parent / "src"
FLAG_ZIP = FIXTURES / "flag_scan_sample.zip"
SAMPLE_ZIP = FIXTURES / "sample.zip"
ANDROID_ZIP = FIXTURES / "android_sample.zip"
IOS_ZIP = FIXTURES / "ios_sample.zip"
HINT = "Flag text hidden. Re-run with --reveal-flags to show it."

# Fixtures whose flags reach the output only through the flag scan, with the flag bodies.
SCANNER_ONLY = {FLAG_ZIP: "b64_wrapped_ph11", SAMPLE_ZIP: "not_here"}


def _cli(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run([sys.executable, "-m", "treska.cli", *args],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    return proc


def _web(zip_path: Path, **kwargs) -> str:
    client = TestClient(create_app())
    resp = client.post("/api/parse",
                       files={"file": (zip_path.name, zip_path.read_bytes(), "application/zip")},
                       **kwargs)
    assert resp.status_code == 200, resp.text
    return resp.text


def _prefix_zip(tmp_path: Path) -> Path:
    zip_path = tmp_path / "prefixes.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", b"x flag{alpha_one} x")
        zf.writestr("b.txt", b"x ctf{bravo_two} x")
        zf.writestr("c.txt", b"x FLAG{charlie_three} x")
        zf.writestr("d.txt", "x CTF{delta_four} x".encode("utf-16-le"))
    return zip_path


# (a) each prefix keeps the prefix as found plus a constant placeholder
def test_default_match_is_prefix_placeholder(tmp_path):
    hits = parse_zip(_prefix_zip(tmp_path)).flag_hits
    assert [(h["path"], h["match"]) for h in hits] == [
        ("a.txt", "flag{...}"), ("b.txt", "ctf{...}"),
        ("c.txt", "FLAG{...}"), ("d.txt", "CTF{...}")]
    assert {p + "...}" for p in flag_scan.FLAG_PREFIXES} == {h["match"] for h in hits}


def test_mask_fails_closed_on_unknown_prefix():
    hits = [{"path": "x", "offset": 3, "encoding": "ascii", "match": "weird{secret}"}]
    masked = mask_flag_hits(hits)
    assert masked == [{"path": "x", "offset": 3, "encoding": "ascii", "match": FLAG_MASK}]
    assert "secret" not in json.dumps(masked)
    assert hits[0]["match"] == "weird{secret}"  # input not mutated
    assert mask_flag_hits(None) is None
    assert mask_flag_hits([]) == []


def test_placeholder_does_not_leak_length(tmp_path):
    zip_path = tmp_path / "len.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("short.txt", b"flag{a}")
        zf.writestr("long.txt", b"flag{" + b"z" * 200 + b"}")
    assert {h["match"] for h in parse_zip(zip_path).flag_hits} == {"flag{...}"}


# (b) the flag body never reaches JSON, pretty output or the web body
@pytest.mark.parametrize("zip_path", list(SCANNER_ONLY), ids=lambda p: p.name)
def test_flag_body_absent_from_every_output(tmp_path, zip_path):
    body = SCANNER_ONLY[zip_path]
    json_out = _cli("--json", str(zip_path)).stdout
    assert json.loads(json_out)["flag_hits"]
    pretty = _cli(str(zip_path)).stdout
    out_file = tmp_path / "pretty.txt"
    _cli("--out", str(out_file), str(zip_path))
    json_file = tmp_path / "out.json"
    _cli("--json", "--out", str(json_file), str(zip_path))
    for text in (json_out, pretty, out_file.read_text(encoding="utf-8"),
                 json_file.read_text(encoding="utf-8"), _web(zip_path)):
        assert body not in text


@pytest.mark.parametrize("zip_path", [ANDROID_ZIP, IOS_ZIP], ids=lambda p: p.name)
def test_device_fixture_hits_masked(zip_path):
    # Triage samples show evidence as found; only the flag hit text is masked.
    for data in (json.loads(_cli("--json", str(zip_path)).stdout), json.loads(_web(zip_path))):
        assert data["flag_hits"]
        assert all(h["match"] == "flag{...}" for h in data["flag_hits"])


# (c) --reveal-flags returns the real text
def test_reveal_flags_returns_text(tmp_path):
    data = json.loads(_cli("--json", "--reveal-flags", str(FLAG_ZIP)).stdout)
    assert [h["match"] for h in data["flag_hits"]] == ["flag{b64_wrapped_ph11}"]
    hits = parse_zip(_prefix_zip(tmp_path), reveal_flags=True).flag_hits
    assert [h["match"] for h in hits] == [
        "flag{alpha_one}", "ctf{bravo_two}", "FLAG{charlie_three}", "CTF{delta_four}"]


# (d) --no-flag-scan stays null with or without --reveal-flags
def test_no_flag_scan_null_with_and_without_reveal():
    for extra in ((), ("--reveal-flags",)):
        data = json.loads(_cli("--json", "--no-flag-scan", *extra, str(FLAG_ZIP)).stdout)
        assert "flag_hits" in data and data["flag_hits"] is None
    assert parse_zip(FLAG_ZIP, no_flag_scan=True, reveal_flags=True).flag_hits is None


# (e) masking changes only the text
@pytest.mark.parametrize("zip_path", [FLAG_ZIP, SAMPLE_ZIP, ANDROID_ZIP, IOS_ZIP],
                         ids=lambda p: p.name)
def test_masked_and_revealed_hits_line_up(zip_path):
    masked = parse_zip(zip_path).flag_hits
    revealed = parse_zip(zip_path, reveal_flags=True).flag_hits
    assert len(masked) == len(revealed) > 0
    strip = lambda hits: [(h["path"], h["offset"], h["encoding"]) for h in hits]  # noqa: E731
    assert strip(masked) == strip(revealed)
    assert [set(h) for h in masked] == [set(h) for h in revealed]


# (f) the web view is always masked and cannot be asked to reveal
def test_web_always_masked():
    for kwargs in ({}, {"params": {"reveal_flags": "true"}},
                   {"data": {"reveal_flags": "true", "reveal-flags": "1"}}):
        data = json.loads(_web(FLAG_ZIP, **kwargs))
        assert [h["match"] for h in data["flag_hits"]] == ["flag{...}"]


# (g) the hint appears only in pretty output, only with hits and reveal off
def test_hint_only_when_hidden_hits_in_pretty(tmp_path):
    assert HINT in _cli(str(FLAG_ZIP)).stdout
    out_file = tmp_path / "pretty.txt"
    _cli("--out", str(out_file), str(FLAG_ZIP))
    assert HINT in out_file.read_text(encoding="utf-8")

    assert HINT not in _cli("--reveal-flags", str(FLAG_ZIP)).stdout
    assert HINT not in _cli("--no-flag-scan", str(FLAG_ZIP)).stdout
    no_hits = tmp_path / "clean.zip"
    with zipfile.ZipFile(no_hits, "w") as zf:
        zf.writestr("readme.txt", b"nothing to see")
    assert HINT not in _cli(str(no_hits)).stdout


def test_hint_never_in_json(tmp_path):
    stdout = _cli("--json", str(FLAG_ZIP)).stdout
    assert HINT not in stdout and "--reveal-flags" not in stdout
    json.loads(stdout)
    json_file = tmp_path / "out.json"
    assert _cli("--json", "--out", str(json_file), str(FLAG_ZIP)).stdout.startswith("Written to:")
    text = json_file.read_text(encoding="utf-8")
    assert HINT not in text and "--reveal-flags" not in text
    json.loads(text)
