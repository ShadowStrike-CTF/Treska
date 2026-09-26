# Treska web tests — exercise the FastAPI app in-process via TestClient.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import dataclasses
from pathlib import Path

from fastapi.testclient import TestClient

from treska.core.pipeline import parse_zip
from treska.web.main import create_app

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_ZIP = FIXTURES / "sample.zip"
README_TXT = FIXTURES / "readme.txt"

client = TestClient(create_app())


def _post(name: str, content: bytes):
    return client.post("/api/parse", files={"file": (name, content, "application/zip")})


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_index_serves_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")


def test_parse_valid_zip():
    resp = _post("sample.zip", SAMPLE_ZIP.read_bytes())
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


def test_parse_result_structure():
    data = _post("sample.zip", SAMPLE_ZIP.read_bytes()).json()
    assert set(data) == {"schema_version", "zip_path", "file_count", "flagged", "inventory"}
    assert data["schema_version"] == "1.0.0"
    assert data["file_count"] == len(data["inventory"])


def test_parse_not_a_zip():
    resp = _post("readme.txt", README_TXT.read_bytes())
    assert resp.status_code == 422
    assert "error" in resp.json()


def test_parse_missing_file():
    resp = _post("empty.zip", b"")
    assert resp.status_code in (422, 500)


def test_parse_json_matches_cli():
    web = _post("sample.zip", SAMPLE_ZIP.read_bytes()).json()
    direct = dataclasses.asdict(parse_zip(SAMPLE_ZIP))
    # zip_path differs by design: web reports the uploaded name, not a server path.
    assert web.pop("zip_path") == "sample.zip"
    direct.pop("zip_path")
    assert web == direct


def test_parse_zip_path_is_str():
    data = _post("sample.zip", SAMPLE_ZIP.read_bytes()).json()
    assert isinstance(data["zip_path"], str)
