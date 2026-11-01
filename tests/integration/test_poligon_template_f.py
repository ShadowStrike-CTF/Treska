# Treska ← Poligon integration — Template F iOS FFS extractions are detected as IOS_FFS.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import json
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

poligon = pytest.importorskip("poligon")

from poligon.core import generate as poligon_generate  # noqa: E402
from poligon.core import history as poligon_history  # noqa: E402
from poligon.core.templates import template_f  # noqa: E402

from treska.core.detect import IOS_FFS  # noqa: E402
from treska.core.pipeline import parse_zip  # noqa: E402

pytestmark = pytest.mark.integration

DIFFICULTIES = (1, 2, 3)
SEEDS = (1, 42, 1337)


def _member(rel: str) -> str:
    """Zip member path Template F writes for a device path."""
    return f"{template_f.ROOT}/{rel}"


# The databases detection keys on, at their real iOS FFS paths.
EXPECTED_DBS = (template_f.SMS_DB, template_f.KNOWLEDGEC_DB, template_f.ADDRESSBOOK_DB)
# Everything else Template F ships: non-flag DBs, the plist, the logs/readme.
DECOYS = (
    _member(template_f.SAFARI_DB),
    _member(template_f.CALENDAR_DB),
    _member(template_f.ACQUISITION_LOG),
    template_f.CHALLENGE_TXT,
)


@pytest.fixture
def make_scenario(tmp_path, monkeypatch):
    """Generate Template F with Poligon's HOME and history isolated in tmp_path,
    as Poligon's own tests do — the real ~/.poligon is never touched."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(poligon_history, "HISTORY_PATH", tmp_path / ".poligon" / "history.json")
    out_dir = tmp_path / ".poligon" / "scenarios"
    monkeypatch.setattr(poligon_generate, "DEFAULT_OUTPUT_DIR", out_dir)

    def _make(difficulty: int, seed: int) -> dict:
        return poligon_generate.generate("ios", difficulty, seed, output_dir=out_dir)

    return _make


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_treska_detects_template_f(make_scenario, difficulty, seed):
    scenario = make_scenario(difficulty, seed)
    zip_path = Path(scenario["zip_path"])
    scenario_dir = Path(scenario["scenario_dir"])

    # Treska is handed the zip only — never the scenario dir.
    result = parse_zip(zip_path)
    by_path = {entry.path: entry for entry in result.inventory}

    assert result.extraction_type == IOS_FFS

    for rel in EXPECTED_DBS:
        entry = by_path.get(_member(rel))
        assert entry is not None, f"{rel} missing from inventory"
        assert "sqlite" in entry.flags
        assert entry.sqlite_schema is not None and entry.sqlite_schema["tables"]

    # Decoys sit alongside the markers without changing the verdict.
    for path in DECOYS:
        assert path in by_path, f"{path} missing from inventory"

    # Binary plist goes through magic/hash/triage without a crash.
    plist = by_path.get(_member(template_f.CLIENTS_PLIST))
    assert plist is not None
    assert plist.triage is None

    # solution.json sits beside the zip, so Treska never sees it.
    solution = scenario_dir / "solution.json"
    assert solution.is_file()
    with zipfile.ZipFile(zip_path) as zf:
        assert not any(name.endswith("solution.json") for name in zf.namelist())
    assert not any(path.endswith("solution.json") for path in by_path)
    flag = json.loads(solution.read_text(encoding="utf-8"))["flag"]
    assert flag not in json.dumps(asdict(result))


def test_treska_rejects_scenario_dir(make_scenario):
    """Treska's input contract is a zip file; the scenario dir (which holds
    solution.json) can't be fed to it."""
    scenario = make_scenario(1, 42)
    with pytest.raises(ValueError):
        parse_zip(Path(scenario["scenario_dir"]))
