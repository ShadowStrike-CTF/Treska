# Treska flag-scan test fixture — regenerate with: python tests/fixtures/make_flag_fixture.py
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Synthetic (no real case data): a .txt carrying a base64-wrapped flag next to
# exact-case decoys that must NOT match, plus a plain file with no flag.

from __future__ import annotations

import base64
import importlib.util
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("make_ios_fixture", HERE / "make_ios_fixture.py")
_ios = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ios)

B64_FLAG = "flag{b64_wrapped_ph11}"
NOTES_PATH = "notes/clue.txt"


def build_flag_tree(root: Path) -> list[Path]:
    root = Path(root)
    notes = root / NOTES_PATH
    notes.parent.mkdir(parents=True, exist_ok=True)
    wrapped = base64.b64encode(b"note to self: " + B64_FLAG.encode() + b" -- burn after reading")
    notes.write_bytes(
        b"Decoys: Flag{wrong_case} flag{unclosed\n"
        b"Encoded: " + wrapped + b"\n"
    )
    other = root / "readme.txt"
    other.write_bytes(b"Treska synthetic flag-scan fixture.\n")
    return sorted([notes, other])


def make_flag_zip(zip_path: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="treska_flag_fixture_") as tmp:
        root = Path(tmp)
        return _ios.zip_tree(root, build_flag_tree(root), Path(zip_path))


if __name__ == "__main__":
    print(make_flag_zip(HERE / "flag_scan_sample.zip"))
