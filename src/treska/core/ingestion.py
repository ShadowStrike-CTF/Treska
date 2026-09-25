# Treska core — zip extraction and temp dir management.
# © 2026 Strategos Pty Ltd. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import atexit
import shutil
import tempfile
import zipfile
from pathlib import Path

_PENDING_CLEANUP: set[Path] = set()


def cleanup(temp_dir: Path) -> None:
    """Remove an extraction temp dir now. Safe to call more than once."""
    _PENDING_CLEANUP.discard(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@atexit.register
def _cleanup_all() -> None:
    for temp_dir in list(_PENDING_CLEANUP):
        cleanup(temp_dir)


def extract(zip_path: Path, keep: bool = False) -> tuple[Path, list[Path]]:
    """Extract zip_path into a fresh temp dir.

    Returns (temp_dir, sorted list of extracted file paths). With keep=False the
    temp dir is removed at interpreter exit (or earlier via cleanup()).
    Raises ValueError if zip_path is missing, not a zip, or unreadable.
    """
    zip_path = Path(zip_path)
    if not zip_path.is_file():
        raise ValueError(f"zip file not found: {zip_path}")
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"not a valid zip file: {zip_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="treska_")).resolve()
    if not keep:
        _PENDING_CLEANUP.add(temp_dir)

    try:
        extracted: set[Path] = set()
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                # zipfile.extract strips absolute paths and ".." components;
                # the containment check below is belt-and-braces against zip-slip.
                out = Path(zf.extract(member, path=temp_dir)).resolve()
                if not out.is_relative_to(temp_dir):
                    raise ValueError(f"unsafe member path in zip: {member.filename!r}")
                extracted.add(out)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        cleanup(temp_dir)
        raise ValueError(f"cannot extract {zip_path}: {exc}") from exc
    except BaseException:
        cleanup(temp_dir)
        raise

    return temp_dir, sorted(extracted)
