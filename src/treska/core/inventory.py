# Treska core — file inventory.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from treska.core.magic_check import file_extension


def _normalise_member(name: str) -> str:
    # Mirror zipfile.extract's sanitising so names match what landed on disk.
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", "/", ".", "..")]
    return "/".join(parts)


def _iso(date_time: tuple[int, ...]) -> str | None:
    try:
        return datetime(*date_time).isoformat()
    except (TypeError, ValueError):
        return None


def _member_timestamps(zip_path: Path) -> dict[str, str | None]:
    with zipfile.ZipFile(zip_path) as zf:
        return {
            _normalise_member(info.filename): _iso(info.date_time)
            for info in zf.infolist()
            if not info.is_dir()
        }


def _match_member(file_path: Path, members: dict[str, str | None]) -> str | None:
    parts = file_path.as_posix().split("/")
    for start in range(len(parts)):
        candidate = "/".join(parts[start:])
        if candidate in members:
            return candidate
    return None


def build_inventory(file_paths: list[Path], zip_path: Path, root: Path | None = None) -> list[dict]:
    """One entry per extracted file: path, size_bytes, extension, zip_timestamp.

    path is zip-relative: relative to root when given, otherwise the longest
    matching zip member name. zip_timestamp is naive ISO 8601 (zip stores local
    time without a zone) or None when missing or invalid.
    """
    members = _member_timestamps(Path(zip_path))
    inventory = []
    for file_path in file_paths:
        file_path = Path(file_path)
        if root is not None:
            member = file_path.relative_to(root).as_posix()
            rel = member
        else:
            member = _match_member(file_path, members)
            rel = member if member is not None else str(file_path)
        inventory.append({
            "path": rel,
            "size_bytes": file_path.stat().st_size,
            "extension": file_extension(file_path),
            "zip_timestamp": members.get(member) if member is not None else None,
        })
    return inventory
