# Treska core — MD5/SHA-256 hashing.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ThreadPoolExecutor only — ProcessPoolExecutor fork-bombs under PyInstaller on Windows.
PARALLEL_THRESHOLD = 100
_CHUNK = 1024 * 1024


def _hash_one(file_path: Path) -> tuple[str | None, str | None]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                md5.update(chunk)
                sha256.update(chunk)
    except OSError:
        return (None, None)
    return (md5.hexdigest(), sha256.hexdigest())


def compute_hashes(file_paths: list[Path], skip: bool = False
                   ) -> dict[Path, tuple[str | None, str | None]]:
    """Map each path to (md5_hex, sha256_hex).

    skip=True (--no-hash) maps every path to (None, None) so hash columns stay
    present. Unreadable files also map to (None, None).
    """
    if skip:
        return {p: (None, None) for p in file_paths}
    if len(file_paths) > PARALLEL_THRESHOLD:
        with ThreadPoolExecutor() as pool:
            return dict(zip(file_paths, pool.map(_hash_one, file_paths)))
    return {p: _hash_one(p) for p in file_paths}
