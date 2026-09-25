# Treska core — end-to-end parse pipeline (the one entry point CLI and web call).
# © 2026 Strategos Pty Ltd. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

from pathlib import Path

from treska.core.hashing import compute_hashes
from treska.core.heuristics import flag_file
from treska.core.ingestion import cleanup, extract
from treska.core.inventory import build_inventory
from treska.core.magic_check import check_magic
from treska.core.output import FileEntry, ParseResult, build_parse_result
from treska.core.sqlite_probe import probe_sqlite


def parse_zip(zip_path: Path, keep: bool = False, no_hash: bool = False) -> ParseResult:
    """Extract, identify, hash and flag every file in zip_path.

    The temp dir is removed before returning unless keep=True. Raises
    ValueError for a missing or invalid zip.
    """
    zip_path = Path(zip_path)
    temp_dir, files = extract(zip_path, keep=keep)
    try:
        rows = build_inventory(files, zip_path, root=temp_dir)
        sizes = [row["size_bytes"] for row in rows]
        hashes = compute_hashes(files, skip=no_hash)
        entries = []
        for file_path, row in zip(files, rows):
            magic_result = check_magic(file_path)
            flags = flag_file(file_path, sizes, magic_result)
            md5, sha256 = hashes[file_path]
            entries.append(FileEntry(
                path=row["path"],
                size_bytes=row["size_bytes"],
                extension=row["extension"],
                zip_timestamp=row["zip_timestamp"],
                magic_type=magic_result["magic_type"],
                mime=magic_result["mime"],
                mismatch=magic_result["mismatch"],
                flags=flags,
                md5=md5,
                sha256=sha256,
                sqlite_schema=probe_sqlite(file_path) if "sqlite" in flags else None,
            ))
        return build_parse_result(str(zip_path), entries)
    finally:
        if not keep:
            cleanup(temp_dir)
