# Treska core — ParseResult output model shared by CLI and web.
# © 2026 Strategos Pty Ltd. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0.0"


@dataclass
class FileEntry:
    path: str
    size_bytes: int
    extension: str
    zip_timestamp: str | None
    magic_type: str
    mime: str
    mismatch: bool
    flags: list[str]
    md5: str | None
    sha256: str | None
    sqlite_schema: dict | None


@dataclass
class ParseResult:
    schema_version: str = SCHEMA_VERSION
    zip_path: str = ""
    file_count: int = 0
    flagged: list[FileEntry] = field(default_factory=list)
    inventory: list[FileEntry] = field(default_factory=list)


def build_parse_result(zip_path: str, entries: list[FileEntry]) -> ParseResult:
    """inventory = all entries by path; flagged = the same objects with flags,
    most flags first (path breaks ties)."""
    inventory = sorted(entries, key=lambda e: e.path)
    flagged = sorted((e for e in inventory if e.flags), key=lambda e: (-len(e.flags), e.path))
    return ParseResult(
        zip_path=str(zip_path),
        file_count=len(inventory),
        flagged=flagged,
        inventory=inventory,
    )
