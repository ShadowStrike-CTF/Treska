# Treska core — ParseResult output model shared by CLI and web.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

from dataclasses import dataclass, field

# 1.1.0: added FileEntry.triage and ParseResult.deferred_files (additive).
# 1.2.0: added ParseResult.extraction_type (additive).
# 1.3.0: new FileEntry.triage formats ios_sms / ios_knowledgec / ios_addressbook (additive).
# 1.4.0: new FileEntry.triage formats android_mmssms / android_contacts / android_calllog (additive).
# 1.5.0: new FileEntry.triage formats ios_callhistory / ios_safari / android_chrome and
#        ParseResult.flag_hits (additive).
SCHEMA_VERSION = "1.5.0"


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
    # EVTX / iOS / Android artifact triage or a "deferred" container notice; None otherwise.
    triage: dict | None = None


@dataclass
class ParseResult:
    schema_version: str = SCHEMA_VERSION
    zip_path: str = ""
    file_count: int = 0
    flagged: list[FileEntry] = field(default_factory=list)
    inventory: list[FileEntry] = field(default_factory=list)
    deferred_files: list[dict] = field(default_factory=list)
    # IOS_FFS / ANDROID_LOGICAL / UNKNOWN from core.detect.
    extraction_type: str = "UNKNOWN"
    # core.flag_scan hits [{path, offset, encoding, match}]; None when the scan was skipped.
    flag_hits: list[dict] | None = None


def build_parse_result(
    zip_path: str,
    entries: list[FileEntry],
    extraction_type: str = "UNKNOWN",
    flag_hits: list[dict] | None = None,
) -> ParseResult:
    """inventory = all entries by path; flagged = the same objects with flags,
    most flags first (path breaks ties); deferred_files = containers to open
    with another tool first."""
    inventory = sorted(entries, key=lambda e: e.path)
    flagged = sorted((e for e in inventory if e.flags), key=lambda e: (-len(e.flags), e.path))
    return ParseResult(
        zip_path=str(zip_path),
        file_count=len(inventory),
        flagged=flagged,
        inventory=inventory,
        deferred_files=[
            e.triage for e in inventory
            if e.triage is not None and e.triage.get("status") == "deferred"
        ],
        extraction_type=extraction_type,
        flag_hits=flag_hits,
    )
