# Treska core — end-to-end parse pipeline (the one entry point CLI and web call).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

from pathlib import Path

from treska.core.detect import detect_extraction_type
from treska.core.hashing import compute_hashes
from treska.core.heuristics import flag_file
from treska.core.ingestion import cleanup, extract
from treska.core.inventory import build_inventory
from treska.core.magic_check import check_magic
from treska.core.output import FileEntry, ParseResult, build_parse_result
from treska.core.sqlite_probe import probe_sqlite
from treska.parsers.evtx import EVTX_MAGIC, parse_evtx

_EXTRACT = " to extract before submitting to Treska."

# Formats Treska does not open: (offset, signature, format, message).
DEFERRED_MAGIC: tuple[tuple[int, bytes, str, str], ...] = (
    (0, b"EVF", "e01", "Use FTK Imager or ewfmount" + _EXTRACT),
    (0, b"vhdxfile", "vhdx", "Use libvhdi or Windows disk management" + _EXTRACT),
    (0, b"ADSEGMENTEDFILE", "ad1", "Use FTK Imager" + _EXTRACT),
    # Legacy .evt: ELF_LOGFILE_HEADER is HeaderSize (0x30) then "LfLe".
    (4, b"LfLe", "evt",
     "Legacy Windows Event Log format — convert to .evtx using Windows Event Viewer "
     "or wevtutil before submitting to Treska."),
)
# Raw images have no magic, so the extension decides — but only when libmagic
# could not identify the file (magic always beats extension).
DEFERRED_EXTENSIONS: dict[str, str] = {
    "dd": "Use Autopsy or The Sleuth Kit" + _EXTRACT,
    "img": "Use Autopsy or The Sleuth Kit" + _EXTRACT,
    "bin": "Use Autopsy or The Sleuth Kit" + _EXTRACT,
}
_UNIDENTIFIED_MIME = "application/octet-stream"
_SNIFF_BYTES = 16


def _deferred(path: str, fmt: str, message: str) -> dict:
    return {
        "filename": path,
        "format": fmt,
        "status": "deferred",
        "message": message,
    }


def triage_file(file_path: Path, path: str, extension: str, mime: str) -> dict | None:
    """Format-specific triage, dispatched on magic bytes first, extension second.

    EVTX -> parse_evtx dict; forensic container -> status "deferred"; else None.
    A ".evtx" without the ElfFile header still goes to parse_evtx so it is
    reported as corrupt rather than silently skipped.
    """
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(_SNIFF_BYTES)
    except OSError:
        return None
    if head.startswith(EVTX_MAGIC):
        return parse_evtx(Path(file_path).read_bytes(), filename=path)
    for offset, signature, fmt, message in DEFERRED_MAGIC:
        if head[offset:offset + len(signature)] == signature:
            return _deferred(path, fmt, message)
    if extension == "evtx":
        return parse_evtx(head, filename=path)
    if extension in DEFERRED_EXTENSIONS and mime == _UNIDENTIFIED_MIME:
        return _deferred(path, extension, DEFERRED_EXTENSIONS[extension])
    return None


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
                triage=triage_file(file_path, row["path"], row["extension"], magic_result["mime"]),
            ))
        return build_parse_result(str(zip_path), entries, detect_extraction_type(temp_dir))
    finally:
        if not keep:
            cleanup(temp_dir)
