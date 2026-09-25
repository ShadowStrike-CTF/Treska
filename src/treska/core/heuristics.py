# Treska core — interesting-file heuristics (8 flags).
# © 2026 Strategos Pty Ltd. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import re
import statistics
from pathlib import Path

from treska.core.sqlite_probe import is_sqlite

FLAG_ORDER = (
    "magic_mismatch",
    "sqlite",
    "executable",
    "nested_archive",
    "zero_bytes",
    "size_outlier",
    "suspicious_name",
    "no_extension",
)

_SQLITE_MIMES = {"application/vnd.sqlite3", "application/x-sqlite3"}
_EXEC_MIMES = {
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/x-elf",
    "application/x-mach-binary",
}
_EXEC_DESC_PREFIXES = ("PE32", "MS-DOS executable", "ELF ", "Mach-O")
# gzip/bzip2/xz included so compressed tarballs are not missed.
_ARCHIVE_MIMES = {
    "application/zip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/vnd.rar",
    "application/x-rar",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
}
# A double extension is only suspicious when the real (final) one runs code.
_DANGEROUS_EXTS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf",
    "ps1", "msi", "hta", "lnk", "jar", "dll", "cpl", "apk", "sh", "elf",
}
_SPACE_BEFORE_EXT = re.compile(r"\s\.[^.\s]+$")
_SPACE_RUN = re.compile(r"\s{2,}")
_RTLO = "‮"


def _is_suspicious_name(name: str) -> bool:
    if name.startswith("."):
        return True
    if _RTLO in name or _SPACE_RUN.search(name) or _SPACE_BEFORE_EXT.search(name):
        return True
    suffixes = [s.lower().lstrip(".") for s in Path(name).suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in _DANGEROUS_EXTS


def flag_file(file_path: Path, all_sizes: list[int], magic_result: dict) -> list[str]:
    """Return the interesting-file flags for file_path (empty list = not interesting)."""
    file_path = Path(file_path)
    mime = magic_result.get("mime", "")
    desc = magic_result.get("magic_type", "")
    size = file_path.stat().st_size
    flags: list[str] = []

    if magic_result.get("mismatch"):
        flags.append("magic_mismatch")
    if mime in _SQLITE_MIMES or desc.startswith("SQLite") or is_sqlite(file_path):
        flags.append("sqlite")
    if mime in _EXEC_MIMES or desc.startswith(_EXEC_DESC_PREFIXES):
        flags.append("executable")
    if mime in _ARCHIVE_MIMES:
        flags.append("nested_archive")
    if size == 0:
        flags.append("zero_bytes")
    if all_sizes:
        median = statistics.median(all_sizes)
        # median 0 would make every non-empty file an outlier
        if median > 0 and size > 3 * median:
            flags.append("size_outlier")
    if _is_suspicious_name(file_path.name):
        flags.append("suspicious_name")
    if not file_path.suffix:
        flags.append("no_extension")

    return flags
