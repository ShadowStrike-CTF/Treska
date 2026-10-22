# Treska core — magic byte detection and extension mismatch flagging.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

from pathlib import Path

import magic

_TEXT = ("text/",)
_ZIP = ("application/zip",)
_SQLITE = ("application/vnd.sqlite3", "application/x-sqlite3")
_PE = ("application/x-dosexec", "application/vnd.microsoft.portable-executable")
_ELF = (
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/x-elf",
)

# Extension -> accepted magic MIME types. An entry ending in "/" matches any
# MIME with that prefix. Extensions not listed here are not judged.
EXPECTED_MIMES: dict[str, tuple[str, ...]] = {
    # images
    "png": ("image/png",),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "gif": ("image/gif",),
    "bmp": ("image/bmp", "image/x-ms-bmp"),
    "webp": ("image/webp",),
    "tif": ("image/tiff",),
    "tiff": ("image/tiff",),
    "ico": ("image/vnd.microsoft.icon", "image/x-icon"),
    "heic": ("image/heic", "image/heif"),
    # documents
    "pdf": ("application/pdf",),
    "docx": _ZIP + ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",),
    "xlsx": _ZIP + ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",),
    "pptx": _ZIP + ("application/vnd.openxmlformats-officedocument.presentationml.presentation",),
    # archives
    "zip": _ZIP,
    "apk": _ZIP + ("application/vnd.android.package-archive", "application/java-archive"),
    "jar": _ZIP + ("application/java-archive", "application/x-java-archive"),
    "gz": ("application/gzip", "application/x-gzip"),
    "tgz": ("application/gzip", "application/x-gzip"),
    "tar": ("application/x-tar",),
    "7z": ("application/x-7z-compressed",),
    "rar": ("application/vnd.rar", "application/x-rar", "application/x-rar-compressed"),
    # databases
    "db": _SQLITE,
    "sqlite": _SQLITE,
    "sqlite3": _SQLITE,
    "db3": _SQLITE,
    # executables
    "exe": _PE,
    "dll": _PE,
    "sys": _PE,
    "so": _ELF,
    # media
    "mp3": ("audio/mpeg",),
    "wav": ("audio/x-wav", "audio/wav", "audio/vnd.wave"),
    "mp4": ("video/mp4", "audio/x-m4a", "video/quicktime"),
    "m4a": ("audio/x-m4a", "audio/mp4", "video/mp4"),
    "mov": ("video/quicktime",),
    # text
    "txt": _TEXT,
    "log": _TEXT,
    "csv": _TEXT + ("application/csv",),
    "md": _TEXT,
    "ini": _TEXT,
    "cfg": _TEXT,
    "conf": _TEXT,
    "json": _TEXT + ("application/json",),
    "xml": _TEXT + ("application/xml",),
    "html": ("text/html", "text/xml", "text/plain"),
    "htm": ("text/html", "text/xml", "text/plain"),
    "py": _TEXT + ("application/x-script.python",),
    "sh": _TEXT + ("application/x-shellscript",),
    "js": _TEXT + ("application/javascript",),
}

_EMPTY_MIMES = ("application/x-empty", "inode/x-empty")


def file_extension(file_path: Path) -> str:
    """Lowercase final suffix without the dot; "" when there is none."""
    return Path(file_path).suffix.lower().lstrip(".")


def _mime_accepted(mime: str, accepted: tuple[str, ...]) -> bool:
    return any(mime.startswith(a) if a.endswith("/") else mime == a for a in accepted)


def check_magic(file_path: Path) -> dict:
    """Identify file_path by magic bytes and flag an extension mismatch.

    Returns {"extension", "magic_type", "mime", "mismatch"}. The extension is
    never trusted for identification; it is only compared against magic.
    """
    extension = file_extension(file_path)
    try:
        magic_type = magic.from_file(str(file_path))
        mime = magic.from_file(str(file_path), mime=True)
    except (OSError, magic.MagicException):
        return {"extension": extension, "magic_type": "unknown", "mime": "unknown", "mismatch": False}

    accepted = EXPECTED_MIMES.get(extension)
    mismatch = (
        accepted is not None
        and mime not in _EMPTY_MIMES
        and not _mime_accepted(mime, accepted)
    )
    return {"extension": extension, "magic_type": magic_type, "mime": mime, "mismatch": mismatch}
