# Treska core — CTF flag scan over the raw bytes of every extracted file.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam
#
# Raw bytes only: never decompresses or recurses into archives, never opens a file
# with sqlite3 (a database's raw bytes are scanned like any other file). Runs on
# the extracted originals before any WAL copy is staged, and refuses .treska_wal paths.

from __future__ import annotations

import base64
import binascii
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import BinaryIO

from treska.parsers.sqlite_triage import TEXT_CAP, WAL_DIR

FLAG_PREFIXES = ("flag{", "ctf{", "FLAG{", "CTF{")  # exact case — "Flag{" never matches
FLAG_HIT_CAP = 50       # total hits across all files
PER_FILE_CAP = 10       # hits per file
CHUNK_SIZE = 1 << 20    # 1 MiB
MAX_PREFIX = max(len(p) for p in FLAG_PREFIXES)
OVERLAP = MAX_PREFIX * 4  # covers the UTF-16LE needle (2×) and every base64 needle
MAX_BODY = 256            # longest flag body extracted (the reported match is TEXT_CAP)
B64_WINDOW = 4096         # bytes of a base64 run examined on each side of a hit
MAX_CANDIDATES = 10_000   # needle hits verified per file — bounds hostile inputs
WORKERS = 8               # ThreadPoolExecutor only — NEVER ProcessPoolExecutor

ASCII = "ascii"
UTF16LE = "utf-16le"
BASE64 = "base64"

# A full flag: prefix (which ends in "{"), 1..MAX_BODY printable ASCII except "{" and
# "}", then "}". Excluding "{" stops an unclosed prefix from swallowing the next one.
_BODY = r"[\x20-\x7a\x7c\x7e]{1,%d}\}" % MAX_BODY
_FLAG_BYTES = {p: re.compile(re.escape(p.encode("ascii")) + _BODY.encode("ascii"))
               for p in FLAG_PREFIXES}
_FLAG_TEXT = {p: re.compile(re.escape(p) + _BODY) for p in FLAG_PREFIXES}

_B64_RUN = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")


def _b64_needle(prefix: bytes, align: int) -> bytes:
    """The base64 characters that encode prefix when it starts `align` bytes into a
    3-byte group — only characters fixed by the prefix itself (none that depend on
    the bytes before or after it)."""
    encoded = base64.b64encode(b"\0" * align + prefix)
    skip = (0, 2, 3)[align]                       # chars touched by the leading pad
    stable = (align + len(prefix)) * 8 // 6       # chars fully inside known bytes
    return encoded[skip:stable]


def _build_needles() -> dict[bytes, tuple[str, str]]:
    needles: dict[bytes, tuple[str, str]] = {}
    for prefix in FLAG_PREFIXES:
        raw = prefix.encode("ascii")
        needles[raw] = (prefix, ASCII)
        needles[prefix.encode("utf-16-le")] = (prefix, UTF16LE)
        for align in range(3):
            needles[_b64_needle(raw, align)] = (prefix, BASE64)
    assert len(needles) == len(FLAG_PREFIXES) * 5, "flag needles must be unique"
    assert max(map(len, needles)) <= OVERLAP
    return needles


# Precomputed at import: needle bytes -> (prefix, encoding).
NEEDLES: dict[bytes, tuple[str, str]] = _build_needles()


def _needle_hits(fh: BinaryIO) -> list[tuple[int, bytes]]:
    """Every (file offset, needle) in fh, read CHUNK_SIZE at a time with OVERLAP
    bytes carried over so a needle split across chunks is still found once."""
    found: list[tuple[int, bytes]] = []
    tail = b""
    pos = 0  # file offset of the next read
    while len(found) < MAX_CANDIDATES:
        data = fh.read(CHUNK_SIZE)
        if not data:
            break
        buf = tail + data
        base = pos - len(tail)
        chunk_hits = []
        for needle in NEEDLES:
            i = buf.find(needle)
            while i != -1:
                # Wholly inside the carried tail -> already found in the previous chunk.
                if i + len(needle) > len(tail):
                    chunk_hits.append((base + i, needle))
                i = buf.find(needle, i + 1)
        found.extend(sorted(chunk_hits))
        pos += len(data)
        tail = buf[-OVERLAP:]
    return found[:MAX_CANDIDATES]


def _read_at(fh: BinaryIO, offset: int, size: int) -> bytes:
    fh.seek(max(offset, 0))
    return fh.read(size)


def _verify_plain(fh: BinaryIO, offset: int, prefix: str, encoding: str) -> str | None:
    if encoding == ASCII:
        window = _read_at(fh, offset, len(prefix) + MAX_BODY + 1)
        m = _FLAG_BYTES[prefix].match(window)
        return m.group(0).decode("ascii") if m else None
    window = _read_at(fh, offset, (len(prefix) + MAX_BODY + 1) * 2)
    m = _FLAG_TEXT[prefix].match(window.decode("utf-16-le", errors="replace"))
    return m.group(0) if m else None


def _verify_base64(fh: BinaryIO, offset: int, prefix: str) -> str | None:
    """Decode the base64 run around the hit; keep it only if the decoded bytes
    contain a full prefix{…} flag."""
    start = max(offset - B64_WINDOW, 0)
    window = _read_at(fh, start, (offset - start) + B64_WINDOW)
    rel = offset - start
    lo = rel
    while lo > 0 and window[lo - 1] in _B64_RUN:
        lo -= 1
    hi = rel
    while hi < len(window) and window[hi] in _B64_RUN:
        hi += 1
    run = re.sub(rb"[\r\n]", b"", window[lo:hi])
    for shift in range(4):  # one of these lines up with the encoder's 4-char quanta
        part = run[shift:].rstrip(b"=")
        part = part[: len(part) - len(part) % 4]
        if not part:
            continue
        try:
            decoded = base64.b64decode(part, validate=True)
        except (binascii.Error, ValueError):
            continue
        m = _FLAG_BYTES[prefix].search(decoded)
        if m:
            return m.group(0).decode("ascii")
    return None


def scan_file(path: Path, display: str | None = None) -> list[dict]:
    """Flag hits in one file: [{path, offset, encoding, match}], at most PER_FILE_CAP,
    deduplicated by (path, match). offset is the file byte offset of the encoded
    hit; match is the decoded flag string, TEXT_CAP characters max."""
    shown = display if display is not None else Path(path).as_posix()
    hits: list[dict] = []
    seen: set[str] = set()
    with open(path, "rb") as fh:
        for offset, needle in _needle_hits(fh):
            prefix, encoding = NEEDLES[needle]
            if encoding == BASE64:
                match = _verify_base64(fh, offset, prefix)
            else:
                match = _verify_plain(fh, offset, prefix, encoding)
            if match is None:
                continue
            match = match[:TEXT_CAP]
            if match in seen:
                continue
            seen.add(match)
            hits.append({"path": shown, "offset": offset, "encoding": encoding, "match": match})
            if len(hits) >= PER_FILE_CAP:
                break
    return hits


def _display(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return Path(path).relative_to(root).as_posix()
        except ValueError:
            pass
    return Path(path).as_posix()


def _is_wal_copy(path: Path, root: Path | None) -> bool:
    parts = Path(_display(path, root)).parts
    return WAL_DIR in parts or WAL_DIR in Path(path).parts


def scan_zip(files: list[Path], *, root: Path | None = None,
             skip: bool = False) -> list[dict] | None:
    """Scan every extracted original for CTF flags. None when skip (--no-flag-scan).

    Hit paths are zip-relative to root (= FileEntry.path). Hits are sorted by
    (path, offset) and capped at FLAG_HIT_CAP. .treska_wal copies are never read.
    A failing file contributes no hits; nothing escapes.
    """
    if skip:
        return None
    targets = [Path(p) for p in files if not _is_wal_copy(Path(p), root)]

    def one(path: Path) -> list[dict]:
        try:
            return scan_file(path, display=_display(path, root))
        except Exception:  # noqa: BLE001 — never let one file break parse_zip
            return []

    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(targets))) as pool:
        results = list(pool.map(one, targets))
    hits = [hit for file_hits in results for hit in file_hits]
    hits.sort(key=lambda h: (h["path"], h["offset"]))
    return hits[:FLAG_HIT_CAP]
