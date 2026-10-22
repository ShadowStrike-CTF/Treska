# Treska test fixtures — regenerate with: python tests/fixtures/make_fixtures.py
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import sqlite3
import struct
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZIP_TIMESTAMP = (2026, 9, 25, 12, 30, 0)
README_TEXT = b"Treska test fixture.\n"


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png_bytes() -> bytes:
    """Minimal valid 1x1 greyscale PNG."""
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + _png_chunk(b"IEND", b"")
    )


def make_sqlite(path: Path) -> None:
    path.unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT, sent_at INTEGER)")
        conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)")
        conn.execute("INSERT INTO messages (sender, body, sent_at) VALUES ('alice', 'flag{not_here}', 0)")
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    (HERE / "readme.txt").write_bytes(README_TEXT)
    (HERE / "mismatch.txt").write_bytes(png_bytes())
    (HERE / "empty.bin").write_bytes(b"")
    make_sqlite(HERE / "sample.db")

    members = {
        "readme.txt": README_TEXT,
        "evidence/mismatch.txt": png_bytes(),
        "evidence/image.png": png_bytes(),
        "evidence/empty.bin": b"",
        "db/sample.db": (HERE / "sample.db").read_bytes(),
    }
    with zipfile.ZipFile(HERE / "sample.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("evidence/", date_time=ZIP_TIMESTAMP), b"")
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP), data)


if __name__ == "__main__":
    main()
