# Treska CLI — thin wrapper over parse_zip(). No parsing logic lives here.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from treska.core.output import FileEntry, ParseResult
from treska.core.pipeline import parse_zip

_DASH = "—"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="treska",
        description="Fast forensic parser for zipped logical extractions.",
    )
    parser.add_argument("zip_path", help="Path to the ZIP file to parse")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON (for Sarissa integration)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include per-file detail in pretty output",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    path = Path(args.zip_path)
    if not path.is_file():
        print(f"treska: file not found: {args.zip_path}", file=sys.stderr)
        sys.exit(1)
    if not os.access(path, os.R_OK):
        print(f"treska: file unreadable: {args.zip_path}", file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_zip(path)
    except Exception as exc:  # noqa: BLE001
        print(f"treska: parse error: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        # Plain print, not rich: JSON must reach Sarissa byte-for-byte.
        # default=str guards against any future non-JSON field (Path, datetime).
        print(json.dumps(_to_dict(result), indent=2, default=str))
    else:
        _pretty_print(result, verbose=args.verbose)


def _to_dict(result: ParseResult) -> dict:
    """ParseResult (a dataclass tree) -> plain dict matching the v1.0.0 JSON schema."""
    return dataclasses.asdict(result)


def _or_dash(value: object) -> str:
    return _DASH if value is None else str(value)


def _pretty_print(result: ParseResult, *, verbose: bool = False) -> None:
    """Rich summary: counts, flagged files, SQLite schemas; verbose adds full inventory."""
    console = Console(highlight=False)
    sqlite_entries = [e for e in result.inventory if e.sqlite_schema is not None]
    mismatches = sum(1 for e in result.inventory if e.mismatch)

    console.print(Text(f"Treska — {result.zip_path}", style="bold"))
    console.print(
        f"schema {result.schema_version} · {result.file_count} files · "
        f"{len(result.flagged)} flagged · {len(sqlite_entries)} SQLite · "
        f"{mismatches} magic mismatch"
    )

    if result.flagged:
        table = Table(title="Flagged files", title_justify="left")
        table.add_column("Path")
        table.add_column("Flags")
        table.add_column("Size", justify="right")
        table.add_column("Magic type")
        for entry in result.flagged:
            flags = Text(", ".join(entry.flags))
            if entry.mismatch:
                flags.append("  MISMATCH", style="bold red")
            table.add_row(Text(entry.path), flags, str(entry.size_bytes), Text(entry.magic_type))
        console.print(table)
    else:
        console.print("No flagged files.")

    for entry in sqlite_entries:
        console.print(Text(f"SQLite: {entry.path}", style="bold"))
        tables = entry.sqlite_schema.get("tables", [])
        if not tables:
            console.print("  (no tables)")
        for tbl in tables:
            cols = ", ".join(f"{c['name']} {c['type']}".strip() for c in tbl["columns"])
            console.print(Text(f"  {tbl['name']}({cols})"))

    if verbose:
        _print_inventory(console, result.inventory)


def _print_inventory(console: Console, inventory: list[FileEntry]) -> None:
    # One block per file rather than a wide table: hashes stay on one line
    # (copy-pasteable) at any terminal width.
    console.print(Text("Inventory", style="bold"))
    for entry in inventory:
        header = Text(entry.path, style="bold")
        if entry.mismatch:
            header.append("  MISMATCH", style="bold red")
        console.print(header)
        console.print(Text(
            f"  size {entry.size_bytes} · ext {entry.extension or _DASH} · "
            f"zip {_or_dash(entry.zip_timestamp)} · {entry.mime}"
        ))
        console.print(Text(f"  md5    {_or_dash(entry.md5)}"), no_wrap=True, crop=False)
        console.print(Text(f"  sha256 {_or_dash(entry.sha256)}"), no_wrap=True, crop=False)


if __name__ == "__main__":
    main()
