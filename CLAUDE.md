# Treska — Fast Forensic Parser
Fast forensic parser for zipped logical extractions in CTF competitions.
by ShadowStrike. MIT.

## Dual delivery mode
CLI: treska challenge.zip [options]
Web: treska --serve → localhost:7332

Port 7332 ALWAYS for web mode (distinct from Sarissa 7331, Poligon 7333).

## Core library (treska/core/) — shared, no duplication
ingestion.py — zip extraction, temp dir (try/finally cleanup, --keep)
magic_check.py — python-magic, mismatch detection
inventory.py — file inventory (path, size, extension, zip timestamp)
heuristics.py — 8 interesting-file flags
sqlite_probe.py — SQLite schema extraction (magic bytes, not extension)
output.py — ParseResult dataclass consumed by both CLI and web

## CLI: treska/cli.py (thin wrapper over core)
## Web: treska/web.py (FastAPI, thin wrapper over core)
## Web frontend: treska/static/index.html (drag-drop, inline results, export buttons)

## Tech stack
Python 3.11, python-magic (+ python-magic-bin Windows), rich, FastAPI, uvicorn,
concurrent.futures.ThreadPoolExecutor (hash parallelism > 100 files — NEVER
ProcessPoolExecutor, fork-bombs on Windows under PyInstaller), stdlib only elsewhere.

## Key invariants
- Core library: NO duplication between cli.py and web.py
- Port: 7332 ALWAYS for web mode
- --out: ALL output to file, nothing to console except "Written to:" line
- Mismatch flagging: NEVER suppressed by any flag
- --no-hash: hash columns always present, render as — (console/file) or null (JSON)
- ThreadPoolExecutor only — NEVER ProcessPoolExecutor
- Temp dir: ALWAYS cleaned on exit, even on error (try/finally)
- JSON schema: stable at v1.0.0, schema_version field in every output

## WHAT NOT TO DO
- Never duplicate parsing logic between cli.py and web.py
- Never use ProcessPoolExecutor (fork-bomb under PyInstaller on Windows)
- Never split output between console and file when --out is set
- Never suppress mismatch flags
- Never drop hash columns when --no-hash — render — / null instead
- Never break JSON schema without bumping schema_version
- Never use git add -A — always path-scoped adds
