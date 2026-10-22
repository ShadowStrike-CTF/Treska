# Treska — Fast Forensic Parser
Fast forensic parser for zipped logical extractions in CTF competitions.
by ShadowStrike. MIT.

## Dual delivery mode
CLI: treska challenge.zip [options]
Web: python -m treska  or  treska-web → 127.0.0.1:7332

Port 7332 ALWAYS for web mode — single PORT constant in web/main.py (distinct from Sarissa 7331, Poligon 7333).

## Core library (src/treska/core/) — shared, no duplication
ingestion.py — zip extraction, temp dir (try/finally cleanup, --keep)
magic_check.py — python-magic, mismatch detection
inventory.py — file inventory (path, size, extension, zip timestamp)
heuristics.py — 8 interesting-file flags
sqlite_probe.py — SQLite schema extraction (magic bytes, not extension)
output.py — ParseResult dataclass consumed by both CLI and web
pipeline.py — parse_zip() entry point; triage_file() magic-byte dispatch (EVTX / deferred)

## Parsers (src/treska/parsers/)
evtx.py — EVTX triage via python-evtx; HIGH_VALUE_IDS, SAMPLE_CAP module constants

## CLI: treska/cli.py (thin wrapper over core)
## Web: src/treska/web/main.py (FastAPI, thin wrapper over core)
## Web frontend: src/treska/web/static/index.html (drag-drop, inline results, one Export JSON button)
## CORS: loopback-only — http://127.0.0.1:7331 and http://localhost:7331 (Sarissa integration); never "*"

## Tech stack
Python 3.11, python-magic (+ python-magic-bin Windows), rich, FastAPI, uvicorn, python-evtx,
concurrent.futures.ThreadPoolExecutor (hash parallelism > 100 files — NEVER
ProcessPoolExecutor, fork-bombs on Windows under PyInstaller), stdlib only elsewhere.

## Key invariants
- Core library: NO duplication between cli.py and web/main.py
- Port: 7332 ALWAYS for web mode
- --out: ALL output to file, nothing to console except "Written to:" line
- Mismatch flagging: NEVER suppressed by any flag
- --no-hash: hash columns always present, render as — (console/file) or null (JSON)
- ThreadPoolExecutor only — NEVER ProcessPoolExecutor
- Temp dir: ALWAYS cleaned on exit, even on error (try/finally)
- JSON schema: stable at v1.1.0, schema_version field in every output

## WHAT NOT TO DO
- Never duplicate parsing logic between cli.py and web/main.py
- Never use ProcessPoolExecutor (fork-bomb under PyInstaller on Windows)
- Never split output between console and file when --out is set
- Never suppress mismatch flags
- Never drop hash columns when --no-hash — render — / null instead
- Never break JSON schema without bumping schema_version
- Never use git add -A — always path-scoped adds

## Phase 6 (v1.1.0)
- EVTX triage: python-evtx (pure Python, imports as `Evtx`), HIGH_VALUE_IDS module-level constant (16 IDs), SAMPLE_CAP = 3
- Per-file result on FileEntry.triage: status parsed / empty / corrupt
- record_errors: count of unparseable records or truncated chunks within an otherwise valid log — does not mark the log corrupt.
- Detect-and-defer: E01 (EVF magic), VHDX (vhdxfile), AD1 (ADSEGMENTEDFILE), DD/IMG/BIN by extension only when libmagic says application/octet-stream → status: deferred, listed in ParseResult.deferred_files
- Legacy .evt ("LfLe" at offset 4) → its own deferred type (format "evt"), message says convert to .evtx with Event Viewer or wevtutil — not a disk image
- Magic byte takes precedence over extension; a .evtx without ElfFile magic is reported corrupt, never skipped
- Schema 1.0.0 → 1.1.0 (additive: FileEntry.triage, ParseResult.deferred_files)
- Tests: 42 → 55 (tests/test_phase6_evtx.py builds synthetic EVTX in-test; no real case data)

## PACKAGING (PyInstaller)
Spec: treska.spec (onefile, console=False, pathex=['src'])
Datas: src/treska/web/static/index.html → treska/web/static/
Static dir: web/main.py resolves _STATIC from Path(__file__).parent / "static"; when frozen, __file__ is under sys._MEIPASS/treska/web/, so it lands on the bundled datas path.
Devnull guard: __main__.py redirects sys.stdout/stderr to devnull when None (windowed exe crash fix).
Build: pyinstaller treska.spec
Output: dist/treska (Linux ELF)
python-magic: hook-magic.py from pyinstaller-hooks-contrib handles it automatically.
